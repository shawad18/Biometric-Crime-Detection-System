import time
import redis
import hashlib
import json
from functools import wraps
from flask import request, jsonify, g
import logging
from typing import Dict, Optional, Tuple
import os
from datetime import datetime, timedelta

class RateLimiter:
    """Advanced rate limiting system with multiple strategies"""
    
    def __init__(self, redis_url=None):
        self.logger = logging.getLogger(__name__)
        
        # Try to connect to Redis, fallback to in-memory storage
        self.use_redis = False
        self.redis_client = None
        self.memory_store = {}
        
        if redis_url or os.getenv('RATELIMIT_STORAGE_URL'):
            try:
                import redis
                redis_url = redis_url or os.getenv('RATELIMIT_STORAGE_URL', 'redis://localhost:6379')
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                self.redis_client.ping()
                self.use_redis = True
                self.logger.info("Rate limiter using Redis storage")
            except Exception as e:
                self.logger.warning(f"Redis connection failed, using memory storage: {e}")
        
        if not self.use_redis:
            self.logger.info("Rate limiter using in-memory storage")
        
        # Default rate limits
        self.default_limits = {
            'global': {'requests': 1000, 'window': 3600},  # 1000 requests per hour
            'login': {'requests': 5, 'window': 300},       # 5 attempts per 5 minutes
            'api': {'requests': 100, 'window': 3600},      # 100 API calls per hour
            'upload': {'requests': 20, 'window': 3600},    # 20 uploads per hour
            'search': {'requests': 50, 'window': 3600},    # 50 searches per hour
        }
    
    def _get_client_identifier(self) -> str:
        """Get unique client identifier"""
        # Try to get real IP address
        if request.environ.get('HTTP_X_FORWARDED_FOR'):
            ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        elif request.environ.get('HTTP_X_REAL_IP'):
            ip = request.environ['HTTP_X_REAL_IP']
        else:
            ip = request.remote_addr
        
        # Include user agent for additional uniqueness
        user_agent = request.headers.get('User-Agent', '')
        
        # Create hash of IP + User Agent
        identifier = hashlib.sha256(f"{ip}:{user_agent}".encode()).hexdigest()[:16]
        return identifier
    
    def _get_key(self, identifier: str, limit_type: str) -> str:
        """Generate Redis/memory key"""
        return f"rate_limit:{limit_type}:{identifier}"
    
    def _get_window_start(self, window_seconds: int) -> int:
        """Get current window start timestamp"""
        current_time = int(time.time())
        return (current_time // window_seconds) * window_seconds
    
    def _increment_counter(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Increment counter and return (current_count, ttl)"""
        if self.use_redis:
            return self._increment_redis_counter(key, window_seconds)
        else:
            return self._increment_memory_counter(key, window_seconds)
    
    def _increment_redis_counter(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Increment Redis counter"""
        try:
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds)
            results = pipe.execute()
            count = results[0]
            ttl = self.redis_client.ttl(key)
            return count, ttl
        except Exception as e:
            self.logger.error(f"Redis error: {e}")
            # Fallback to memory storage
            return self._increment_memory_counter(key, window_seconds)
    
    def _increment_memory_counter(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Increment in-memory counter"""
        current_time = time.time()
        window_start = self._get_window_start(window_seconds)
        
        # Clean old entries
        self._cleanup_memory_store(current_time)
        
        if key not in self.memory_store:
            self.memory_store[key] = {'count': 0, 'window_start': window_start}
        
        # Reset counter if new window
        if self.memory_store[key]['window_start'] < window_start:
            self.memory_store[key] = {'count': 0, 'window_start': window_start}
        
        self.memory_store[key]['count'] += 1
        
        # Calculate TTL
        ttl = int((window_start + window_seconds) - current_time)
        
        return self.memory_store[key]['count'], ttl
    
    def _cleanup_memory_store(self, current_time: float):
        """Clean up expired entries from memory store"""
        expired_keys = []
        for key, data in self.memory_store.items():
            # Extract window_seconds from the data or use default
            window_end = data.get('window_start', 0) + 3600  # Default 1 hour
            if current_time > window_end:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.memory_store[key]
    
    def check_rate_limit(self, limit_type: str = 'global', 
                        custom_limit: Optional[Dict] = None) -> Tuple[bool, Dict]:
        """Check if request is within rate limit"""
        
        # Get limit configuration
        if custom_limit:
            limit_config = custom_limit
        else:
            limit_config = self.default_limits.get(limit_type, self.default_limits['global'])
        
        max_requests = limit_config['requests']
        window_seconds = limit_config['window']
        
        # Get client identifier
        identifier = self._get_client_identifier()
        key = self._get_key(identifier, limit_type)
        
        # Increment counter
        current_count, ttl = self._increment_counter(key, window_seconds)
        
        # Check if limit exceeded
        limit_exceeded = current_count > max_requests
        
        # Prepare response info
        info = {
            'limit': max_requests,
            'remaining': max(0, max_requests - current_count),
            'reset_time': int(time.time()) + ttl,
            'retry_after': ttl if limit_exceeded else 0,
            'current_count': current_count
        }
        
        # Log rate limit events
        if limit_exceeded:
            self.logger.warning(f"Rate limit exceeded for {identifier} on {limit_type}: {current_count}/{max_requests}")
        
        return not limit_exceeded, info
    
    def get_rate_limit_headers(self, info: Dict) -> Dict[str, str]:
        """Generate rate limit headers for HTTP response"""
        return {
            'X-RateLimit-Limit': str(info['limit']),
            'X-RateLimit-Remaining': str(info['remaining']),
            'X-RateLimit-Reset': str(info['reset_time']),
            'X-RateLimit-Retry-After': str(info['retry_after']) if info['retry_after'] > 0 else '0'
        }
    
    def reset_rate_limit(self, identifier: str = None, limit_type: str = 'global') -> bool:
        """Reset rate limit for specific client/type"""
        if identifier is None:
            identifier = self._get_client_identifier()
        
        key = self._get_key(identifier, limit_type)
        
        try:
            if self.use_redis:
                self.redis_client.delete(key)
            else:
                if key in self.memory_store:
                    del self.memory_store[key]
            
            self.logger.info(f"Rate limit reset for {identifier} on {limit_type}")
            return True
        except Exception as e:
            self.logger.error(f"Error resetting rate limit: {e}")
            return False
    
    def get_rate_limit_stats(self, limit_type: str = None) -> Dict:
        """Get rate limiting statistics"""
        stats = {
            'storage_type': 'redis' if self.use_redis else 'memory',
            'total_keys': 0,
            'active_limits': {}
        }
        
        try:
            if self.use_redis:
                pattern = f"rate_limit:{limit_type or '*'}:*"
                keys = self.redis_client.keys(pattern)
                stats['total_keys'] = len(keys)
                
                # Group by limit type
                for key in keys:
                    parts = key.split(':')
                    if len(parts) >= 3:
                        lt = parts[1]
                        if lt not in stats['active_limits']:
                            stats['active_limits'][lt] = 0
                        stats['active_limits'][lt] += 1
            else:
                # Memory storage stats
                for key in self.memory_store.keys():
                    if key.startswith('rate_limit:'):
                        stats['total_keys'] += 1
                        parts = key.split(':')
                        if len(parts) >= 3:
                            lt = parts[1]
                            if lt not in stats['active_limits']:
                                stats['active_limits'][lt] = 0
                            stats['active_limits'][lt] += 1
        
        except Exception as e:
            self.logger.error(f"Error getting rate limit stats: {e}")
        
        return stats

# Flask decorators for easy integration
def rate_limit(limit_type='global', requests=None, window=None, per_user=False):
    """Decorator for rate limiting Flask routes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get rate limiter instance
            if not hasattr(g, 'rate_limiter'):
                g.rate_limiter = RateLimiter()
            
            # Custom limit if specified
            custom_limit = None
            if requests and window:
                custom_limit = {'requests': requests, 'window': window}
            
            # Check rate limit
            allowed, info = g.rate_limiter.check_rate_limit(limit_type, custom_limit)
            
            if not allowed:
                # Rate limit exceeded
                headers = g.rate_limiter.get_rate_limit_headers(info)
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Try again in {info["retry_after"]} seconds.',
                    'retry_after': info['retry_after']
                })
                response.status_code = 429
                
                # Add rate limit headers
                for header, value in headers.items():
                    response.headers[header] = value
                
                return response
            
            # Add rate limit headers to successful response
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                headers = g.rate_limiter.get_rate_limit_headers(info)
                for header, value in headers.items():
                    response.headers[header] = value
            
            return response
        
        return decorated_function
    return decorator

def init_rate_limiting(app):
    """Initialize rate limiting for Flask app"""
    
    @app.before_request
    def before_request():
        """Initialize rate limiter for each request"""
        g.rate_limiter = RateLimiter()
    
    @app.after_request
    def after_request(response):
        """Add security headers to all responses"""
        # Add general security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add HSTS header for HTTPS
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response
    
    # Rate limiting middleware
    @app.errorhandler(429)
    def rate_limit_handler(e):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.'
        }), 429

# Utility functions
def get_rate_limiter():
    """Get rate limiter instance"""
    if hasattr(g, 'rate_limiter'):
        return g.rate_limiter
    return RateLimiter()

def check_api_rate_limit():
    """Quick API rate limit check"""
    limiter = get_rate_limiter()
    return limiter.check_rate_limit('api')

def check_login_rate_limit():
    """Quick login rate limit check"""
    limiter = get_rate_limiter()
    return limiter.check_rate_limit('login')

if __name__ == '__main__':
    # Example usage
    limiter = RateLimiter()
    
    # Test rate limiting
    for i in range(10):
        allowed, info = limiter.check_rate_limit('test', {'requests': 5, 'window': 60})
        print(f"Request {i+1}: Allowed={allowed}, Info={info}")
        time.sleep(0.1)