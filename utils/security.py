import os
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, redirect, url_for, g, current_app
import logging
from typing import Optional, Dict, Any
import json

class SessionManager:
    """Advanced session management with security features"""
    
    def __init__(self, app=None):
        self.logger = logging.getLogger(__name__)
        self.app = app
        
        # Session configuration from environment
        self.session_timeout = int(os.getenv('PERMANENT_SESSION_LIFETIME', '1800'))  # 30 minutes
        self.max_session_lifetime = int(os.getenv('MAX_SESSION_LIFETIME', '28800'))  # 8 hours
        self.session_refresh_threshold = int(os.getenv('SESSION_REFRESH_THRESHOLD', '300'))  # 5 minutes
        
        # Security settings
        self.max_failed_attempts = int(os.getenv('MAX_FAILED_ATTEMPTS', '5'))
        self.lockout_duration = int(os.getenv('LOCKOUT_DURATION', '900'))  # 15 minutes
        self.require_fresh_login = ['admin_management', 'delete_criminal', 'delete_admin']
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize session manager with Flask app"""
        self.app = app
        
        # Configure Flask session settings
        app.config.update({
            'SESSION_COOKIE_SECURE': os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'PERMANENT_SESSION_LIFETIME': timedelta(seconds=self.session_timeout),
            'SESSION_REFRESH_EACH_REQUEST': False
        })
        
        # Register session handlers
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    def create_session(self, user_id: int, username: str, role: str = 'admin', 
                      remember_me: bool = False) -> str:
        """Create a new secure session"""
        session_id = secrets.token_urlsafe(32)
        current_time = time.time()
        
        # Set session data
        session.permanent = True
        session['session_id'] = session_id
        session['user_id'] = user_id
        session['username'] = username
        session['role'] = role
        session['admin_logged_in'] = True
        session['login_time'] = current_time
        session['last_activity'] = current_time
        session['ip_address'] = self._get_client_ip()
        session['user_agent_hash'] = self._hash_user_agent()
        session['csrf_token'] = secrets.token_urlsafe(32)
        session['fresh_login'] = True
        session['remember_me'] = remember_me
        
        # Extend session if remember me is checked
        if remember_me:
            session['expires_at'] = current_time + (30 * 24 * 3600)  # 30 days
        else:
            session['expires_at'] = current_time + self.session_timeout
        
        self.logger.info(f"Session created for user {username} (ID: {user_id}) from {session['ip_address']}")
        return session_id
    
    def validate_session(self) -> bool:
        """Validate current session"""
        if not session.get('admin_logged_in'):
            return False
        
        current_time = time.time()
        
        # Check if session exists
        if not session.get('session_id'):
            self.logger.warning("Session validation failed: No session ID")
            return False
        
        # Check session expiration
        expires_at = session.get('expires_at', 0)
        if current_time > expires_at:
            self.logger.info(f"Session expired for user {session.get('username')}")
            self.destroy_session()
            return False
        
        # Check maximum session lifetime
        login_time = session.get('login_time', 0)
        if current_time - login_time > self.max_session_lifetime:
            self.logger.info(f"Maximum session lifetime exceeded for user {session.get('username')}")
            self.destroy_session()
            return False
        
        # Validate IP address (optional, can be disabled for mobile users)
        if os.getenv('VALIDATE_SESSION_IP', 'False').lower() == 'true':
            if session.get('ip_address') != self._get_client_ip():
                self.logger.warning(f"IP address mismatch for user {session.get('username')}")
                self.destroy_session()
                return False
        
        # Validate user agent (detect session hijacking)
        if session.get('user_agent_hash') != self._hash_user_agent():
            self.logger.warning(f"User agent mismatch for user {session.get('username')}")
            self.destroy_session()
            return False
        
        return True
    
    def refresh_session(self) -> bool:
        """Refresh session if needed"""
        if not self.validate_session():
            return False
        
        current_time = time.time()
        last_activity = session.get('last_activity', 0)
        
        # Refresh session if threshold is met
        if current_time - last_activity > self.session_refresh_threshold:
            session['last_activity'] = current_time
            
            # Extend expiration if not remember_me session
            if not session.get('remember_me', False):
                session['expires_at'] = current_time + self.session_timeout
            
            # Mark as no longer fresh after some time
            if current_time - session.get('login_time', 0) > 600:  # 10 minutes
                session['fresh_login'] = False
            
            self.logger.debug(f"Session refreshed for user {session.get('username')}")
        
        return True
    
    def destroy_session(self):
        """Destroy current session"""
        username = session.get('username', 'unknown')
        session_id = session.get('session_id', 'unknown')
        
        session.clear()
        
        self.logger.info(f"Session destroyed for user {username} (Session ID: {session_id})")
    
    def require_fresh_login_for(self, endpoint: str) -> bool:
        """Check if endpoint requires fresh login"""
        return endpoint in self.require_fresh_login
    
    def is_fresh_login(self) -> bool:
        """Check if current session is from a fresh login"""
        return session.get('fresh_login', False)
    
    def mark_fresh_login_used(self):
        """Mark fresh login as used (for sensitive operations)"""
        session['fresh_login'] = False
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information"""
        if not session.get('admin_logged_in'):
            return {}
        
        current_time = time.time()
        login_time = session.get('login_time', 0)
        expires_at = session.get('expires_at', 0)
        
        return {
            'user_id': session.get('user_id'),
            'username': session.get('username'),
            'role': session.get('role'),
            'login_time': datetime.fromtimestamp(login_time).isoformat(),
            'session_duration': int(current_time - login_time),
            'time_until_expiry': max(0, int(expires_at - current_time)),
            'is_fresh': session.get('fresh_login', False),
            'remember_me': session.get('remember_me', False),
            'ip_address': session.get('ip_address')
        }
    
    def before_request(self):
        """Handle before request session validation"""
        # Skip session validation for static files and login page
        if (request.endpoint and 
            (request.endpoint.startswith('static') or 
             request.endpoint in ['login', 'logout'])):
            return
        
        # Validate and refresh session
        if session.get('admin_logged_in'):
            if not self.refresh_session():
                # Session invalid, redirect to login
                return redirect(url_for('login'))
    
    def after_request(self, response):
        """Handle after request security headers"""
        # Add security headers
        self._add_security_headers(response)
        return response
    
    def _get_client_ip(self) -> str:
        """Get client IP address"""
        if request.environ.get('HTTP_X_FORWARDED_FOR'):
            return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        elif request.environ.get('HTTP_X_REAL_IP'):
            return request.environ['HTTP_X_REAL_IP']
        else:
            return request.remote_addr or 'unknown'
    
    def _hash_user_agent(self) -> str:
        """Hash user agent for session validation"""
        user_agent = request.headers.get('User-Agent', '')
        return hashlib.sha256(user_agent.encode()).hexdigest()[:16]
    
    def _add_security_headers(self, response):
        """Add comprehensive security headers"""
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Other security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        # HSTS for HTTPS
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        # Cache control for sensitive pages
        if session.get('admin_logged_in') and request.endpoint not in ['static']:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

# Decorators for session management
def login_required(f):
    """Require valid session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def fresh_login_required(f):
    """Require fresh login for sensitive operations"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('login'))
        
        if not session.get('fresh_login', False):
            # Store the intended destination
            session['next_url'] = request.url
            return redirect(url_for('login', fresh_required=True))
        
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Require specific role(s)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            if user_role not in roles:
                from flask import abort
                abort(403)  # Forbidden
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Utility functions
def get_session_manager():
    """Get session manager instance"""
    if not hasattr(g, 'session_manager'):
        g.session_manager = SessionManager()
    return g.session_manager

def init_security(app):
    """Initialize security features for Flask app"""
    session_manager = SessionManager(app)
    
    # Add CSRF protection
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get('csrf_token')
            if not token or token != request.form.get('csrf_token'):
                from flask import abort
                abort(400)  # Bad Request
    
    # Add template global for CSRF token
    @app.template_global()
    def csrf_token():
        return session.get('csrf_token', '')
    
    return session_manager

if __name__ == '__main__':
    # Example usage
    from flask import Flask
    
    app = Flask(__name__)
    app.secret_key = 'test-key'
    
    session_manager = SessionManager(app)
    
    @app.route('/test')
    @login_required
    def test():
        return f"Session info: {session_manager.get_session_info()}"
    
    app.run(debug=True)