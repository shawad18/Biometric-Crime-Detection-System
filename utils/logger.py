import logging
import logging.handlers
import os
from datetime import datetime
import json

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        if hasattr(record, 'action'):
            log_entry['action'] = record.action
        
        return json.dumps(log_entry)

def setup_logging():
    """Setup structured logging configuration"""
    
    # Get configuration from environment variables
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_file = os.getenv('LOG_FILE', 'logs/app.log')
    log_max_bytes = int(os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB
    log_backup_count = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with simple format for development
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(getattr(logging, log_level))
    
    # File handler with JSON format for production
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count
        )
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(getattr(logging, log_level))
        root_logger.addHandler(file_handler)
    
    # Add console handler
    root_logger.addHandler(console_handler)
    
    # Set specific logger levels
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    return root_logger

def get_logger(name):
    """Get a logger instance with the given name"""
    return logging.getLogger(name)

def log_security_event(logger, event_type, message, user_id=None, ip_address=None, **kwargs):
    """Log security-related events with structured data"""
    extra = {
        'action': 'security_event',
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        **kwargs
    }
    logger.warning(message, extra=extra)

def log_user_action(logger, action, user_id, ip_address=None, **kwargs):
    """Log user actions with structured data"""
    extra = {
        'action': 'user_action',
        'user_id': user_id,
        'ip_address': ip_address,
        **kwargs
    }
    logger.info(f"User action: {action}", extra=extra)

def log_system_event(logger, event_type, message, **kwargs):
    """Log system events with structured data"""
    extra = {
        'action': 'system_event',
        'event_type': event_type,
        **kwargs
    }
    logger.info(message, extra=extra)

def log_error(logger, error, context=None, **kwargs):
    """Log errors with structured data"""
    extra = {
        'action': 'error',
        'context': context,
        **kwargs
    }
    logger.error(f"Error occurred: {str(error)}", extra=extra, exc_info=True)