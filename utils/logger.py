"""
Agentic-IAM: Logging Utilities

Centralized logging configuration for the platform.
"""
import logging
import logging.config
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
    enable_console: bool = True,
    enable_json: bool = False
) -> logging.Logger:
    """
    Setup centralized logging configuration
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        log_format: Custom log format string
        enable_console: Enable console logging
        enable_json: Enable JSON formatted logging
    
    Returns:
        Configured logger instance
    """
    
    # Default log format
    if not log_format:
        if enable_json:
            log_format = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}'
        else:
            log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]"
    
    # Create logs directory if using file logging
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Logging configuration
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": log_format,
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "detailed": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(pathname)s:%(lineno)d]",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            }
        },
        "handlers": {},
        "loggers": {
            "agentic_iam": {
                "level": log_level,
                "handlers": [],
                "propagate": False
            },
            "uvicorn": {
                "level": "INFO",
                "handlers": [],
                "propagate": False
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": [],
                "propagate": False
            }
        },
        "root": {
            "level": log_level,
            "handlers": []
        }
    }
    
    # Console handler
    if enable_console:
        config["handlers"]["console"] = {
            "class": "logging.StreamHandler",
            "level": log_level,
            "formatter": "standard",
            "stream": sys.stdout
        }
        config["loggers"]["agentic_iam"]["handlers"].append("console")
        config["loggers"]["uvicorn"]["handlers"].append("console")
        config["loggers"]["uvicorn.access"]["handlers"].append("console")
        config["root"]["handlers"].append("console")
    
    # File handler
    if log_file:
        config["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": log_level,
            "formatter": "detailed",
            "filename": log_file,
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8"
        }
        config["loggers"]["agentic_iam"]["handlers"].append("file")
        config["root"]["handlers"].append("file")
    
    # Apply configuration
    logging.config.dictConfig(config)
    
    # Get logger
    logger = logging.getLogger("agentic_iam")
    
    # Log startup message
    logger.info(f"Logging initialized - Level: {log_level}, Console: {enable_console}, File: {bool(log_file)}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name"""
    return logging.getLogger(f"agentic_iam.{name}")


class SecurityLogFilter(logging.Filter):
    """Filter to prevent logging of sensitive information"""
    
    SENSITIVE_PATTERNS = [
        "password", "secret", "key", "token", "credential",
        "auth", "jwt", "signature", "private", "confidential"
    ]
    
    def filter(self, record):
        """Filter out records containing sensitive information"""
        message = record.getMessage().lower()
        
        # Check for sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in message:
                # Mask the sensitive information
                record.msg = "[REDACTED - SENSITIVE INFORMATION]"
                record.args = ()
                break
        
        return True


class AuditLogHandler(logging.Handler):
    """Custom handler for audit logs"""
    
    def __init__(self, audit_manager=None):
        super().__init__()
        self.audit_manager = audit_manager
    
    def emit(self, record):
        """Emit audit log record"""
        if self.audit_manager:
            try:
                # Create audit event from log record
                from audit_compliance import AuditEventType, EventSeverity
                
                # Map log levels to event severity
                severity_map = {
                    logging.DEBUG: EventSeverity.LOW,
                    logging.INFO: EventSeverity.LOW,
                    logging.WARNING: EventSeverity.MEDIUM,
                    logging.ERROR: EventSeverity.HIGH,
                    logging.CRITICAL: EventSeverity.CRITICAL
                }
                
                # Log as audit event
                self.audit_manager.log_event(
                    event_type=AuditEventType.SYSTEM_STARTUP,  # Would be more specific
                    component="logging",
                    severity=severity_map.get(record.levelno, EventSeverity.LOW),
                    details={
                        "message": record.getMessage(),
                        "module": record.module,
                        "function": record.funcName,
                        "line": record.lineno,
                        "level": record.levelname
                    }
                )
            except Exception:
                # Don't let audit logging failures crash the application
                pass


class StructuredLogger:
    """Structured logging helper"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def info(self, message: str, **kwargs):
        """Log info with structured data"""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning with structured data"""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error with structured data"""
        self._log(logging.ERROR, message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug with structured data"""
        self._log(logging.DEBUG, message, **kwargs)
    
    def _log(self, level: int, message: str, **kwargs):
        """Internal log method with structured data"""
        if kwargs:
            structured_data = " | ".join([f"{k}={v}" for k, v in kwargs.items()])
            full_message = f"{message} | {structured_data}"
        else:
            full_message = message
        
        self.logger.log(level, full_message)


def configure_uvicorn_logging():
    """Configure uvicorn logging to integrate with our logging setup"""
    
    # Disable uvicorn's default logging
    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    
    # Clear existing handlers
    uvicorn_logger.handlers.clear()
    uvicorn_access_logger.handlers.clear()
    
    # Set levels
    uvicorn_logger.setLevel(logging.INFO)
    uvicorn_access_logger.setLevel(logging.INFO)


class LoggerMixin:
    """Mixin class to add logging capabilities to any class"""
    
    @property
    def logger(self) -> logging.Logger:
        """Get logger for the class"""
        if not hasattr(self, '_logger'):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger
    
    def log_info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)
    
    def log_warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
    
    def log_error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, extra=kwargs)
    
    def log_debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)


def log_function_call(func):
    """Decorator to log function calls"""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Function {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Function {func.__name__} failed with error: {str(e)}")
            raise
    
    return wrapper


def log_performance(func):
    """Decorator to log function performance"""
    def wrapper(*args, **kwargs):
        import time
        
        logger = get_logger(func.__module__)
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.info(f"Function {func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Function {func.__name__} failed after {duration:.3f}s with error: {str(e)}")
            raise
    
    return wrapper


# Example usage
if __name__ == "__main__":
    # Setup logging
    logger = setup_logging(
        log_level="DEBUG",
        log_file="./logs/agentic_iam.log",
        enable_console=True
    )
    
    # Test logging
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.debug("This is a debug message")
    
    # Test structured logging
    structured = StructuredLogger(logger)
    structured.info("User logged in", user_id="123", ip_address="192.168.1.1")
    
    # Test decorator
    @log_function_call
    @log_performance
    def sample_function(x, y):
        import time
        time.sleep(0.1)  # Simulate work
        return x + y
    
    result = sample_function(1, 2)
    print(f"Result: {result}")