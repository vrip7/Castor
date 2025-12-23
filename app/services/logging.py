"""
Structured logging service.
Provides secure, structured logging with sensitive data redaction.
"""

import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, WrappedLogger

from app.core.config import get_settings
from app.middleware.request_id import get_correlation_id, get_request_id


# Sensitive fields that should be redacted
SENSITIVE_FIELDS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "secret",
    "secret_key",
    "encryption_key",
    "authorization",
    "cookie",
    "credit_card",
    "ssn",
    "social_security",
    "private_key"
}


def redact_sensitive_data(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict
) -> EventDict:
    """
    Processor to redact sensitive data from log entries.
    
    Replaces sensitive field values with [REDACTED].
    """
    def redact_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        result = {}
        for key, value in d.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive field names
            is_sensitive = any(
                sensitive in key_lower 
                for sensitive in SENSITIVE_FIELDS
            )
            
            if is_sensitive:
                result[key] = "[REDACTED]"
            elif isinstance(value, dict):
                result[key] = redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    redact_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = value
        
        return result
    
    return redact_dict(event_dict)


def add_request_context(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict
) -> EventDict:
    """
    Processor to add request context to log entries.
    """
    request_id = get_request_id()
    correlation_id = get_correlation_id()
    
    if request_id:
        event_dict["request_id"] = request_id
    if correlation_id:
        event_dict["correlation_id"] = correlation_id
    
    return event_dict


def add_timestamp(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict
) -> EventDict:
    """
    Processor to add ISO format timestamp.
    """
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def add_service_info(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict
) -> EventDict:
    """
    Processor to add service information.
    """
    settings = get_settings()
    event_dict["service"] = settings.app_name
    event_dict["version"] = settings.app_version
    event_dict["environment"] = settings.app_env
    return event_dict


def setup_logging() -> None:
    """
    Configure structured logging for the application.
    
    Sets up:
    - JSON structured logging for production
    - Console logging for development
    - Sensitive data redaction
    - Request context injection
    """
    settings = get_settings()
    
    # Determine if we should use JSON format
    use_json = settings.logging.format.lower() == "json"
    
    # Build processor chain
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        add_timestamp,
        add_service_info,
        add_request_context,
        redact_sensitive_data,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if use_json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    log_level = getattr(logging, settings.logging.level.upper(), logging.INFO)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    if use_json:
        # JSON formatter for production
        from pythonjsonlogger import jsonlogger
        
        formatter = jsonlogger.JsonFormatter(
            fmt="%(timestamp)s %(level)s %(name)s %(message)s",
            rename_fields={"levelname": "level"},
            timestamp=True
        )
        console_handler.setFormatter(formatter)
    else:
        # Simple formatter for development
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)
    
    root_logger.addHandler(console_handler)
    
    # Silence noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    

def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Configured structured logger
    """
    return structlog.get_logger(name)


class SecurityLogger:
    """
    Specialized logger for security events.
    
    Provides methods for logging security-relevant events
    with appropriate severity and context.
    """
    
    def __init__(self):
        self._logger = get_logger("security")
    
    def login_success(
        self,
        user_id: str,
        email: str,
        ip_address: str,
        user_agent: Optional[str] = None,
        mfa_used: bool = False
    ) -> None:
        """Log successful login."""
        self._logger.info(
            "Login successful",
            event_type="login_success",
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_used=mfa_used
        )
    
    def login_failure(
        self,
        email: str,
        ip_address: str,
        reason: str,
        user_agent: Optional[str] = None
    ) -> None:
        """Log failed login attempt."""
        self._logger.warning(
            "Login failed",
            event_type="login_failure",
            email=email,
            ip_address=ip_address,
            reason=reason,
            user_agent=user_agent
        )
    
    def account_locked(
        self,
        user_id: str,
        email: str,
        ip_address: str,
        failed_attempts: int
    ) -> None:
        """Log account lockout."""
        self._logger.warning(
            "Account locked due to failed login attempts",
            event_type="account_locked",
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            failed_attempts=failed_attempts
        )
    
    def suspicious_activity(
        self,
        description: str,
        ip_address: str,
        user_id: Optional[str] = None,
        **context
    ) -> None:
        """Log suspicious activity."""
        self._logger.error(
            description,
            event_type="suspicious_activity",
            user_id=user_id,
            ip_address=ip_address,
            **context
        )
    
    def permission_denied(
        self,
        user_id: str,
        resource: str,
        action: str,
        required_permission: str
    ) -> None:
        """Log permission denied event."""
        self._logger.warning(
            "Permission denied",
            event_type="permission_denied",
            user_id=user_id,
            resource=resource,
            action=action,
            required_permission=required_permission
        )
    
    def api_key_used(
        self,
        key_id: str,
        user_id: str,
        ip_address: str,
        endpoint: str
    ) -> None:
        """Log API key usage."""
        self._logger.info(
            "API key used",
            event_type="api_key_used",
            key_id=key_id,
            user_id=user_id,
            ip_address=ip_address,
            endpoint=endpoint
        )


# Singleton security logger
_security_logger: Optional[SecurityLogger] = None


def get_security_logger() -> SecurityLogger:
    """Get security logger singleton."""
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger()
    return _security_logger
