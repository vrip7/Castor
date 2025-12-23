"""
Application constants.
Centralized location for all constant values.
"""

from enum import Enum
from typing import Final


# API Constants
API_VERSION: Final[str] = "v1"
API_TITLE: Final[str] = "VRIP7 API"
API_DESCRIPTION: Final[str] = """
Enterprise-grade authentication API with end-to-end encryption.

## Features
- User registration and authentication
- Multi-factor authentication (TOTP)
- API key management
- Session management
- Password reset functionality
- Role-based access control

## Security
- End-to-end encryption (AES-256-GCM)
- SQL injection protection
- Rate limiting
- CSRF protection
- Security headers
"""


class TokenType(str, Enum):
    """Token types."""
    ACCESS = "access"
    REFRESH = "refresh"
    RESET_PASSWORD = "reset_password"
    EMAIL_VERIFICATION = "email_verification"
    API_KEY = "api_key"


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING_VERIFICATION = "pending_verification"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


class UserRole(str, Enum):
    """User roles for RBAC."""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    USER = "user"
    SERVICE = "service"
    READ_ONLY = "read_only"


class Permission(str, Enum):
    """System permissions."""
    # User permissions
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_MANAGE = "user:manage"
    
    # API key permissions
    API_KEY_READ = "api_key:read"
    API_KEY_CREATE = "api_key:create"
    API_KEY_UPDATE = "api_key:update"
    API_KEY_DELETE = "api_key:delete"
    API_KEY_MANAGE = "api_key:manage"
    
    # Session permissions
    SESSION_READ = "session:read"
    SESSION_WRITE = "session:write"
    SESSION_DELETE = "session:delete"
    SESSION_MANAGE = "session:manage"
    
    # Audit permissions
    AUDIT_READ = "audit:read"
    
    # System permissions
    SYSTEM_ADMIN = "system:admin"


# Role-Permission mapping
ROLE_PERMISSIONS: dict[UserRole, list[Permission]] = {
    UserRole.SUPER_ADMIN: list(Permission),  # All permissions
    UserRole.ADMIN: [
        Permission.USER_READ,
        Permission.USER_CREATE,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.USER_MANAGE,
        Permission.API_KEY_READ,
        Permission.API_KEY_CREATE,
        Permission.API_KEY_UPDATE,
        Permission.API_KEY_DELETE,
        Permission.API_KEY_MANAGE,
        Permission.SESSION_READ,
        Permission.SESSION_WRITE,
        Permission.SESSION_MANAGE,
        Permission.AUDIT_READ,
    ],
    UserRole.USER: [
        Permission.USER_READ,
        Permission.API_KEY_READ,
        Permission.API_KEY_CREATE,
        Permission.SESSION_READ,
        Permission.SESSION_DELETE,
    ],
    UserRole.SERVICE: [
        Permission.USER_READ,
        Permission.API_KEY_READ,
    ],
    UserRole.READ_ONLY: [
        Permission.USER_READ,
        Permission.API_KEY_READ,
        Permission.SESSION_READ,
    ],
}


class AuditAction(str, Enum):
    """Audit log actions."""
    # Authentication actions
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    LOGIN_FAILURE = "login_failure"
    TOKEN_REFRESH = "token_refresh"
    
    # User actions
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_STATUS_CHANGED = "user_status_changed"
    USER_ROLE_CHANGED = "user_role_changed"
    
    # Password actions
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET = "password_reset"
    
    # Email actions
    EMAIL_VERIFIED = "email_verified"
    
    # MFA actions
    MFA_SETUP_INITIATED = "mfa_setup_initiated"
    MFA_SETUP_FAILED = "mfa_setup_failed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"
    MFA_BACKUP_CODE_USED = "mfa_backup_code_used"
    MFA_BACKUP_CODES_REGENERATED = "mfa_backup_codes_regenerated"
    
    # API key actions
    API_KEY_CREATED = "api_key_created"
    API_KEY_UPDATED = "api_key_updated"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_ROTATED = "api_key_rotated"
    API_KEY_USED = "api_key_used"
    
    # Session actions
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    SESSION_EXPIRED = "session_expired"
    
    # Security events
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ACCESS_DENIED = "access_denied"


class SecurityEventSeverity(str, Enum):
    """Security event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# HTTP Headers
class SecurityHeaders:
    """Security header constants."""
    X_REQUEST_ID = "X-Request-ID"
    X_CORRELATION_ID = "X-Correlation-ID"
    X_API_KEY = "X-API-Key"
    X_SIGNATURE = "X-Signature"
    X_TIMESTAMP = "X-Timestamp"
    X_NONCE = "X-Nonce"
    AUTHORIZATION = "Authorization"
    X_FORWARDED_FOR = "X-Forwarded-For"
    X_REAL_IP = "X-Real-IP"
    USER_AGENT = "User-Agent"
    CONTENT_TYPE = "Content-Type"


# Cookie Names
class CookieNames:
    """Cookie name constants."""
    SESSION = "castor_session"
    CSRF = "castor_csrf"
    REFRESH_TOKEN = "castor_refresh"


# Cache Keys
class CacheKeys:
    """Redis cache key prefixes."""
    SESSION = "session:"
    USER = "user:"
    RATE_LIMIT = "rate_limit:"
    BLACKLIST = "blacklist:"
    LOCKOUT = "lockout:"
    MFA = "mfa:"
    NONCE = "nonce:"
    API_KEY = "api_key:"
    PASSWORD_RESET = "password_reset:"


# Time Constants (in seconds)
class TimeConstants:
    """Time-related constants."""
    MINUTE: int = 60
    HOUR: int = 3600
    DAY: int = 86400
    WEEK: int = 604800
    MONTH: int = 2592000
    YEAR: int = 31536000


# Regex Patterns
class RegexPatterns:
    """Regex patterns for validation."""
    EMAIL = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    USERNAME = r"^[a-zA-Z0-9_-]{3,32}$"
    UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    API_KEY = r"^cstr_[a-zA-Z0-9]{64}$"
    PHONE = r"^\+?[1-9]\d{1,14}$"


# Rate Limiting Constants
RATE_LIMIT_LOGIN: Final[int] = 5  # Max login attempts per minute
RATE_LIMIT_REGISTER: Final[int] = 3  # Max registration attempts per minute
RATE_LIMIT_PASSWORD_RESET: Final[int] = 3  # Max password reset requests per minute
RATE_LIMIT_API: Final[int] = 100  # Default API rate limit per minute


# Error Messages Dictionary
ERROR_MESSAGES: dict[str, str] = {
    "INVALID_CREDENTIALS": "Invalid email/username or password",
    "ACCOUNT_LOCKED": "Account is locked due to multiple failed login attempts",
    "ACCOUNT_DISABLED": "Account has been disabled",
    "ACCOUNT_SUSPENDED": "Account has been suspended",
    "TOKEN_EXPIRED": "Token has expired",
    "TOKEN_INVALID": "Invalid token",
    "MFA_REQUIRED": "Multi-factor authentication required",
    "MFA_INVALID": "Invalid MFA code",
    "RATE_LIMIT_EXCEEDED": "Rate limit exceeded. Please try again later",
    "PERMISSION_DENIED": "Permission denied",
    "RESOURCE_NOT_FOUND": "Resource not found",
    "VALIDATION_ERROR": "Validation error",
    "INTERNAL_ERROR": "An internal error occurred",
    "SESSION_EXPIRED": "Session has expired",
    "API_KEY_INVALID": "Invalid API key",
    "API_KEY_REVOKED": "API key has been revoked",
    "API_KEY_EXPIRED": "API key has expired",
    "PASSWORD_TOO_WEAK": "Password does not meet security requirements",
    "EMAIL_NOT_VERIFIED": "Email address not verified",
    "EMAIL_ALREADY_EXISTS": "Email address is already registered",
    "USERNAME_ALREADY_EXISTS": "Username is already taken",
}


# Error Messages Class (for backward compatibility)
class ErrorMessages:
    """Standardized error messages."""
    INVALID_CREDENTIALS = "Invalid email or password"
    ACCOUNT_LOCKED = "Account is locked due to multiple failed login attempts"
    ACCOUNT_DISABLED = "Account has been disabled"
    TOKEN_EXPIRED = "Token has expired"
    TOKEN_INVALID = "Invalid token"
    MFA_REQUIRED = "Multi-factor authentication required"
    MFA_INVALID = "Invalid MFA code"
    RATE_LIMIT_EXCEEDED = "Rate limit exceeded. Please try again later"
    PERMISSION_DENIED = "Permission denied"
    RESOURCE_NOT_FOUND = "Resource not found"
    VALIDATION_ERROR = "Validation error"
    INTERNAL_ERROR = "An internal error occurred"
    SESSION_EXPIRED = "Session has expired"
    API_KEY_INVALID = "Invalid API key"
    API_KEY_REVOKED = "API key has been revoked"
    PASSWORD_TOO_WEAK = "Password does not meet security requirements"
    EMAIL_NOT_VERIFIED = "Email address not verified"
