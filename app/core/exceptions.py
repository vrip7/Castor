"""
Custom exception classes for the application.
Provides consistent error handling across the API.
"""

from typing import Any, Dict, Optional

from fastapi import HTTPException, status


class BaseAPIException(HTTPException):
    """Base exception for all API errors."""
    
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str,
        headers: Optional[Dict[str, str]] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code
        self.extra = extra or {}


class AuthenticationError(BaseAPIException):
    """Authentication failed."""
    
    def __init__(
        self,
        detail: str = "Authentication failed",
        error_code: str = "AUTH_FAILED",
        headers: Optional[Dict[str, str]] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code=error_code,
            headers=headers or {"WWW-Authenticate": "Bearer"},
            extra=extra
        )


class InvalidCredentialsError(AuthenticationError):
    """Invalid credentials provided."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="Invalid email or password",
            error_code="INVALID_CREDENTIALS",
            extra=extra
        )


class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    
    def __init__(self, token_type: str = "access", extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail=f"{token_type.capitalize()} token has expired",
            error_code="TOKEN_EXPIRED",
            extra=extra
        )


class TokenInvalidError(AuthenticationError):
    """Token is invalid."""
    
    def __init__(self, detail: str = "Invalid token", extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail=detail,
            error_code="TOKEN_INVALID",
            extra=extra
        )


class MFARequiredError(AuthenticationError):
    """MFA verification required."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="Multi-factor authentication required",
            error_code="MFA_REQUIRED",
            extra=extra
        )


class MFAInvalidError(AuthenticationError):
    """Invalid MFA code."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="Invalid MFA code",
            error_code="MFA_INVALID",
            extra=extra
        )


class AccountLockedError(AuthenticationError):
    """Account is locked."""
    
    def __init__(
        self,
        lockout_minutes: int = 30,
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"Account is locked. Try again in {lockout_minutes} minutes",
            error_code="ACCOUNT_LOCKED",
            extra=extra
        )


class AccountDisabledError(AuthenticationError):
    """Account is disabled."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="Account has been disabled",
            error_code="ACCOUNT_DISABLED",
            extra=extra
        )


class EmailNotVerifiedError(AuthenticationError):
    """Email not verified."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="Email address not verified",
            error_code="EMAIL_NOT_VERIFIED",
            extra=extra
        )


class SessionExpiredError(AuthenticationError):
    """Session has expired."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="Session has expired",
            error_code="SESSION_EXPIRED",
            extra=extra
        )


class AuthorizationError(BaseAPIException):
    """Authorization failed - insufficient permissions."""
    
    def __init__(
        self,
        detail: str = "Permission denied",
        error_code: str = "PERMISSION_DENIED",
        required_permission: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        _extra = extra or {}
        if required_permission:
            _extra["required_permission"] = required_permission
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            error_code=error_code,
            extra=_extra
        )


class ResourceNotFoundError(BaseAPIException):
    """Resource not found."""
    
    def __init__(
        self,
        resource: str = "Resource",
        resource_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        _extra = extra or {}
        if resource_id:
            _extra["resource_id"] = resource_id
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} not found",
            error_code="RESOURCE_NOT_FOUND",
            extra=_extra
        )


class UserNotFoundError(ResourceNotFoundError):
    """User not found."""
    
    def __init__(self, user_id: Optional[str] = None, extra: Optional[Dict[str, Any]] = None):
        super().__init__(resource="User", resource_id=user_id, extra=extra)


class ValidationError(BaseAPIException):
    """Validation error."""
    
    def __init__(
        self,
        detail: str = "Validation error",
        errors: Optional[list] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        _extra = extra or {}
        if errors:
            _extra["errors"] = errors
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
            error_code="VALIDATION_ERROR",
            extra=_extra
        )


class PasswordValidationError(ValidationError):
    """Password validation failed."""
    
    def __init__(
        self,
        detail: str = "Password does not meet security requirements",
        requirements: Optional[list] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        _extra = extra or {}
        if requirements:
            _extra["requirements"] = requirements
        super().__init__(detail=detail, extra=_extra)
        self.error_code = "PASSWORD_VALIDATION_ERROR"


class RateLimitExceededError(BaseAPIException):
    """Rate limit exceeded."""
    
    def __init__(
        self,
        retry_after: int = 60,
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later",
            error_code="RATE_LIMIT_EXCEEDED",
            headers={"Retry-After": str(retry_after)},
            extra=extra
        )


class ConflictError(BaseAPIException):
    """Resource conflict error."""
    
    def __init__(
        self,
        detail: str = "Resource conflict",
        error_code: str = "CONFLICT",
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
            error_code=error_code,
            extra=extra
        )


class UserAlreadyExistsError(ConflictError):
    """User already exists."""
    
    def __init__(self, field: str = "email", extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail=f"User with this {field} already exists",
            error_code="USER_ALREADY_EXISTS",
            extra=extra
        )


class APIKeyError(BaseAPIException):
    """API key error."""
    
    def __init__(
        self,
        detail: str = "Invalid API key",
        error_code: str = "API_KEY_INVALID",
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code=error_code,
            headers={"WWW-Authenticate": "ApiKey"},
            extra=extra
        )


class APIKeyRevokedError(APIKeyError):
    """API key has been revoked."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="API key has been revoked",
            error_code="API_KEY_REVOKED",
            extra=extra
        )


class APIKeyExpiredError(APIKeyError):
    """API key has expired."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="API key has expired",
            error_code="API_KEY_EXPIRED",
            extra=extra
        )


class InternalServerError(BaseAPIException):
    """Internal server error."""
    
    def __init__(
        self,
        detail: str = "An internal error occurred",
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="INTERNAL_ERROR",
            extra=extra
        )


class DatabaseError(InternalServerError):
    """Database error."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="A database error occurred",
            extra=extra
        )
        self.error_code = "DATABASE_ERROR"


class EncryptionError(InternalServerError):
    """Encryption/decryption error."""
    
    def __init__(self, extra: Optional[Dict[str, Any]] = None):
        super().__init__(
            detail="An encryption error occurred",
            extra=extra
        )
        self.error_code = "ENCRYPTION_ERROR"


class ServiceUnavailableError(BaseAPIException):
    """Service unavailable."""
    
    def __init__(
        self,
        detail: str = "Service temporarily unavailable",
        retry_after: int = 60,
        extra: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
            error_code="SERVICE_UNAVAILABLE",
            headers={"Retry-After": str(retry_after)},
            extra=extra
        )


# Aliases for backward compatibility
NotFoundError = ResourceNotFoundError
RateLimitError = RateLimitExceededError
TokenError = TokenInvalidError
ForbiddenError = AuthorizationError
