"""
Pydantic schemas for API request/response validation.
"""

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    PasswordChangeRequest,
    PasswordChangeRequest as ChangePasswordRequest,  # Alias for backward compatibility
    TokenResponse,
    MFASetupResponse,
    MFAVerificationRequest,
    MFAVerificationRequest as MFAVerifyRequest,  # Alias for backward compatibility
)
from app.schemas.user import (
    UserCreateRequest,
    UserCreateRequest as UserCreate,  # Alias for backward compatibility
    UserUpdateRequest,
    UserUpdateRequest as UserUpdate,  # Alias for backward compatibility
    UserResponse,
    UserListResponse
)
from app.schemas.api_key import (
    APIKeyCreateRequest,
    APIKeyCreateRequest as APIKeyCreate,  # Alias for backward compatibility
    APIKeyResponse,
    APIKeyListResponse
)
from app.schemas.common import (
    ErrorResponse,
    SuccessResponse,
    PaginatedResponse,
    HealthResponse
)

__all__ = [
    "LoginRequest",
    "LoginResponse",
    "RegisterRequest",
    "RegisterResponse",
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "PasswordChangeRequest",
    "ChangePasswordRequest",
    "TokenResponse",
    "MFASetupResponse",
    "MFAVerificationRequest",
    "MFAVerifyRequest",
    "UserCreateRequest",
    "UserCreate",
    "UserUpdateRequest",
    "UserUpdate",
    "UserResponse",
    "UserListResponse",
    "APIKeyCreateRequest",
    "APIKeyCreate",
    "APIKeyResponse",
    "APIKeyListResponse",
    "ErrorResponse",
    "SuccessResponse",
    "PaginatedResponse",
    "HealthResponse"
]
