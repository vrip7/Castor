"""
Authentication schemas.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.constants import UserRole


class LoginRequest(BaseModel):
    """User login request."""
    identifier: str = Field(..., description="User email or username")
    password: str = Field(..., min_length=1, description="User password")
    mfa_code: Optional[str] = Field(
        default=None,
        min_length=6,
        max_length=6,
        description="MFA TOTP code (if MFA is enabled)"
    )
    device_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Device identifier for trusted devices"
    )
    device_name: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Human-readable device name"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "identifier": "user@example.com",
                "password": "SecurePassword123!",
                "mfa_code": "123456"
            }
        }


class TokenResponse(BaseModel):
    """Token pair response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzUxMiIs...",
                "refresh_token": "eyJhbGciOiJIUzUxMiIs...",
                "token_type": "bearer",
                "expires_in": 900
            }
        }


class LoginResponse(BaseModel):
    """Login response."""
    access_token: str = Field(default="", description="JWT access token")
    refresh_token: str = Field(default="", description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(default=0, description="Access token expiration in seconds")
    requires_mfa: bool = Field(default=False, description="Whether MFA verification is needed")
    mfa_type: Optional[str] = Field(default=None, description="Type of MFA required (totp)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzUxMiIs...",
                "refresh_token": "eyJhbGciOiJIUzUxMiIs...",
                "token_type": "bearer",
                "expires_in": 900,
                "requires_mfa": False
            }
        }


class UserBasicInfo(BaseModel):
    """Basic user information for responses."""
    id: str
    email: str
    role: str
    mfa_enabled: bool = False


class RegisterRequest(BaseModel):
    """User registration request."""
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Username (alphanumeric, underscore, hyphen)"
    )
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="User password (min 12 chars)"
    )
    password_confirm: str = Field(..., description="Password confirmation")
    first_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="User's first name"
    )
    last_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="User's last name"
    )
    phone: Optional[str] = Field(
        default=None,
        max_length=20,
        description="Phone number"
    )
    
    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()
    
    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower().strip()
    
    @field_validator("password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "username": "johndoe",
                "password": "SecurePassword123!",
                "password_confirm": "SecurePassword123!",
                "first_name": "John",
                "last_name": "Doe"
            }
        }


class RegisterResponse(BaseModel):
    """Registration response."""
    user_id: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    message: str = Field(..., description="Registration message")
    requires_verification: bool = Field(
        default=True,
        description="Whether email verification is needed"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "user@example.com",
                "message": "Registration successful. Please verify your email.",
                "requires_verification": True
            }
        }


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str = Field(..., description="Refresh token")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzUxMiIs..."
            }
        }


class RefreshTokenResponse(BaseModel):
    """Token refresh response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")


class LogoutRequest(BaseModel):
    """Logout request."""
    refresh_token: Optional[str] = Field(default=None, description="Refresh token to invalidate")
    all_sessions: bool = Field(default=False, description="Logout from all sessions")


class MessageResponse(BaseModel):
    """Simple message response."""
    message: str = Field(..., description="Response message")


class PasswordResetRequest(BaseModel):
    """Password reset request."""
    email: EmailStr = Field(..., description="User email address")
    
    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation."""
    email: EmailStr = Field(..., description="User email address")
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="New password"
    )
    new_password_confirm: str = Field(..., description="New password confirmation")
    
    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()
    
    @field_validator("new_password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "token": "reset_token_here",
                "new_password": "NewSecurePassword123!",
                "new_password_confirm": "NewSecurePassword123!"
            }
        }


class PasswordChangeRequest(BaseModel):
    """Change password request (for authenticated users)."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="New password"
    )
    new_password_confirm: str = Field(..., description="New password confirmation")
    logout_other_sessions: bool = Field(default=True, description="Logout other sessions after password change")
    
    @field_validator("new_password_confirm")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "current_password": "CurrentPassword123!",
                "new_password": "NewSecurePassword123!",
                "new_password_confirm": "NewSecurePassword123!",
                "logout_other_sessions": True
            }
        }


class MFASetupResponse(BaseModel):
    """MFA setup response."""
    secret: str = Field(..., description="TOTP secret (base32 encoded)")
    qr_code: str = Field(..., description="QR code image (base64 PNG)")
    provisioning_uri: str = Field(..., description="otpauth:// URI")
    backup_codes: List[str] = Field(..., description="One-time backup codes")
    
    class Config:
        json_schema_extra = {
            "example": {
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code": "iVBORw0KGgoAAAANSUhEUgAA...",
                "provisioning_uri": "otpauth://totp/CastorAuth:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=CastorAuth",
                "backup_codes": ["ABCD-1234", "EFGH-5678"]
            }
        }


class MFAVerificationRequest(BaseModel):
    """MFA verification request."""
    code: str = Field(
        ...,
        min_length=6,
        max_length=10,
        description="TOTP code or backup code"
    )
    mfa_token: Optional[str] = Field(
        default=None,
        description="Temporary MFA token from login"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "code": "123456"
            }
        }
