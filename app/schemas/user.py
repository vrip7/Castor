"""
User schemas.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.constants import UserRole, UserStatus


class UserCreateRequest(BaseModel):
    """Admin user creation request."""
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=12, description="User password")
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=20)
    role: Optional[UserRole] = Field(default=UserRole.USER)
    skip_verification: bool = Field(default=False, description="Skip email verification")
    
    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()
    
    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower().strip()


class UserUpdateRequest(BaseModel):
    """User update request."""
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=20)
    username: Optional[str] = Field(default=None, min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")


class UserStatusUpdateRequest(BaseModel):
    """User status update request."""
    status: UserStatus = Field(..., description="New user status")
    reason: Optional[str] = Field(default=None, max_length=500, description="Reason for status change")


class UserRoleUpdateRequest(BaseModel):
    """User role update request."""
    role: UserRole = Field(..., description="New user role")


class UserResponse(BaseModel):
    """User response."""
    id: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    username: str = Field(..., description="Username")
    first_name: Optional[str] = Field(default=None)
    last_name: Optional[str] = Field(default=None)
    role: UserRole = Field(..., description="User role")
    status: UserStatus = Field(..., description="Account status")
    email_verified: bool = Field(..., description="Email verification status")
    mfa_enabled: bool = Field(default=False)
    created_at: datetime = Field(...)
    last_login: Optional[datetime] = Field(default=None)
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "user@example.com",
                "username": "johndoe",
                "first_name": "John",
                "last_name": "Doe",
                "role": "user",
                "status": "active",
                "email_verified": True,
                "mfa_enabled": True,
                "created_at": "2024-01-01T00:00:00Z",
                "last_login": "2024-01-01T00:00:00Z"
            }
        }


class UserListResponse(BaseModel):
    """User list response."""
    items: List[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
