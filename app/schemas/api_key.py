"""
API Key schemas.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class APIKeyCreateRequest(BaseModel):
    """API key creation request."""
    name: str = Field(..., min_length=1, max_length=255, description="Key name")
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description="Days until expiration (max 365)"
    )
    permissions: Optional[List[str]] = Field(default=[], description="Allowed permissions")
    allowed_ips: Optional[List[str]] = Field(default=[], description="Allowed IP addresses (CIDR notation)")
    rate_limit: Optional[int] = Field(default=None, ge=1, le=10000, description="Rate limit per minute")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Production API Key",
                "expires_in_days": 90,
                "permissions": ["user:read", "api_key:read"],
                "allowed_ips": ["10.0.0.0/8"],
                "rate_limit": 100
            }
        }


class APIKeyCreateResponse(BaseModel):
    """API key creation response (includes full key - shown only once)."""
    id: str = Field(..., description="Key ID")
    name: str = Field(..., description="Key name")
    key: str = Field(..., description="Full API key (only shown once!)")
    key_prefix: str = Field(..., description="Key prefix for identification")
    permissions: List[str] = Field(default=[])
    allowed_ips: List[str] = Field(default=[])
    rate_limit: int = Field(...)
    expires_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(...)
    message: str = Field(default="Store this API key securely. It will not be shown again.")
    
    class Config:
        from_attributes = True


class APIKeyResponse(BaseModel):
    """API key response (without full key)."""
    id: str = Field(..., description="Key ID")
    user_id: str = Field(..., description="Owner user ID")
    name: str = Field(..., description="Key name")
    key_prefix: str = Field(..., description="Key prefix for identification")
    permissions: List[str] = Field(default=[])
    allowed_ips: List[str] = Field(default=[])
    rate_limit: int = Field(...)
    expires_at: Optional[datetime] = Field(default=None)
    last_used_at: Optional[datetime] = Field(default=None)
    last_used_ip: Optional[str] = Field(default=None)
    usage_count: int = Field(default=0)
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(...)
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "user_id": "123e4567-e89b-12d3-a456-426614174001",
                "name": "Production API Key",
                "key_prefix": "cstr_abc123",
                "permissions": ["user:read"],
                "allowed_ips": [],
                "rate_limit": 100,
                "expires_at": "2025-01-01T00:00:00Z",
                "last_used_at": "2024-01-01T00:00:00Z",
                "usage_count": 1000,
                "revoked": False,
                "created_at": "2024-01-01T00:00:00Z"
            }
        }


class APIKeyListResponse(BaseModel):
    """API key list response."""
    items: List[APIKeyResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class APIKeyUpdateRequest(BaseModel):
    """API key update request."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    permissions: Optional[List[str]] = Field(default=None)
    allowed_ips: Optional[List[str]] = Field(default=None)
    rate_limit: Optional[int] = Field(default=None, ge=1, le=10000)


class APIKeyRotateResponse(BaseModel):
    """API key rotation response (includes new full key)."""
    id: str = Field(..., description="Key ID")
    name: str = Field(..., description="Key name")
    key: str = Field(..., description="New full API key (only shown once!)")
    key_prefix: str = Field(..., description="New key prefix")
    message: str = Field(default="API key rotated successfully. Store the new key securely.")
