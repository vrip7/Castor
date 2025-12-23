"""
API Key management endpoints.

Handles API key creation, listing, rotation, and revocation.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from sqlalchemy import select, update, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import (
    AuditAction,
    Permission,
)
from app.core.exceptions import (
    NotFoundError,
    ForbiddenError,
    ValidationError,
)
from app.db.session import get_db
from app.models.api_key import APIKey
from app.schemas.api_key import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyResponse,
    APIKeyListResponse,
    APIKeyUpdateRequest,
    APIKeyRotateResponse,
)
from app.schemas.common import MessageResponse
from app.security.api_key import APIKeyService
from app.security.password import PasswordService
from app.services.audit import AuditService
from app.services.logging import get_logger
from app.api.dependencies import (
    get_current_user,
    CurrentUser,
    require_permissions,
)

router = APIRouter(prefix="/api-keys", tags=["API Keys"])
logger = get_logger(__name__)


@router.post("", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: Request,
    data: APIKeyCreateRequest,
    current_user: CurrentUser = Depends(require_permissions([Permission.API_KEY_CREATE])),
    db: AsyncSession = Depends(get_db),
) -> APIKeyCreateResponse:
    """
    Create a new API key.
    
    The full API key is only returned once upon creation.
    Store it securely as it cannot be retrieved again.
    """
    # Check key limit per user
    count_result = await db.execute(
        select(func.count(APIKey.id)).where(
            and_(
                APIKey.user_id == current_user.user.id,
                APIKey.revoked == False,
            )
        )
    )
    current_count = count_result.scalar() or 0
    
    max_keys = settings.security.max_api_keys_per_user
    if current_count >= max_keys:
        raise ValidationError(f"Maximum number of API keys ({max_keys}) reached.")
    
    # Generate API key
    key_id, key_secret, full_key = APIKeyService.generate_api_key()
    
    # Hash the secret for storage
    key_hash = PasswordService.hash_password(key_secret)
    
    # Calculate expiration
    expires_at = None
    if data.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_in_days)
    
    # Create API key record
    api_key = APIKey(
        id=str(uuid4()),
        user_id=current_user.user.id,
        name=data.name,
        key_prefix=key_id,
        key_hash=key_hash,
        permissions=data.permissions or [],
        allowed_ips=data.allowed_ips or [],
        rate_limit=data.rate_limit or settings.security.api_key_default_rate_limit,
        expires_at=expires_at,
    )
    
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    await AuditService.log(
        db=db,
        action=AuditAction.API_KEY_CREATED,
        user_id=current_user.user.id,
        resource_type="api_key",
        resource_id=api_key.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={
            "key_name": api_key.name,
            "key_prefix": key_id,
            "permissions": data.permissions,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    
    logger.info(
        "API key created",
        api_key_id=api_key.id,
        key_prefix=key_id,
        user_id=current_user.user.id,
    )
    
    return APIKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        key=full_key,  # Only returned once!
        key_prefix=key_id,
        permissions=api_key.permissions,
        allowed_ips=api_key.allowed_ips,
        rate_limit=api_key.rate_limit,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        message="Store this API key securely. It will not be shown again.",
    )


@router.get("", response_model=APIKeyListResponse)
async def list_api_keys(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    include_revoked: bool = Query(False, description="Include revoked keys"),
) -> APIKeyListResponse:
    """
    List API keys for the current user.
    
    Admins with API_KEY_READ permission can see all keys.
    """
    # Build query
    if current_user.has_permission(Permission.API_KEY_READ):
        # Admin can see all keys
        query = select(APIKey)
        count_query = select(func.count(APIKey.id))
    else:
        # Users can only see their own keys
        query = select(APIKey).where(APIKey.user_id == current_user.user.id)
        count_query = select(func.count(APIKey.id)).where(APIKey.user_id == current_user.user.id)
    
    if not include_revoked:
        query = query.where(APIKey.revoked == False)
        count_query = count_query.where(APIKey.revoked == False)
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.order_by(APIKey.created_at.desc()).offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query)
    api_keys = result.scalars().all()
    
    # Build response
    key_responses = [
        APIKeyResponse(
            id=key.id,
            user_id=key.user_id,
            name=key.name,
            key_prefix=key.key_prefix,
            permissions=key.permissions,
            allowed_ips=key.allowed_ips,
            rate_limit=key.rate_limit,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
            last_used_ip=key.last_used_ip,
            usage_count=key.usage_count,
            revoked=key.revoked,
            revoked_at=key.revoked_at,
            created_at=key.created_at,
        )
        for key in api_keys
    ]
    
    return APIKeyListResponse(
        items=key_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIKeyResponse:
    """
    Get API key details by ID.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise NotFoundError("API key not found.")
    
    # Check authorization
    if api_key.user_id != current_user.user.id and not current_user.has_permission(Permission.API_KEY_READ):
        raise ForbiddenError("You don't have permission to view this API key.")
    
    return APIKeyResponse(
        id=api_key.id,
        user_id=api_key.user_id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        permissions=api_key.permissions,
        allowed_ips=api_key.allowed_ips,
        rate_limit=api_key.rate_limit,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        last_used_ip=api_key.last_used_ip,
        usage_count=api_key.usage_count,
        revoked=api_key.revoked,
        revoked_at=api_key.revoked_at,
        created_at=api_key.created_at,
    )


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    request: Request,
    key_id: str,
    data: APIKeyUpdateRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIKeyResponse:
    """
    Update API key settings.
    
    Can update name, permissions, allowed IPs, and rate limit.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise NotFoundError("API key not found.")
    
    # Check authorization
    if api_key.user_id != current_user.user.id and not current_user.has_permission(Permission.API_KEY_UPDATE):
        raise ForbiddenError("You don't have permission to update this API key.")
    
    if api_key.revoked:
        raise ValidationError("Cannot update a revoked API key.")
    
    changes = {}
    
    if data.name is not None:
        api_key.name = data.name
        changes["name"] = data.name
    
    if data.permissions is not None:
        api_key.permissions = data.permissions
        changes["permissions"] = data.permissions
    
    if data.allowed_ips is not None:
        api_key.allowed_ips = data.allowed_ips
        changes["allowed_ips"] = data.allowed_ips
    
    if data.rate_limit is not None:
        api_key.rate_limit = data.rate_limit
        changes["rate_limit"] = data.rate_limit
    
    api_key.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    await db.refresh(api_key)
    
    await AuditService.log(
        db=db,
        action=AuditAction.API_KEY_UPDATED,
        user_id=current_user.user.id,
        resource_type="api_key",
        resource_id=api_key.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"changes": changes},
    )
    
    logger.info(
        "API key updated",
        api_key_id=api_key.id,
        user_id=current_user.user.id,
    )
    
    return APIKeyResponse(
        id=api_key.id,
        user_id=api_key.user_id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        permissions=api_key.permissions,
        allowed_ips=api_key.allowed_ips,
        rate_limit=api_key.rate_limit,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        last_used_ip=api_key.last_used_ip,
        usage_count=api_key.usage_count,
        revoked=api_key.revoked,
        revoked_at=api_key.revoked_at,
        created_at=api_key.created_at,
    )


@router.post("/{key_id}/rotate", response_model=APIKeyRotateResponse)
async def rotate_api_key(
    request: Request,
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIKeyRotateResponse:
    """
    Rotate an API key.
    
    Generates a new key secret while preserving all other settings.
    The old key is immediately invalidated.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise NotFoundError("API key not found.")
    
    # Check authorization
    if api_key.user_id != current_user.user.id and not current_user.has_permission(Permission.API_KEY_UPDATE):
        raise ForbiddenError("You don't have permission to rotate this API key.")
    
    if api_key.revoked:
        raise ValidationError("Cannot rotate a revoked API key.")
    
    # Generate new key
    new_key_id, new_key_secret, new_full_key = APIKeyService.generate_api_key()
    
    # Update key
    api_key.key_prefix = new_key_id
    api_key.key_hash = PasswordService.hash_password(new_key_secret)
    api_key.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    await db.refresh(api_key)
    
    await AuditService.log(
        db=db,
        action=AuditAction.API_KEY_ROTATED,
        user_id=current_user.user.id,
        resource_type="api_key",
        resource_id=api_key.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"new_key_prefix": new_key_id},
    )
    
    logger.info(
        "API key rotated",
        api_key_id=api_key.id,
        new_key_prefix=new_key_id,
        user_id=current_user.user.id,
    )
    
    return APIKeyRotateResponse(
        id=api_key.id,
        name=api_key.name,
        key=new_full_key,  # Only returned once!
        key_prefix=new_key_id,
        message="API key rotated successfully. Store the new key securely.",
    )


@router.delete("/{key_id}", response_model=MessageResponse)
async def revoke_api_key(
    request: Request,
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Revoke an API key.
    
    The key is immediately invalidated and cannot be used.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise NotFoundError("API key not found.")
    
    # Check authorization
    if api_key.user_id != current_user.user.id and not current_user.has_permission(Permission.API_KEY_DELETE):
        raise ForbiddenError("You don't have permission to revoke this API key.")
    
    if api_key.revoked:
        return MessageResponse(message="API key is already revoked.")
    
    api_key.revoked = True
    api_key.revoked_at = datetime.now(timezone.utc)
    api_key.revoked_by = current_user.user.id
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.API_KEY_REVOKED,
        user_id=current_user.user.id,
        resource_type="api_key",
        resource_id=api_key.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"key_prefix": api_key.key_prefix},
    )
    
    logger.info(
        "API key revoked",
        api_key_id=api_key.id,
        key_prefix=api_key.key_prefix,
        user_id=current_user.user.id,
    )
    
    return MessageResponse(message="API key revoked successfully.")


@router.get("/{key_id}/usage")
async def get_api_key_usage(
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Get usage statistics for an API key.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise NotFoundError("API key not found.")
    
    # Check authorization
    if api_key.user_id != current_user.user.id and not current_user.has_permission(Permission.API_KEY_READ):
        raise ForbiddenError("You don't have permission to view this API key's usage.")
    
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "usage_count": api_key.usage_count,
        "last_used_at": api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        "last_used_ip": api_key.last_used_ip,
        "rate_limit": api_key.rate_limit,
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        "is_active": not api_key.revoked and (
            api_key.expires_at is None or api_key.expires_at > datetime.now(timezone.utc)
        ),
    }
