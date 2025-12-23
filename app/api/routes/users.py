"""
User management API endpoints.

Handles user CRUD operations, profile management, and administrative functions.
"""

from datetime import datetime, timezone
from typing import Optional, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import (
    AuditAction,
    UserStatus,
    UserRole,
    Permission,
)
from app.core.exceptions import (
    NotFoundError,
    ForbiddenError,
    ValidationError,
)
from app.db.session import get_db
from app.models.user import User
from app.models.session import UserSession
from app.schemas.user import (
    UserResponse,
    UserListResponse,
    UserUpdateRequest,
    UserCreateRequest,
    UserStatusUpdateRequest,
    UserRoleUpdateRequest,
)
from app.schemas.common import PaginationParams, PaginatedResponse
from app.security.password import PasswordService
from app.security.encryption import EncryptionService
from app.services.audit import AuditService
from app.services.logging import get_logger
from app.api.dependencies import (
    get_current_user,
    CurrentUser,
    require_permissions,
    require_role,
)

router = APIRouter(prefix="/users", tags=["Users"])
logger = get_logger(__name__)


@router.get("", response_model=UserListResponse)
async def list_users(
    request: Request,
    current_user: CurrentUser = Depends(require_permissions([Permission.USER_READ])),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, max_length=100, description="Search by email or username"),
    status_filter: Optional[UserStatus] = Query(None, alias="status", description="Filter by status"),
    role_filter: Optional[UserRole] = Query(None, alias="role", description="Filter by role"),
) -> UserListResponse:
    """
    List all users with pagination and filtering.
    
    Requires USER_READ permission.
    """
    # Build query
    query = select(User)
    count_query = select(func.count(User.id))
    
    # Apply filters
    conditions = []
    
    if search:
        search_term = f"%{search.lower()}%"
        conditions.append(
            or_(
                User.email.ilike(search_term),
                User.username.ilike(search_term),
            )
        )
    
    if status_filter:
        conditions.append(User.status == status_filter)
    
    if role_filter:
        conditions.append(User.role == role_filter)
    
    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.order_by(User.created_at.desc()).offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query)
    users = result.scalars().all()
    
    # Build response
    encryption_service = EncryptionService()
    user_responses = []
    
    for user in users:
        user_responses.append(
            UserResponse(
                id=user.id,
                email=user.email,
                username=user.username,
                first_name=encryption_service.decrypt(user.first_name_encrypted) if user.first_name_encrypted else None,
                last_name=encryption_service.decrypt(user.last_name_encrypted) if user.last_name_encrypted else None,
                role=user.role,
                status=user.status,
                email_verified=user.email_verified,
                mfa_enabled=user.mfa_enabled,
                created_at=user.created_at,
                last_login=user.last_login,
            )
        )
    
    return UserListResponse(
        items=user_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    data: UserCreateRequest,
    current_user: CurrentUser = Depends(require_permissions([Permission.USER_CREATE])),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Create a new user (admin function).
    
    Requires USER_CREATE permission.
    """
    # Check if email already exists
    existing = await db.execute(
        select(User).where(
            or_(
                User.email == data.email.lower(),
                User.username == data.username.lower(),
            )
        )
    )
    if existing.scalar_one_or_none():
        raise ValidationError("Email or username already exists.")
    
    # Hash password
    password_hash = PasswordService.hash_password(data.password)
    
    # Encrypt PII
    encryption_service = EncryptionService()
    
    # Create user
    user = User(
        id=str(uuid4()),
        email=data.email.lower(),
        username=data.username.lower(),
        password_hash=password_hash,
        first_name_encrypted=encryption_service.encrypt(data.first_name) if data.first_name else None,
        last_name_encrypted=encryption_service.encrypt(data.last_name) if data.last_name else None,
        phone_encrypted=encryption_service.encrypt(data.phone) if data.phone else None,
        role=data.role or UserRole.USER,
        status=UserStatus.ACTIVE if data.skip_verification else UserStatus.PENDING_VERIFICATION,
        email_verified=data.skip_verification,
        email_verified_at=datetime.now(timezone.utc) if data.skip_verification else None,
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    await AuditService.log(
        db=db,
        action=AuditAction.USER_CREATED,
        user_id=current_user.user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={
            "created_user_id": user.id,
            "created_user_email": user.email,
            "role": user.role.value,
        },
    )
    
    logger.info(
        "User created by admin",
        created_user_id=user.id,
        admin_user_id=current_user.user.id,
    )
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=data.first_name,
        last_name=data.last_name,
        role=user.role,
        status=user.status,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Get user by ID.
    
    Users can view their own profile.
    Admins can view any user.
    """
    # Check authorization
    if user_id != current_user.user.id and not current_user.has_permission(Permission.USER_READ):
        raise ForbiddenError("You don't have permission to view this user.")
    
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise NotFoundError("User not found.")
    
    encryption_service = EncryptionService()
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=encryption_service.decrypt(user.first_name_encrypted) if user.first_name_encrypted else None,
        last_name=encryption_service.decrypt(user.last_name_encrypted) if user.last_name_encrypted else None,
        role=user.role,
        status=user.status,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: str,
    data: UserUpdateRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Update user profile.
    
    Users can update their own profile (limited fields).
    Admins can update any user.
    """
    # Check authorization
    is_self = user_id == current_user.user.id
    is_admin = current_user.has_permission(Permission.USER_UPDATE)
    
    if not is_self and not is_admin:
        raise ForbiddenError("You don't have permission to update this user.")
    
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise NotFoundError("User not found.")
    
    encryption_service = EncryptionService()
    changes = {}
    
    # Update fields
    if data.first_name is not None:
        user.first_name_encrypted = encryption_service.encrypt(data.first_name) if data.first_name else None
        changes["first_name"] = "updated"
    
    if data.last_name is not None:
        user.last_name_encrypted = encryption_service.encrypt(data.last_name) if data.last_name else None
        changes["last_name"] = "updated"
    
    if data.phone is not None:
        user.phone_encrypted = encryption_service.encrypt(data.phone) if data.phone else None
        changes["phone"] = "updated"
    
    # Username change (check uniqueness)
    if data.username is not None and data.username.lower() != user.username:
        existing = await db.execute(
            select(User).where(
                and_(
                    User.username == data.username.lower(),
                    User.id != user.id,
                )
            )
        )
        if existing.scalar_one_or_none():
            raise ValidationError("Username is already taken.")
        user.username = data.username.lower()
        changes["username"] = data.username
    
    user.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    await db.refresh(user)
    
    await AuditService.log(
        db=db,
        action=AuditAction.USER_UPDATED,
        user_id=current_user.user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"changes": changes},
    )
    
    logger.info("User updated", user_id=user.id, updated_by=current_user.user.id)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=encryption_service.decrypt(user.first_name_encrypted) if user.first_name_encrypted else None,
        last_name=encryption_service.decrypt(user.last_name_encrypted) if user.last_name_encrypted else None,
        role=user.role,
        status=user.status,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.patch("/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    request: Request,
    user_id: str,
    data: UserStatusUpdateRequest,
    current_user: CurrentUser = Depends(require_permissions([Permission.USER_UPDATE])),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Update user status (activate, suspend, deactivate).
    
    Requires USER_UPDATE permission.
    Cannot modify own status.
    """
    if user_id == current_user.user.id:
        raise ForbiddenError("You cannot modify your own status.")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise NotFoundError("User not found.")
    
    old_status = user.status
    user.status = data.status
    user.updated_at = datetime.now(timezone.utc)
    
    # If suspending or deactivating, revoke all sessions
    if data.status in [UserStatus.SUSPENDED, UserStatus.DEACTIVATED]:
        await db.execute(
            update(UserSession)
            .where(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.revoked == False,
                )
            )
            .values(revoked=True, revoked_at=datetime.now(timezone.utc))
        )
    
    await db.commit()
    await db.refresh(user)
    
    await AuditService.log(
        db=db,
        action=AuditAction.USER_STATUS_CHANGED,
        user_id=current_user.user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={
            "old_status": old_status.value,
            "new_status": data.status.value,
            "reason": data.reason,
        },
    )
    
    logger.info(
        "User status changed",
        user_id=user.id,
        old_status=old_status.value,
        new_status=data.status.value,
        changed_by=current_user.user.id,
    )
    
    encryption_service = EncryptionService()
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=encryption_service.decrypt(user.first_name_encrypted) if user.first_name_encrypted else None,
        last_name=encryption_service.decrypt(user.last_name_encrypted) if user.last_name_encrypted else None,
        role=user.role,
        status=user.status,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    request: Request,
    user_id: str,
    data: UserRoleUpdateRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.SUPER_ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """
    Update user role.
    
    Requires SUPER_ADMIN role.
    Cannot modify own role.
    """
    if user_id == current_user.user.id:
        raise ForbiddenError("You cannot modify your own role.")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise NotFoundError("User not found.")
    
    old_role = user.role
    user.role = data.role
    user.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    await db.refresh(user)
    
    await AuditService.log(
        db=db,
        action=AuditAction.USER_ROLE_CHANGED,
        user_id=current_user.user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={
            "old_role": old_role.value,
            "new_role": data.role.value,
        },
    )
    
    logger.info(
        "User role changed",
        user_id=user.id,
        old_role=old_role.value,
        new_role=data.role.value,
        changed_by=current_user.user.id,
    )
    
    encryption_service = EncryptionService()
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=encryption_service.decrypt(user.first_name_encrypted) if user.first_name_encrypted else None,
        last_name=encryption_service.decrypt(user.last_name_encrypted) if user.last_name_encrypted else None,
        role=user.role,
        status=user.status,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: str,
    current_user: CurrentUser = Depends(require_permissions([Permission.USER_DELETE])),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Delete a user (soft delete by deactivating).
    
    Requires USER_DELETE permission.
    Cannot delete own account through this endpoint.
    """
    if user_id == current_user.user.id:
        raise ForbiddenError("You cannot delete your own account through this endpoint.")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise NotFoundError("User not found.")
    
    # Soft delete - change status to deactivated
    user.status = UserStatus.DEACTIVATED
    user.updated_at = datetime.now(timezone.utc)
    
    # Revoke all sessions
    await db.execute(
        update(UserSession)
        .where(
            and_(
                UserSession.user_id == user.id,
                UserSession.revoked == False,
            )
        )
        .values(revoked=True, revoked_at=datetime.now(timezone.utc))
    )
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.USER_DELETED,
        user_id=current_user.user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"deleted_user_email": user.email},
    )
    
    logger.info(
        "User deleted (soft)",
        user_id=user.id,
        deleted_by=current_user.user.id,
    )


@router.get("/{user_id}/sessions")
async def get_user_sessions(
    user_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[dict]:
    """
    Get active sessions for a user.
    
    Users can view their own sessions.
    Admins can view any user's sessions.
    """
    if user_id != current_user.user.id and not current_user.has_permission(Permission.USER_READ):
        raise ForbiddenError("You don't have permission to view this user's sessions.")
    
    result = await db.execute(
        select(UserSession)
        .where(
            and_(
                UserSession.user_id == user_id,
                UserSession.revoked == False,
                UserSession.expires_at > datetime.now(timezone.utc),
            )
        )
        .order_by(UserSession.created_at.desc())
    )
    sessions = result.scalars().all()
    
    return [
        {
            "id": session.id,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat() if session.last_activity else None,
            "expires_at": session.expires_at.isoformat(),
        }
        for session in sessions
    ]


@router.delete("/{user_id}/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    request: Request,
    user_id: str,
    session_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Revoke a specific session.
    
    Users can revoke their own sessions.
    Admins can revoke any session.
    """
    if user_id != current_user.user.id and not current_user.has_permission(Permission.USER_UPDATE):
        raise ForbiddenError("You don't have permission to revoke this session.")
    
    result = await db.execute(
        select(UserSession).where(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
            )
        )
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise NotFoundError("Session not found.")
    
    session.revoked = True
    session.revoked_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.SESSION_REVOKED,
        user_id=current_user.user.id,
        resource_type="session",
        resource_id=session_id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"target_user_id": user_id},
    )
    
    logger.info(
        "Session revoked",
        session_id=session_id,
        user_id=user_id,
        revoked_by=current_user.user.id,
    )
