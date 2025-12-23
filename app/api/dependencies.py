"""
API dependencies for authentication and authorization.
"""

from typing import List, Optional
from uuid import UUID

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import Permission, ROLE_PERMISSIONS, SecurityHeaders, UserRole, UserStatus
from app.core.exceptions import (
    AccountDisabledError,
    APIKeyError,
    AuthenticationError,
    AuthorizationError,
    TokenInvalidError
)
from app.db.session import get_db
from app.models.api_key import APIKey
from app.models.user import User
from app.security.api_key import get_api_key_service
from app.security.jwt import get_jwt_service, TokenPayload


# HTTP Bearer security scheme
bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser:
    """Container for current authenticated user information."""
    
    def __init__(
        self,
        user: User,
        token_payload: Optional[TokenPayload] = None,
        api_key: Optional[APIKey] = None
    ):
        self.user = user
        self.token_payload = token_payload
        self.api_key = api_key
        self.id = user.id
        self.email = user.email
        self.role = UserRole(user.role.value) if user.role else UserRole.USER
        self.permissions = self._get_permissions()
    
    def _get_permissions(self) -> List[Permission]:
        """Get user permissions from role and additional permissions."""
        # Get role-based permissions
        role_perms = set(ROLE_PERMISSIONS.get(self.role, []))
        
        # Add additional permissions
        if self.user.permissions:
            for perm in self.user.permissions:
                try:
                    role_perms.add(Permission(perm))
                except ValueError:
                    pass
        
        return list(role_perms)
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission."""
        return permission in self.permissions or Permission.SYSTEM_ADMIN in self.permissions
    
    def has_any_permission(self, permissions: List[Permission]) -> bool:
        """Check if user has any of the specified permissions."""
        return any(self.has_permission(p) for p in permissions)
    
    def has_all_permissions(self, permissions: List[Permission]) -> bool:
        """Check if user has all specified permissions."""
        return all(self.has_permission(p) for p in permissions)


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key_header: Optional[str] = Header(None, alias=SecurityHeaders.X_API_KEY),
    db: AsyncSession = Depends(get_db)
) -> Optional[CurrentUser]:
    """
    Get current user if authenticated (optional).
    
    Supports both JWT tokens and API keys.
    """
    jwt_service = get_jwt_service()
    api_key_service = get_api_key_service()
    
    # Try JWT token first
    if credentials and credentials.credentials:
        try:
            payload = jwt_service.verify_access_token(credentials.credentials)
            
            # Get user from database
            result = await db.execute(
                select(User).where(User.id == UUID(payload.sub))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return None
            
            if user.status != UserStatus.ACTIVE:
                raise AccountDisabledError()
            
            return CurrentUser(user=user, token_payload=payload)
            
        except Exception:
            pass
    
    # Try API key
    if api_key_header:
        if not api_key_service.validate_key_format(api_key_header):
            return None
        
        key_prefix = api_key_service.extract_prefix(api_key_header)
        key_hash = api_key_service._hash_key(api_key_header)
        
        # Find API key
        result = await db.execute(
            select(APIKey).where(
                APIKey.key_prefix == key_prefix,
                APIKey.key_hash == key_hash,
                APIKey.is_active == True
            )
        )
        api_key = result.scalar_one_or_none()
        
        if not api_key or not api_key.is_valid:
            return None
        
        # Check IP restrictions
        client_ip = getattr(request.state, "client_ip", None)
        if api_key.allowed_ips and client_ip:
            # TODO: Implement IP range checking
            pass
        
        # Get user
        result = await db.execute(
            select(User).where(User.id == api_key.user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user or user.status != UserStatus.ACTIVE:
            return None
        
        return CurrentUser(user=user, api_key=api_key)
    
    return None


async def get_current_user(
    current_user: Optional[CurrentUser] = Depends(get_current_user_optional)
) -> CurrentUser:
    """
    Get current authenticated user (required).
    
    Raises AuthenticationError if not authenticated.
    """
    if not current_user:
        raise AuthenticationError()
    return current_user


async def get_current_active_user(
    current_user: CurrentUser = Depends(get_current_user)
) -> CurrentUser:
    """
    Get current active user.
    
    Verifies user account is active.
    """
    if current_user.user.status != UserStatus.ACTIVE:
        raise AccountDisabledError()
    return current_user


def require_permissions(*permissions: Permission):
    """
    Dependency factory for permission-based access control.
    
    Usage:
        @router.get("/admin")
        async def admin_only(user: CurrentUser = Depends(require_permissions(Permission.SYSTEM_ADMIN))):
            ...
    """
    async def permission_checker(
        current_user: CurrentUser = Depends(get_current_active_user)
    ) -> CurrentUser:
        if not current_user.has_any_permission(list(permissions)):
            raise AuthorizationError(
                required_permission=", ".join(p.value for p in permissions)
            )
        return current_user
    
    return permission_checker


def require_all_permissions(*permissions: Permission):
    """
    Dependency factory requiring ALL specified permissions.
    """
    async def permission_checker(
        current_user: CurrentUser = Depends(get_current_active_user)
    ) -> CurrentUser:
        if not current_user.has_all_permissions(list(permissions)):
            raise AuthorizationError(
                required_permission=", ".join(p.value for p in permissions)
            )
        return current_user
    
    return permission_checker


def require_role(*roles: UserRole):
    """
    Dependency factory for role-based access control.
    
    Usage:
        @router.get("/admin")
        async def admin_only(user: CurrentUser = Depends(require_role(UserRole.ADMIN))):
            ...
    """
    async def role_checker(
        current_user: CurrentUser = Depends(get_current_active_user)
    ) -> CurrentUser:
        if current_user.role not in roles:
            raise AuthorizationError(
                detail=f"Role {current_user.role.value} not authorized"
            )
        return current_user
    
    return role_checker


class RateLimitDependency:
    """Rate limiting dependency with custom limits."""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
    
    async def __call__(self, request: Request) -> None:
        # Rate limiting is handled by middleware
        # This is for custom per-endpoint limits
        pass
