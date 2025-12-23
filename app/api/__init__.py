"""
API routes initialization.
"""

from fastapi import APIRouter

from app.api.routes.auth import router as auth_router
from app.api.routes.users import router as users_router
from app.api.routes.api_keys import router as api_keys_router
from app.api.routes.mfa import router as mfa_router
from app.api.routes.health import router as health_router

# Create main API router
api_router = APIRouter()

# Include all route modules
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(api_keys_router)
api_router.include_router(mfa_router)
api_router.include_router(health_router)

__all__ = [
    "api_router",
    "auth_router",
    "users_router",
    "api_keys_router",
    "mfa_router",
    "health_router"
]
