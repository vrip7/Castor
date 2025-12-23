"""
Main FastAPI application module.

This module initializes the FastAPI application with all middleware,
routes, exception handlers, and startup/shutdown events.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable
import sys

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from prometheus_client import make_asgi_app
from sqlalchemy import text
import structlog

from app.core.config import settings
from app.core.exceptions import (
    BaseAPIException,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    NotFoundError,
    RateLimitError,
    AccountLockedError,
    TokenError,
)
from app.db.session import engine, async_session_factory
from app.api import api_router
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_validation import RequestValidationMiddleware
from app.services.logging import get_logger, setup_logging
from app.services.metrics import MetricsService

# Initialize logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(
        "Starting application",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
    )
    
    # Initialize metrics
    MetricsService.initialize()
    
    # Verify database connection
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection verified")
    except Exception as e:
        logger.error("Failed to connect to database", error=str(e))
        if settings.app_env == "production":
            sys.exit(1)
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    
    # Close database connections
    await engine.dispose()
    logger.info("Database connections closed")


def create_application() -> FastAPI:
    """
    Application factory function.
    
    Creates and configures the FastAPI application with all middleware,
    routes, and exception handlers.
    """
    app = FastAPI(
        title=settings.app_name,
        description="Enterprise-grade Authentication API with comprehensive security features",
        version=settings.app_version,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )
    
    # Register middleware (order matters - first registered = last executed)
    register_middleware(app)
    
    # Register exception handlers
    register_exception_handlers(app)
    
    # Register routes
    register_routes(app)
    
    return app


def register_middleware(app: FastAPI) -> None:
    """Register all middleware components."""
    
    # Request ID middleware (should be first to ensure all requests have an ID)
    app.add_middleware(RequestIDMiddleware)
    
    # Security headers middleware
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Request validation middleware
    app.add_middleware(RequestValidationMiddleware)
    
    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)
    
    # GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Trusted host middleware (only in production)
    if settings.app_env == "production" and hasattr(settings.security, 'allowed_hosts') and settings.security.allowed_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.security.allowed_hosts,
        )
    
    # CORS middleware
    if settings.security.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.security.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Request-ID",
                "X-API-Key",
            ],
            expose_headers=["X-Request-ID"],
            max_age=600,  # Cache preflight for 10 minutes
        )
    
    logger.debug("Middleware registered")


def register_exception_handlers(app: FastAPI) -> None:
    """Register custom exception handlers."""
    
    @app.exception_handler(BaseAPIException)
    async def api_exception_handler(
        request: Request,
        exc: BaseAPIException
    ) -> JSONResponse:
        """Handle custom API exceptions."""
        logger.warning(
            "API exception",
            error_code=exc.error_code,
            message=exc.detail,
            status_code=exc.status_code,
            path=request.url.path,
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.error_code,
                    "message": exc.detail,
                    "details": exc.extra,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": request.url.path,
            },
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError
    ) -> JSONResponse:
        """Handle request validation errors."""
        errors = []
        for error in exc.errors():
            errors.append({
                "field": ".".join(str(loc) for loc in error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            })
        
        logger.warning(
            "Validation error",
            errors=errors,
            path=request.url.path,
        )
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": errors,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": request.url.path,
            },
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException
    ) -> JSONResponse:
        """Handle standard HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": "HTTP_ERROR",
                    "message": exc.detail,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": request.url.path,
            },
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request,
        exc: Exception
    ) -> JSONResponse:
        """Handle unexpected exceptions."""
        logger.exception(
            "Unhandled exception",
            error=str(exc),
            error_type=type(exc).__name__,
            path=request.url.path,
        )
        
        # Don't expose internal errors in production
        message = "An internal error occurred"
        if settings.debug:
            message = str(exc)
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": message,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": request.url.path,
            },
        )
    
    logger.debug("Exception handlers registered")


def register_routes(app: FastAPI) -> None:
    """Register all API routes."""
    
    # Health check at root level (no prefix, no auth)
    @app.get("/", include_in_schema=False)
    async def root() -> dict:
        """Root endpoint."""
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "status": "running",
        }
    
    # Root-level health endpoint for Docker healthcheck
    @app.get("/health", include_in_schema=False)
    async def health() -> dict:
        """Health check endpoint for container orchestration."""
        return {
            "status": "healthy",
            "service": settings.app_name,
            "version": settings.app_version,
        }
    
    # Mount Prometheus metrics endpoint
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)
    
    # API routes with version prefix
    app.include_router(
        api_router,
        prefix=settings.api_prefix,
    )
    
    logger.debug("Routes registered")


# Create the application instance
app = create_application()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        workers=1 if settings.debug else 4,
        log_level="debug" if settings.debug else "info",
        access_log=True,
    )
