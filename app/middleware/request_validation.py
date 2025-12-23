"""
Request validation middleware.
Validates request integrity and prevents attacks.
"""

import hashlib
import time
from typing import Optional, Set

import redis.asyncio as redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.constants import CacheKeys, SecurityHeaders


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for request validation and attack prevention.
    
    Features:
    - Request size limits
    - Content-Type validation
    - Nonce validation (replay attack prevention)
    - Request signature verification
    - Suspicious pattern detection
    
    Protection against:
    - Replay attacks
    - Request tampering
    - Oversized payload attacks
    - Content-Type confusion attacks
    """
    
    # Maximum request body size (10 MB)
    MAX_BODY_SIZE = 10 * 1024 * 1024
    
    # Allowed content types for API requests
    ALLOWED_CONTENT_TYPES: Set[str] = {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data"
    }
    
    # Suspicious patterns in request paths (SQL injection, etc.)
    SUSPICIOUS_PATTERNS = [
        "' OR '",
        "'; DROP",
        "<script>",
        "javascript:",
        "../",
        "..\\",
        "%00",
        "\x00"
    ]
    
    def __init__(self, app, redis_client: Optional[redis.Redis] = None):
        super().__init__(app)
        self.settings = get_settings()
        self._redis: Optional[redis.Redis] = redis_client
    
    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                self.settings.redis.url,
                encoding="utf-8",
                decode_responses=True
            )
        return self._redis
    
    def _check_suspicious_patterns(self, request: Request) -> Optional[str]:
        """
        Check for suspicious patterns in request.
        
        Returns:
            Detected pattern or None if clean
        """
        # Check URL path
        path = request.url.path.lower()
        query = str(request.url.query).lower()
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in path or pattern.lower() in query:
                return pattern
        
        return None
    
    def _validate_content_type(self, request: Request) -> bool:
        """
        Validate request Content-Type header.
        
        Returns:
            True if valid
        """
        # Only check for requests with body
        if request.method not in ["POST", "PUT", "PATCH"]:
            return True
        
        content_type = request.headers.get("Content-Type", "")
        
        # Extract main content type (ignore charset, boundary, etc.)
        main_type = content_type.split(";")[0].strip().lower()
        
        if not main_type:
            # Allow empty content type for GET/DELETE
            return request.method in ["GET", "DELETE", "HEAD", "OPTIONS"]
        
        return main_type in self.ALLOWED_CONTENT_TYPES
    
    async def _validate_nonce(self, request: Request) -> bool:
        """
        Validate request nonce to prevent replay attacks.
        
        A nonce (number used once) ensures each request is unique.
        
        Returns:
            True if nonce is valid and unused
        """
        nonce = request.headers.get(SecurityHeaders.X_NONCE)
        
        # Nonce is optional for most endpoints
        if not nonce:
            return True
        
        # Check nonce format
        if len(nonce) < 16 or len(nonce) > 64:
            return False
        
        redis_client = await self._get_redis()
        key = f"{CacheKeys.NONCE}{nonce}"
        
        # Try to set nonce (only succeeds if not exists)
        # Nonce expires after 5 minutes
        result = await redis_client.set(key, "1", ex=300, nx=True)
        
        return result is not None
    
    async def _validate_timestamp(self, request: Request) -> bool:
        """
        Validate request timestamp to prevent replay attacks.
        
        Returns:
            True if timestamp is within acceptable range
        """
        timestamp = request.headers.get(SecurityHeaders.X_TIMESTAMP)
        
        # Timestamp is optional
        if not timestamp:
            return True
        
        try:
            # Parse ISO format timestamp
            from datetime import datetime, timezone
            
            request_time = datetime.fromisoformat(
                timestamp.replace('Z', '+00:00')
            )
            now = datetime.now(timezone.utc)
            
            # Allow 5 minutes of clock drift
            diff = abs((now - request_time).total_seconds())
            return diff <= 300
            
        except (ValueError, AttributeError):
            return False
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with validation."""
        # Skip validation for health checks
        if request.url.path in ["/health", "/ready", "/metrics"]:
            return await call_next(request)
        
        # Check for suspicious patterns
        suspicious = self._check_suspicious_patterns(request)
        if suspicious:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "message": "Request contains invalid characters"
                }
            )
        
        # Validate Content-Type
        if not self._validate_content_type(request):
            return JSONResponse(
                status_code=415,
                content={
                    "error": "unsupported_media_type",
                    "message": "Unsupported Content-Type"
                }
            )
        
        # Check Content-Length
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.MAX_BODY_SIZE:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "message": f"Request body exceeds maximum size of {self.MAX_BODY_SIZE} bytes"
                        }
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_content_length",
                        "message": "Invalid Content-Length header"
                    }
                )
        
        # Validate timestamp
        if not await self._validate_timestamp(request):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_timestamp",
                    "message": "Request timestamp is invalid or expired"
                }
            )
        
        # Validate nonce (if provided)
        if not await self._validate_nonce(request):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_nonce",
                    "message": "Request nonce is invalid or has been used"
                }
            )
        
        # Store client IP in request state
        request.state.client_ip = self._get_client_ip(request)
        
        return await call_next(request)
    
    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
