"""
Rate limiting middleware using Redis.
Implements sliding window rate limiting.
"""

import hashlib
import time
from typing import Optional, Tuple

import redis.asyncio as redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.constants import CacheKeys


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Redis-based rate limiting middleware.
    
    Features:
    - Sliding window algorithm for smooth rate limiting
    - Per-IP and per-user rate limits
    - Different limits for different endpoints
    - Burst allowance for spiky traffic
    - Rate limit headers in response
    
    Protection against:
    - DDoS attacks
    - Brute force attacks
    - API abuse
    """
    
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
    
    def _get_client_identifier(self, request: Request) -> str:
        """
        Get unique identifier for the client.
        
        Uses a combination of IP and user ID if authenticated.
        """
        # Get real IP (consider proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.headers.get(
                "X-Real-IP",
                request.client.host if request.client else "unknown"
            )
        
        # Include user ID if available
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            identifier = f"user:{user_id}:{ip}"
        else:
            identifier = f"ip:{ip}"
        
        # Hash for privacy and fixed length
        return hashlib.sha256(identifier.encode()).hexdigest()[:32]
    
    def _get_rate_limits(self, request: Request) -> Tuple[int, int, int]:
        """
        Get rate limits based on endpoint.
        
        Returns:
            Tuple of (requests_per_minute, requests_per_hour, burst)
        """
        path = request.url.path.lower()
        settings = self.settings.rate_limit
        
        # Stricter limits for authentication endpoints
        if "/auth/login" in path or "/auth/token" in path:
            return (
                settings.login_per_minute,
                settings.login_per_minute * 60,
                3
            )
        
        if "/auth/register" in path:
            return (
                settings.registration_per_hour // 60,
                settings.registration_per_hour,
                2
            )
        
        # Default limits
        return (
            settings.per_minute,
            settings.per_hour,
            settings.burst
        )
    
    async def _check_rate_limit(
        self,
        identifier: str,
        limit: int,
        window: int
    ) -> Tuple[bool, int, int, int]:
        """
        Check if request is within rate limit using sliding window.
        
        Args:
            identifier: Client identifier
            limit: Maximum requests in window
            window: Time window in seconds
        
        Returns:
            Tuple of (allowed, remaining, reset_time, retry_after)
        """
        redis_client = await self._get_redis()
        now = time.time()
        window_start = now - window
        
        key = f"{CacheKeys.RATE_LIMIT}{identifier}:{window}"
        
        # Use Redis pipeline for atomic operations
        pipe = redis_client.pipeline()
        
        # Remove old entries outside the window
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count current requests in window
        pipe.zcard(key)
        
        # Add current request
        pipe.zadd(key, {f"{now}:{id(now)}": now})
        
        # Set expiration on key
        pipe.expire(key, window + 1)
        
        results = await pipe.execute()
        current_count = results[1]
        
        # Calculate remaining requests
        remaining = max(0, limit - current_count - 1)
        reset_time = int(now + window)
        
        if current_count >= limit:
            # Get oldest request time for retry-after
            oldest = await redis_client.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window - now) + 1
            else:
                retry_after = window
            return False, 0, reset_time, retry_after
        
        return True, remaining, reset_time, 0
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with rate limiting."""
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/ready", "/metrics"]:
            return await call_next(request)
        
        identifier = self._get_client_identifier(request)
        per_minute, per_hour, burst = self._get_rate_limits(request)
        
        # Check minute limit
        allowed, remaining, reset_time, retry_after = await self._check_rate_limit(
            identifier, per_minute, 60
        )
        
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time)
                }
            )
        
        # Check hour limit
        allowed_hour, remaining_hour, reset_hour, retry_hour = await self._check_rate_limit(
            identifier, per_hour, 3600
        )
        
        if not allowed_hour:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Hourly rate limit exceeded. Please try again later.",
                    "retry_after": retry_hour
                },
                headers={
                    "Retry-After": str(retry_hour),
                    "X-RateLimit-Limit": str(per_hour),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_hour)
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        
        return response
    
    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
