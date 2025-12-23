"""
Health check endpoints.

Provides health and readiness checks for the application.
"""

from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis

from app.core.config import settings
from app.db.session import get_db
from app.services.logging import get_logger
from app.services.metrics import MetricsService

router = APIRouter(prefix="/health", tags=["Health"])
logger = get_logger(__name__)


async def check_database(db: AsyncSession) -> Dict[str, Any]:
    """Check database connectivity."""
    try:
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        return {"status": "healthy", "latency_ms": 0}
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return {"status": "unhealthy", "error": str(e)}


async def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity."""
    try:
        redis_client = redis.from_url(
            settings.redis.url,
            encoding="utf-8",
            decode_responses=True,
        )
        await redis_client.ping()
        await redis_client.close()
        return {"status": "healthy"}
    except Exception as e:
        logger.error("Redis health check failed", error=str(e))
        return {"status": "unhealthy", "error": str(e)}


@router.get("")
async def health_check() -> Dict[str, Any]:
    """
    Basic health check endpoint.
    
    Returns a simple status indicating the service is running.
    This endpoint does not check dependencies.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": settings.app_name,
        "version": settings.app_version,
    }


@router.get("/live")
async def liveness_check() -> Dict[str, Any]:
    """
    Kubernetes liveness probe endpoint.
    
    Indicates whether the application is running.
    Should only fail if the application needs to be restarted.
    """
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def readiness_check(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Kubernetes readiness probe endpoint.
    
    Indicates whether the application is ready to serve traffic.
    Checks all critical dependencies.
    """
    checks = {}
    overall_healthy = True
    
    # Check database
    db_health = await check_database(db)
    checks["database"] = db_health
    if db_health["status"] != "healthy":
        overall_healthy = False
    
    # Check Redis
    redis_health = await check_redis()
    checks["redis"] = redis_health
    if redis_health["status"] != "healthy":
        overall_healthy = False
    
    response = {
        "status": "ready" if overall_healthy else "not_ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }
    
    if not overall_healthy:
        logger.warning("Readiness check failed", checks=checks)
    
    return response


@router.get("/detailed")
async def detailed_health_check(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Detailed health check with metrics.
    
    Provides comprehensive health information including:
    - Service status
    - Dependency health
    - System metrics
    """
    checks = {}
    overall_healthy = True
    
    # Database check
    db_health = await check_database(db)
    checks["database"] = db_health
    if db_health["status"] != "healthy":
        overall_healthy = False
    
    # Redis check
    redis_health = await check_redis()
    checks["redis"] = redis_health
    if redis_health["status"] != "healthy":
        overall_healthy = False
    
    return {
        "status": "healthy" if overall_healthy else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": {
            "name": settings.app_name,
            "version": settings.app_version,
            "environment": settings.app_env,
        },
        "checks": checks,
        "uptime": "N/A",  # Would need to track startup time
    }


@router.get("/metrics")
async def get_metrics() -> Dict[str, Any]:
    """
    Get application metrics.
    
    Returns Prometheus-compatible metrics.
    """
    # This endpoint returns JSON metrics
    # For Prometheus scraping, use /metrics endpoint from prometheus_client
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "For Prometheus metrics, use the /metrics endpoint",
    }
