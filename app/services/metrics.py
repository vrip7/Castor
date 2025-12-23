"""
Prometheus metrics service.
Provides application metrics for monitoring.
"""

from typing import Optional

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST
)

from app.core.config import get_settings


class MetricsService:
    """
    Service for application metrics.
    
    Provides Prometheus-compatible metrics for:
    - Request counts and latencies
    - Authentication events
    - Error rates
    - Active sessions
    - Rate limiting
    """
    
    def __init__(self):
        """Initialize metrics."""
        settings = get_settings()
        
        # Application info
        self.app_info = Info(
            "castor_app",
            "Application information"
        )
        self.app_info.info({
            "version": settings.app_version,
            "environment": settings.app_env
        })
        
        # Request metrics
        self.request_total = Counter(
            "castor_requests_total",
            "Total number of requests",
            ["method", "endpoint", "status"]
        )
        
        self.request_latency = Histogram(
            "castor_request_latency_seconds",
            "Request latency in seconds",
            ["method", "endpoint"],
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        # Authentication metrics
        self.auth_attempts = Counter(
            "castor_attempts_total",
            "Total authentication attempts",
            ["type", "result"]
        )
        
        self.active_sessions = Gauge(
            "castor_active_sessions",
            "Number of active sessions"
        )
        
        self.active_users = Gauge(
            "castor_active_users",
            "Number of active users"
        )
        
        # MFA metrics
        self.mfa_verifications = Counter(
            "castor_mfa_verifications_total",
            "Total MFA verification attempts",
            ["result"]
        )
        
        # API key metrics
        self.api_key_usage = Counter(
            "castor_api_key_usage_total",
            "Total API key usage",
            ["key_id"]
        )
        
        # Rate limiting metrics
        self.rate_limit_hits = Counter(
            "castor_rate_limit_hits_total",
            "Total rate limit hits",
            ["endpoint"]
        )
        
        # Error metrics
        self.errors_total = Counter(
            "castor_errors_total",
            "Total errors",
            ["type", "endpoint"]
        )
        
        # Account lockouts
        self.account_lockouts = Counter(
            "castor_account_lockouts_total",
            "Total account lockouts"
        )
        
        # Database metrics
        self.db_connections_active = Gauge(
            "castor_db_connections_active",
            "Active database connections"
        )
        
        self.db_query_latency = Histogram(
            "castor_db_query_latency_seconds",
            "Database query latency",
            ["operation"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
    
    def record_request(
        self,
        method: str,
        endpoint: str,
        status: int,
        latency: float
    ) -> None:
        """Record request metrics."""
        self.request_total.labels(
            method=method,
            endpoint=endpoint,
            status=str(status)
        ).inc()
        
        self.request_latency.labels(
            method=method,
            endpoint=endpoint
        ).observe(latency)
    
    def record_auth_attempt(
        self,
        auth_type: str,
        success: bool
    ) -> None:
        """Record authentication attempt."""
        self.auth_attempts.labels(
            type=auth_type,
            result="success" if success else "failure"
        ).inc()
    
    def record_login_success(self) -> None:
        """Record successful login."""
        self.record_auth_attempt("login", True)
    
    def record_login_failure(self) -> None:
        """Record failed login."""
        self.record_auth_attempt("login", False)
    
    def record_mfa_verification(self, success: bool) -> None:
        """Record MFA verification attempt."""
        self.mfa_verifications.labels(
            result="success" if success else "failure"
        ).inc()
    
    def record_api_key_usage(self, key_id: str) -> None:
        """Record API key usage."""
        # Truncate key_id for cardinality control
        self.api_key_usage.labels(key_id=key_id[:12]).inc()
    
    def record_rate_limit_hit(self, endpoint: str) -> None:
        """Record rate limit hit."""
        self.rate_limit_hits.labels(endpoint=endpoint).inc()
    
    def record_error(self, error_type: str, endpoint: str) -> None:
        """Record error occurrence."""
        self.errors_total.labels(
            type=error_type,
            endpoint=endpoint
        ).inc()
    
    def record_account_lockout(self) -> None:
        """Record account lockout."""
        self.account_lockouts.inc()
    
    def set_active_sessions(self, count: int) -> None:
        """Set active session count."""
        self.active_sessions.set(count)
    
    def set_active_users(self, count: int) -> None:
        """Set active user count."""
        self.active_users.set(count)
    
    def set_db_connections(self, count: int) -> None:
        """Set active database connection count."""
        self.db_connections_active.set(count)
    
    def record_db_query(self, operation: str, latency: float) -> None:
        """Record database query latency."""
        self.db_query_latency.labels(operation=operation).observe(latency)
    
    def get_metrics(self) -> bytes:
        """Generate Prometheus metrics output."""
        return generate_latest()
    
    @staticmethod
    def get_content_type() -> str:
        """Get Prometheus content type."""
        return CONTENT_TYPE_LATEST
    
    @classmethod
    def initialize(cls) -> "MetricsService":
        """Initialize the metrics service singleton."""
        return get_metrics_service()
    
    @classmethod
    def track_login_attempt(cls, success: bool) -> None:
        """Track login attempt via class method."""
        service = get_metrics_service()
        if success:
            service.record_login_success()
        else:
            service.record_login_failure()
    
    @classmethod
    def track_mfa_verification(cls, success: bool) -> None:
        """Track MFA verification via class method."""
        service = get_metrics_service()
        service.record_mfa_verification(success)


# Singleton instance
_metrics_service: Optional[MetricsService] = None


def get_metrics_service() -> MetricsService:
    """Get metrics service singleton."""
    global _metrics_service
    if _metrics_service is None:
        _metrics_service = MetricsService()
    return _metrics_service
