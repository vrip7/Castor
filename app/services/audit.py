"""
Audit service for tracking security-relevant events.
Provides comprehensive audit logging for compliance.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import AuditAction, SecurityEventSeverity
from app.middleware.request_id import get_correlation_id, get_request_id
from app.models.audit_log import AuditLog
from app.services.logging import get_logger

logger = get_logger(__name__)


class AuditService:
    """
    Service for creating and querying audit logs.
    
    Features:
    - Comprehensive event tracking
    - Sensitive data sanitization
    - Request context inclusion
    - Efficient querying with indexes
    """
    
    # Fields to never include in audit logs
    FORBIDDEN_FIELDS = {
        "password",
        "password_hash",
        "token",
        "secret",
        "api_key",
        "encryption_key",
        "private_key"
    }
    
    @staticmethod
    def _sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize context dictionary by removing sensitive data.
        
        Args:
            context: Raw context dictionary
        
        Returns:
            Sanitized context
        """
        if not context:
            return {}
        
        def sanitize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
            result = {}
            for key, value in d.items():
                key_lower = key.lower()
                
                # Skip forbidden fields
                if any(forbidden in key_lower for forbidden in AuditService.FORBIDDEN_FIELDS):
                    continue
                
                if isinstance(value, dict):
                    result[key] = sanitize_dict(value)
                elif isinstance(value, list):
                    result[key] = [
                        sanitize_dict(item) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    # Convert non-serializable types
                    if isinstance(value, (UUID, datetime)):
                        result[key] = str(value)
                    else:
                        result[key] = value
            
            return result
        
        return sanitize_dict(context)
    
    @staticmethod
    async def log(
        db: AsyncSession,
        action: AuditAction,
        user_id: Optional[str] = None,
        description: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        severity: SecurityEventSeverity = SecurityEventSeverity.LOW,
        details: Optional[Dict[str, Any]] = None,
        geo_country: Optional[str] = None,
        geo_city: Optional[str] = None
    ) -> AuditLog:
        """
        Create an audit log entry.
        
        Args:
            db: Database session
            action: Type of action being logged
            user_id: ID of user performing action (if applicable)
            description: Human-readable description (auto-generated if not provided)
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            ip_address: Client IP address
            user_agent: Client user agent
            success: Whether the action was successful
            error_message: Error message if action failed
            severity: Event severity level
            details: Additional context (will be sanitized)
            geo_country: Country code
            geo_city: City name
        
        Returns:
            Created audit log entry
        """
        # Get request context
        request_id = get_request_id()
        correlation_id = get_correlation_id()
        
        # Auto-generate description if not provided
        if not description:
            description = f"{action.value.replace('_', ' ').title()}"
        
        # Sanitize context
        sanitized_context = AuditService._sanitize_context(details or {})
        
        # Create audit log entry
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            severity=severity,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            correlation_id=correlation_id,
            context=sanitized_context,
            success=success,
            error_message=error_message,
            geo_country=geo_country,
            geo_city=geo_city
        )
        
        db.add(audit_log)
        await db.flush()
        
        # Also log to structured logger for real-time monitoring
        log_method = logger.info if success else logger.warning
        log_method(
            description,
            audit_action=action.value,
            user_id=str(user_id) if user_id else None,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            severity=severity.value,
            success=success
        )
        
        return audit_log
    
    @staticmethod
    def _hash_email(email: str) -> str:
        """Hash email for audit logging."""
        import hashlib
        return hashlib.sha256(email.lower().encode()).hexdigest()[:16]


# Factory function for dependency injection
async def get_audit_service(db: AsyncSession) -> AuditService:
    """Get audit service instance."""
    return AuditService(db)
