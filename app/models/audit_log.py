"""
Audit Log model for security and compliance.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Index,
    String,
    Text
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID

from app.core.constants import AuditAction, SecurityEventSeverity
from app.db.base import Base


class AuditLog(Base):
    """
    Audit log model for tracking all security-relevant events.
    
    Security considerations:
    - Logs are immutable (no updates or deletes)
    - All sensitive data is sanitized before logging
    - Logs include request context for forensics
    - Retention policies are enforced
    """
    
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_severity", "severity"),
        Index("ix_audit_logs_resource_type", "resource_type"),
        Index("ix_audit_logs_correlation_id", "correlation_id"),
        {"schema": "auth"}
    )
    
    # Actor (who performed the action)
    user_id = Column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="User who performed the action (null for system events)"
    )
    
    # Action details
    action = Column(
        Enum(AuditAction, schema="auth"),
        nullable=False,
        index=True,
        comment="Type of action performed"
    )
    severity = Column(
        Enum(SecurityEventSeverity, schema="auth"),
        default=SecurityEventSeverity.LOW,
        nullable=False,
        index=True,
        comment="Severity level of the event"
    )
    
    # Resource affected
    resource_type = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Type of resource affected (user, session, api_key, etc.)"
    )
    resource_id = Column(
        String(255),
        nullable=True,
        comment="ID of the resource affected"
    )
    
    # Event description
    description = Column(
        Text,
        nullable=False,
        comment="Human-readable description of the event"
    )
    
    # Request context
    ip_address = Column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="Client IP address"
    )
    user_agent = Column(
        Text,
        nullable=True,
        comment="Client user agent"
    )
    request_id = Column(
        String(64),
        nullable=True,
        index=True,
        comment="Request ID for correlation"
    )
    correlation_id = Column(
        String(64),
        nullable=True,
        index=True,
        comment="Correlation ID for distributed tracing"
    )
    
    # Additional context (sanitized)
    context = Column(
        JSONB,
        default={},
        nullable=False,
        comment="Additional context (sanitized of sensitive data)"
    )
    
    # Result
    success = Column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether the action was successful"
    )
    error_message = Column(
        Text,
        nullable=True,
        comment="Error message if action failed"
    )
    
    # Geolocation (optional)
    geo_country = Column(
        String(2),
        nullable=True,
        comment="ISO 3166-1 alpha-2 country code"
    )
    geo_city = Column(
        String(255),
        nullable=True
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id})>"
