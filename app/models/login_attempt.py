"""
Login Attempt model for tracking authentication attempts.
"""

from datetime import datetime, timezone as tz
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class LoginAttempt(Base):
    """
    Login Attempt model for tracking all login attempts.
    
    Security considerations:
    - Tracks both successful and failed attempts
    - Used for account lockout policies
    - Used for anomaly detection
    - Enables security alerting
    """
    
    __tablename__ = "login_attempts"
    __table_args__ = (
        Index("ix_login_attempts_user_created", "user_id", "created_at"),
        Index("ix_login_attempts_ip_created", "ip_address", "created_at"),
        Index("ix_login_attempts_success", "success"),
        {"schema": "auth"}
    )
    
    # User (may be null for non-existent users)
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Attempted email (for tracking attempts on non-existent accounts)
    email_hash = Column(
        String(64),
        nullable=False,
        index=True,
        comment="SHA-256 hash of attempted email"
    )
    
    # Result
    success = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    failure_reason = Column(
        String(100),
        nullable=True,
        comment="Reason for login failure"
    )
    
    # Request context
    ip_address = Column(
        String(45),  # IPv6 max length  
        nullable=False,
        index=True
    )
    user_agent = Column(
        String(500),
        nullable=True
    )
    
    # Geolocation
    geo_country = Column(
        String(2),
        nullable=True
    )
    geo_city = Column(
        String(255),
        nullable=True
    )
    
    # MFA status
    mfa_used = Column(
        Boolean,
        default=False,
        nullable=False
    )
    
    # Relationships
    user = relationship("User", back_populates="login_attempts")
    
    def __repr__(self) -> str:
        return f"<LoginAttempt(id={self.id}, user_id={self.user_id}, success={self.success})>"
