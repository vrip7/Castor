"""
User session model for managing user sessions.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class UserSession(Base):
    """
    User session model for tracking active user sessions.
    
    Security considerations:
    - Sessions are bound to IP and user agent fingerprint
    - Refresh tokens use token family for rotation detection
    - Sessions have absolute expiration
    - Concurrent session limits are enforced
    """
    
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_revoked", "user_id", "revoked"),
        Index("ix_sessions_token_family", "token_family"),
        Index("ix_sessions_expires_at", "expires_at"),
        {"schema": "auth"}
    )
    
    # User reference
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Token family for refresh token rotation detection
    token_family = Column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Token family ID for detecting token reuse"
    )
    
    # Session state
    revoked = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    
    # Expiration
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Absolute session expiration"
    )
    
    # Activity tracking
    last_activity = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last activity timestamp"
    )
    
    # Security context
    ip_address = Column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="Client IP address"
    )
    user_agent = Column(
        String(500),
        nullable=True,
        comment="Client user agent string"
    )
    
    # Revocation info
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When session was revoked"
    )
    revoked_reason = Column(
        String(255),
        nullable=True,
        comment="Reason for session revocation"
    )
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid (not revoked and not expired)."""
        return not self.revoked and not self.is_expired
    
    def __repr__(self) -> str:
        return f"<UserSession(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"
