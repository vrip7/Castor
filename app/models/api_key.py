"""
API Key model for service-to-service authentication.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PG_UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class APIKey(Base):
    """
    API Key model for authenticating external services and integrations.
    
    Security considerations:
    - Keys are hashed before storage (only prefix is stored in plain)
    - Keys have configurable expiration
    - Scopes limit access to specific resources
    - Usage is tracked and rate limited
    - Keys can be rotated without downtime
    """
    
    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_prefix", "key_prefix"),
        Index("ix_api_keys_hash", "key_hash"),
        Index("ix_api_keys_user_active", "user_id", "is_active"),
        {"schema": "auth"}
    )
    
    # Owner
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Key identification
    name = Column(
        String(255),
        nullable=False,
        comment="Human-readable key name"
    )
    description = Column(
        Text,
        nullable=True,
        comment="Key description/purpose"
    )
    
    # Key storage (never store full key)
    key_prefix = Column(
        String(12),
        nullable=False,
        index=True,
        comment="First 12 chars for identification (cstr_xxxxxxx)"
    )
    key_hash = Column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
        comment="SHA-512 hash of full key"
    )
    
    # Status
    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        index=True
    )
    
    # Expiration
    expires_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Optional expiration date"
    )
    
    # Access control
    scopes = Column(
        ARRAY(String),
        default=[],
        nullable=False,
        comment="List of allowed scopes/permissions"
    )
    allowed_ips = Column(
        ARRAY(String),
        default=[],
        nullable=False,
        comment="List of allowed IP addresses/CIDR blocks"
    )
    allowed_origins = Column(
        ARRAY(String),
        default=[],
        nullable=False,
        comment="List of allowed origin domains"
    )
    
    # Rate limiting
    rate_limit_per_minute = Column(
        Integer,
        default=60,
        nullable=False,
        comment="Custom rate limit for this key"
    )
    rate_limit_per_hour = Column(
        Integer,
        default=1000,
        nullable=False
    )
    
    # Usage tracking
    last_used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time key was used"
    )
    last_used_ip = Column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="IP address of last use"
    )
    usage_count = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Total number of uses"
    )
    
    # Rotation support
    previous_key_hash = Column(
        String(128),
        nullable=True,
        comment="Hash of previous key during rotation grace period"
    )
    rotation_deadline = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Deadline to complete key rotation"
    )
    
    # Revocation info
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    revoked_reason = Column(
        String(255),
        nullable=True
    )
    revoked_by = Column(
        PG_UUID(as_uuid=True),
        nullable=True,
        comment="User ID who revoked the key"
    )
    
    # Extra data
    extra_data = Column(
        JSONB,
        default={},
        nullable=False,
        comment="Additional key metadata"
    )
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    @property
    def is_expired(self) -> bool:
        """Check if API key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if API key is valid."""
        return self.is_active and not self.is_expired and self.revoked_at is None
    
    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name={self.name}, prefix={self.key_prefix})>"
