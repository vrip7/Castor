"""
MFA Device and Backup Code models for multi-factor authentication.
"""

from datetime import datetime, timezone as tz
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class MFADevice(Base):
    """
    MFA Device model for storing TOTP authenticator information.
    
    Security considerations:
    - TOTP secrets are encrypted at rest
    - Backup codes are hashed
    - Device verification is required
    - Rate limiting on verification attempts
    """
    
    __tablename__ = "mfa_devices"
    __table_args__ = (
        Index("ix_mfa_devices_user_active", "user_id", "is_active"),
        {"schema": "auth"}
    )
    
    # Owner
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Device info
    name = Column(
        String(255),
        nullable=False,
        default="Authenticator",
        comment="Human-readable device name"
    )
    device_type = Column(
        String(50),
        nullable=False,
        default="totp",
        comment="Type of MFA (totp, webauthn, etc.)"
    )
    
    # TOTP secret (encrypted)
    secret_encrypted = Column(
        LargeBinary,
        nullable=False,
        comment="AES-256-GCM encrypted TOTP secret"
    )
    
    # Status
    is_active = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether device is active (verified)"
    )
    is_primary = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether this is the primary MFA device"
    )
    
    # Verification
    verified_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When device was verified"
    )
    last_used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful use"
    )
    
    # Backup codes (hashed)
    backup_codes_hash = Column(
        LargeBinary,
        nullable=True,
        comment="Encrypted array of hashed backup codes"
    )
    backup_codes_remaining = Column(
        String(2),  # String to prevent timing attacks
        default="10",
        nullable=False,
        comment="Number of backup codes remaining"
    )
    
    # Failed attempts tracking
    failed_attempts = Column(
        String(3),
        default="0",
        nullable=False,
        comment="Consecutive failed verification attempts"
    )
    locked_until = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Device locked until this time"
    )
    
    # Relationships
    user = relationship("User", back_populates="mfa_devices")
    
    @property
    def is_locked(self) -> bool:
        """Check if device is locked due to failed attempts."""
        if self.locked_until is None:
            return False
        return datetime.now(tz.utc) < self.locked_until
    
    def __repr__(self) -> str:
        return f"<MFADevice(id={self.id}, user_id={self.user_id}, type={self.device_type})>"


class MFABackupCode(Base):
    """
    MFA Backup Code model for storing one-time backup codes.
    
    Security considerations:
    - Codes are hashed using Argon2id
    - Each code can only be used once
    - Codes are associated with a specific user
    """
    
    __tablename__ = "mfa_backup_codes"
    __table_args__ = (
        Index("ix_mfa_backup_codes_user_used", "user_id", "used"),
        {"schema": "auth"}
    )
    
    # Owner
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Hashed code
    code_hash = Column(
        String(255),
        nullable=False,
        comment="Argon2id hash of backup code"
    )
    
    # Usage status
    used = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When code was used"
    )
    
    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(tz.utc),
        nullable=False
    )
    
    # Relationships
    user = relationship("User", back_populates="mfa_backup_codes")
    
    def __repr__(self) -> str:
        return f"<MFABackupCode(id={self.id}, user_id={self.user_id}, used={self.used})>"
