"""
User model for authentication.
"""

from datetime import datetime, timezone as tz

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Index,
    Integer,
    LargeBinary,
    String,
    text
)
from sqlalchemy.orm import relationship

from app.core.constants import UserRole, UserStatus
from app.db.base import Base


class User(Base):
    """
    User model representing authenticated users in the system.
    
    Security considerations:
    - Passwords are hashed using Argon2id
    - Sensitive fields are encrypted at rest
    - Email is normalized and indexed for lookups
    - Failed login attempts are tracked for account lockout
    """
    
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email_lower", text("LOWER(email)")),
        Index("ix_users_username_lower", text("LOWER(username)")),
        Index("ix_users_status_active", "status"),
        {"schema": "auth"}
    )
    
    # Core fields
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User email address (normalized to lowercase)"
    )
    username = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Username (normalized to lowercase)"
    )
    email_verified = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether email has been verified"
    )
    email_verified_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When email was verified"
    )
    email_verification_token = Column(
        String(64),
        nullable=True,
        comment="Email verification token"
    )
    email_verification_sent_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When verification email was sent"
    )
    
    # Password (hashed)
    password_hash = Column(
        String(255),
        nullable=False,
        comment="Argon2id hashed password"
    )
    password_changed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last password change timestamp"
    )
    password_reset_token = Column(
        String(255),
        nullable=True,
        comment="Hashed password reset token"
    )
    password_reset_sent_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When password reset email was sent"
    )
    
    # Profile fields (encrypted at application level)
    first_name_encrypted = Column(
        LargeBinary,
        nullable=True,
        comment="AES-256-GCM encrypted first name"
    )
    last_name_encrypted = Column(
        LargeBinary,
        nullable=True,
        comment="AES-256-GCM encrypted last name"
    )
    phone_encrypted = Column(
        LargeBinary,
        nullable=True,
        comment="AES-256-GCM encrypted phone number"
    )
    
    # Status and role
    status = Column(
        Enum(UserStatus, name="userstatus", schema="auth", create_type=False),
        default=UserStatus.PENDING_VERIFICATION,
        nullable=False,
        index=True,
        comment="Account status"
    )
    role = Column(
        Enum(UserRole, name="userrole", schema="auth", create_type=False),
        default=UserRole.USER,
        nullable=False,
        index=True,
        comment="User role for RBAC"
    )
    
    # MFA
    mfa_enabled = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether MFA is enabled"
    )
    mfa_secret = Column(
        String(64),
        nullable=True,
        comment="TOTP secret (base32 encoded)"
    )
    mfa_enabled_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="When MFA was enabled"
    )
    
    # Account security
    failed_login_attempts = Column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of consecutive failed login attempts"
    )
    locked_until = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Account lockout expiration"
    )
    last_failed_login = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last failed login timestamp"
    )
    last_login = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful login timestamp"
    )
    last_login_ip = Column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="IP address of last login"
    )
    
    # Relationships
    sessions = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    api_keys = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    mfa_devices = relationship(
        "MFADevice",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    mfa_backup_codes = relationship(
        "MFABackupCode",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    password_history = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    login_attempts = relationship(
        "LoginAttempt",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    @property
    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.status == UserStatus.ACTIVE
    
    @property
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.locked_until is None:
            return False
        return datetime.now(tz.utc) < self.locked_until
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, status={self.status})>"
