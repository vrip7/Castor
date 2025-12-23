"""
Password History model for password reuse prevention.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Column, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class PasswordHistory(Base):
    """
    Password History model to prevent password reuse.
    
    Security considerations:
    - Only password hashes are stored
    - Limited history depth (configurable)
    - Old entries are automatically purged
    """
    
    __tablename__ = "password_history"
    __table_args__ = (
        Index("ix_password_history_user_created", "user_id", "created_at"),
        {"schema": "auth"}
    )
    
    # Owner
    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Password hash
    password_hash = Column(
        String(255),
        nullable=False,
        comment="Argon2id hash of previous password"
    )
    
    # Relationships
    user = relationship("User", back_populates="password_history")
    
    def __repr__(self) -> str:
        return f"<PasswordHistory(id={self.id}, user_id={self.user_id})>"
