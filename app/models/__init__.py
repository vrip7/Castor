"""
Database models initialization.
Import all models here to ensure they are registered with SQLAlchemy.
"""

from app.models.user import User
from app.models.session import UserSession
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.mfa import MFADevice, MFABackupCode
from app.models.password_history import PasswordHistory
from app.models.login_attempt import LoginAttempt

__all__ = [
    "User",
    "UserSession",
    "APIKey",
    "AuditLog",
    "MFADevice",
    "MFABackupCode",
    "PasswordHistory",
    "LoginAttempt"
]
