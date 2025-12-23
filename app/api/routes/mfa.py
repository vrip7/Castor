"""
Multi-Factor Authentication (MFA) endpoints.

Handles MFA setup, verification, and management.
"""

from datetime import datetime, timezone
from uuid import uuid4
import io
import base64

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import AuditAction
from app.core.exceptions import (
    ValidationError,
    AuthenticationError,
)
from app.db.session import get_db
from app.models.user import User
from app.models.mfa import MFABackupCode
from app.models.session import UserSession
from app.schemas.auth import MessageResponse
from app.security.mfa import MFAService
from app.security.password import PasswordService
from app.services.audit import AuditService
from app.services.logging import get_logger
from app.api.dependencies import get_current_user, CurrentUser

router = APIRouter(prefix="/mfa", tags=["Multi-Factor Authentication"])
logger = get_logger(__name__)


@router.post("/setup/initiate")
async def initiate_mfa_setup(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Initiate MFA setup by generating a TOTP secret.
    
    Returns:
    - secret: Base32 encoded secret (for manual entry)
    - qr_code: Base64 encoded QR code image
    - provisioning_uri: URI for authenticator apps
    """
    user = current_user.user
    
    if user.mfa_enabled:
        raise ValidationError("MFA is already enabled for this account.")
    
    # Generate TOTP secret
    secret = MFAService.generate_totp_secret()
    
    # Generate provisioning URI
    provisioning_uri = MFAService.get_provisioning_uri(
        secret=secret,
        email=user.email,
        issuer=settings.app_name,
    )
    
    # Generate QR code
    qr_code_base64 = MFAService.generate_qr_code(provisioning_uri)
    
    # Store secret temporarily (user must verify before it's activated)
    user.mfa_secret = secret
    user.mfa_enabled = False  # Not enabled until verified
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.MFA_SETUP_INITIATED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("MFA setup initiated", user_id=user.id)
    
    return {
        "secret": secret,
        "qr_code": qr_code_base64,
        "provisioning_uri": provisioning_uri,
        "message": "Scan the QR code with your authenticator app, then verify with a code.",
    }


@router.post("/setup/verify")
async def verify_mfa_setup(
    request: Request,
    code: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Verify MFA setup by providing a valid TOTP code.
    
    This completes the MFA setup and generates backup codes.
    """
    user = current_user.user
    
    if user.mfa_enabled:
        raise ValidationError("MFA is already enabled.")
    
    if not user.mfa_secret:
        raise ValidationError("MFA setup has not been initiated. Please start the setup process first.")
    
    # Verify the code
    if not MFAService.verify_totp(user.mfa_secret, code):
        await AuditService.log(
            db=db,
            action=AuditAction.MFA_SETUP_FAILED,
            user_id=user.id,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details={"reason": "invalid_verification_code"},
            success=False,
        )
        raise ValidationError("Invalid verification code. Please try again.")
    
    # Generate backup codes
    backup_codes = MFAService.generate_backup_codes()
    
    # Store backup codes (hashed)
    for code_value in backup_codes:
        backup_code = MFABackupCode(
            id=str(uuid4()),
            user_id=user.id,
            code_hash=PasswordService.hash_password(code_value),
        )
        db.add(backup_code)
    
    # Enable MFA
    user.mfa_enabled = True
    user.mfa_enabled_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.MFA_ENABLED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("MFA enabled successfully", user_id=user.id)
    
    return {
        "message": "MFA has been enabled successfully.",
        "backup_codes": backup_codes,
        "warning": "Store these backup codes securely. They will not be shown again.",
    }


@router.post("/disable")
async def disable_mfa(
    request: Request,
    password: str,
    code: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Disable MFA for the account.
    
    Requires both password and a valid MFA code for security.
    """
    user = current_user.user
    
    if not user.mfa_enabled:
        raise ValidationError("MFA is not enabled for this account.")
    
    # Verify password
    if not PasswordService.verify_password(password, user.password_hash):
        await AuditService.log(
            db=db,
            action=AuditAction.MFA_DISABLED,
            user_id=user.id,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details={"reason": "invalid_password"},
            success=False,
        )
        raise AuthenticationError("Invalid password.")
    
    # Verify MFA code
    if not MFAService.verify_totp(user.mfa_secret, code):
        await AuditService.log(
            db=db,
            action=AuditAction.MFA_DISABLED,
            user_id=user.id,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details={"reason": "invalid_mfa_code"},
            success=False,
        )
        raise ValidationError("Invalid MFA code.")
    
    # Disable MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_enabled_at = None
    
    # Delete all backup codes
    await db.execute(
        update(MFABackupCode)
        .where(MFABackupCode.user_id == user.id)
        .values(used=True, used_at=datetime.now(timezone.utc))
    )
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.MFA_DISABLED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("MFA disabled", user_id=user.id)
    
    return MessageResponse(message="MFA has been disabled successfully.")


@router.post("/verify")
async def verify_mfa_code(
    request: Request,
    code: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Verify a MFA code (for additional security checks).
    """
    user = current_user.user
    
    if not user.mfa_enabled:
        raise ValidationError("MFA is not enabled for this account.")
    
    if not MFAService.verify_totp(user.mfa_secret, code):
        raise ValidationError("Invalid MFA code.")
    
    return MessageResponse(message="MFA code verified successfully.")


@router.post("/backup-codes/verify")
async def verify_backup_code(
    request: Request,
    code: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Verify and consume a backup code.
    
    Each backup code can only be used once.
    """
    user = current_user.user
    
    if not user.mfa_enabled:
        raise ValidationError("MFA is not enabled for this account.")
    
    # Get unused backup codes
    result = await db.execute(
        select(MFABackupCode).where(
            MFABackupCode.user_id == user.id,
            MFABackupCode.used == False,
        )
    )
    backup_codes = result.scalars().all()
    
    # Check each backup code (constant-time comparison)
    matched_code = None
    for backup_code in backup_codes:
        if PasswordService.verify_password(code, backup_code.code_hash):
            matched_code = backup_code
            break
    
    if not matched_code:
        await AuditService.log(
            db=db,
            action=AuditAction.MFA_BACKUP_CODE_USED,
            user_id=user.id,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details={"reason": "invalid_backup_code"},
            success=False,
        )
        raise ValidationError("Invalid backup code.")
    
    # Mark code as used
    matched_code.used = True
    matched_code.used_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    # Count remaining codes
    remaining_result = await db.execute(
        select(MFABackupCode).where(
            MFABackupCode.user_id == user.id,
            MFABackupCode.used == False,
        )
    )
    remaining_codes = len(remaining_result.scalars().all())
    
    await AuditService.log(
        db=db,
        action=AuditAction.MFA_BACKUP_CODE_USED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"remaining_codes": remaining_codes},
    )
    
    logger.info(
        "Backup code used",
        user_id=user.id,
        remaining_codes=remaining_codes,
    )
    
    warning = ""
    if remaining_codes <= 2:
        warning = f" Warning: Only {remaining_codes} backup code(s) remaining. Consider regenerating."
    
    return MessageResponse(
        message=f"Backup code verified successfully.{warning}"
    )


@router.post("/backup-codes/regenerate")
async def regenerate_backup_codes(
    request: Request,
    password: str,
    code: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Regenerate all backup codes.
    
    Invalidates all existing backup codes and generates new ones.
    Requires password and MFA code for security.
    """
    user = current_user.user
    
    if not user.mfa_enabled:
        raise ValidationError("MFA is not enabled for this account.")
    
    # Verify password
    if not PasswordService.verify_password(password, user.password_hash):
        raise AuthenticationError("Invalid password.")
    
    # Verify MFA code
    if not MFAService.verify_totp(user.mfa_secret, code):
        raise ValidationError("Invalid MFA code.")
    
    # Invalidate all existing backup codes
    await db.execute(
        update(MFABackupCode)
        .where(MFABackupCode.user_id == user.id)
        .values(used=True, used_at=datetime.now(timezone.utc))
    )
    
    # Generate new backup codes
    new_backup_codes = MFAService.generate_backup_codes()
    
    # Store new backup codes
    for code_value in new_backup_codes:
        backup_code = MFABackupCode(
            id=str(uuid4()),
            user_id=user.id,
            code_hash=PasswordService.hash_password(code_value),
        )
        db.add(backup_code)
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.MFA_BACKUP_CODES_REGENERATED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("Backup codes regenerated", user_id=user.id)
    
    return {
        "message": "Backup codes have been regenerated.",
        "backup_codes": new_backup_codes,
        "warning": "Store these backup codes securely. They will not be shown again. All previous backup codes have been invalidated.",
    }


@router.get("/backup-codes/count")
async def get_backup_codes_count(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Get the count of remaining unused backup codes.
    """
    user = current_user.user
    
    if not user.mfa_enabled:
        return {"count": 0, "mfa_enabled": False}
    
    result = await db.execute(
        select(MFABackupCode).where(
            MFABackupCode.user_id == user.id,
            MFABackupCode.used == False,
        )
    )
    count = len(result.scalars().all())
    
    return {
        "count": count,
        "mfa_enabled": True,
        "warning": "Low backup code count. Consider regenerating." if count <= 2 else None,
    }


@router.get("/status")
async def get_mfa_status(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Get MFA status for the current user.
    """
    user = current_user.user
    
    # Get backup code count
    backup_count = 0
    if user.mfa_enabled:
        result = await db.execute(
            select(MFABackupCode).where(
                MFABackupCode.user_id == user.id,
                MFABackupCode.used == False,
            )
        )
        backup_count = len(result.scalars().all())
    
    return {
        "mfa_enabled": user.mfa_enabled,
        "mfa_type": "totp" if user.mfa_enabled else None,
        "enabled_at": user.mfa_enabled_at.isoformat() if user.mfa_enabled_at else None,
        "backup_codes_remaining": backup_count,
    }
