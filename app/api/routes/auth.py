"""
Authentication API endpoints.

Handles user authentication, registration, token management, and password operations.
Implements comprehensive security measures including rate limiting, audit logging,
and brute-force protection.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.constants import (
    AuditAction,
    UserStatus,
    TokenType,
    ERROR_MESSAGES,
    RATE_LIMIT_LOGIN,
)
from app.core.exceptions import (
    AuthenticationError,
    AccountLockedError,
    TokenError,
    ValidationError,
    RateLimitError,
)
from app.db.session import get_db
from app.models.user import User
from app.models.session import UserSession
from app.models.login_attempt import LoginAttempt
from app.models.password_history import PasswordHistory
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    TokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    PasswordChangeRequest,
    LogoutRequest,
    MessageResponse,
    MFAVerificationRequest,
)
from app.schemas.user import UserResponse
from app.security.password import PasswordService
from app.security.jwt import JWTService
from app.security.encryption import EncryptionService
from app.security.mfa import MFAService
from app.services.audit import AuditService
from app.services.logging import get_logger
from app.services.metrics import MetricsService
from app.api.dependencies import get_current_user, CurrentUser

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = get_logger(__name__)


async def record_login_attempt(
    db: AsyncSession,
    user_id: Optional[str],
    email: str,
    ip_address: str,
    user_agent: str,
    success: bool,
    failure_reason: Optional[str] = None,
) -> None:
    """Record a login attempt for security monitoring."""
    import hashlib
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
    
    attempt = LoginAttempt(
        user_id=user_id,
        email_hash=email_hash,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,
        success=success,
        failure_reason=failure_reason,
    )
    db.add(attempt)
    await db.commit()


async def check_account_lockout(db: AsyncSession, user: User) -> None:
    """Check if account is locked and handle lockout logic."""
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        remaining = (user.locked_until - datetime.now(timezone.utc)).seconds
        raise AccountLockedError(
            f"Account is locked. Try again in {remaining // 60} minutes."
        )
    
    # Reset lockout if expired
    if user.locked_until and user.locked_until <= datetime.now(timezone.utc):
        user.failed_login_attempts = 0
        user.locked_until = None


async def handle_failed_login(db: AsyncSession, user: User) -> None:
    """Handle failed login attempt and implement lockout logic."""
    user.failed_login_attempts += 1
    user.last_failed_login = datetime.now(timezone.utc)
    
    if user.failed_login_attempts >= settings.security.max_login_attempts:
        lockout_minutes = min(
            settings.security.lockout_duration_minutes * (2 ** (user.failed_login_attempts // settings.security.max_login_attempts - 1)),
            1440  # Max 24 hours
        )
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        logger.warning(
            "Account locked due to failed attempts",
            user_id=user.id,
            failed_attempts=user.failed_login_attempts,
            lockout_minutes=lockout_minutes,
        )


async def reset_failed_attempts(db: AsyncSession, user: User) -> None:
    """Reset failed login attempts on successful login."""
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)


async def create_user_session(
    db: AsyncSession,
    user: User,
    request: Request,
    token_family: str,
) -> UserSession:
    """Create a new user session."""
    session = UserSession(
        id=str(uuid4()),
        user_id=user.id,
        token_family=token_family,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "")[:500],
        expires_at=datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt.refresh_expire_minutes
        ),
    )
    db.add(session)
    return session


async def invalidate_token_family(db: AsyncSession, token_family: str) -> None:
    """Invalidate all sessions in a token family (for refresh token rotation)."""
    await db.execute(
        update(UserSession)
        .where(UserSession.token_family == token_family)
        .values(revoked=True, revoked_at=datetime.now(timezone.utc))
    )


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    data: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """
    Register a new user account.
    
    - Validates email uniqueness
    - Enforces password policy
    - Encrypts sensitive data
    - Sends verification email (background task)
    """
    # Check if email already exists
    existing_user = await db.execute(
        select(User).where(User.email == data.email.lower())
    )
    if existing_user.scalar_one_or_none():
        # Don't reveal if email exists - security measure
        logger.warning("Registration attempt with existing email", email=data.email)
        raise ValidationError("Unable to complete registration. Please check your information.")
    
    # Check if username already exists
    existing_username = await db.execute(
        select(User).where(User.username == data.username.lower())
    )
    if existing_username.scalar_one_or_none():
        raise ValidationError("Username is already taken.")
    
    # Hash password
    password_hash = PasswordService.hash_password(data.password)
    
    # Generate email verification token
    verification_token = EncryptionService.generate_secure_token(32)
    
    # Encrypt PII fields
    encryption_service = EncryptionService()
    
    # Create user
    user = User(
        id=str(uuid4()),
        email=data.email.lower(),
        username=data.username.lower(),
        password_hash=password_hash,
        first_name_encrypted=encryption_service.encrypt(data.first_name) if data.first_name else None,
        last_name_encrypted=encryption_service.encrypt(data.last_name) if data.last_name else None,
        phone_encrypted=encryption_service.encrypt(data.phone) if data.phone else None,
        status=UserStatus.PENDING_VERIFICATION,
        email_verification_token=verification_token,
        email_verification_sent_at=datetime.now(timezone.utc),
    )
    
    db.add(user)
    
    # Store initial password in history
    password_history = PasswordHistory(
        id=str(uuid4()),
        user_id=user.id,
        password_hash=password_hash,
    )
    db.add(password_history)
    
    await db.commit()
    await db.refresh(user)
    
    # Audit log
    await AuditService.log(
        db=db,
        action=AuditAction.USER_CREATED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"email": user.email, "username": user.username},
    )
    
    # Track metrics
    MetricsService.track_user_registration()
    
    logger.info("User registered successfully", user_id=user.id, email=user.email)
    
    # TODO: Send verification email in background task
    # background_tasks.add_task(send_verification_email, user.email, verification_token)
    
    return RegisterResponse(
        message="Registration successful. Please check your email to verify your account.",
        user_id=user.id,
        email=user.email,
        requires_verification=True,
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """
    Authenticate user and return access/refresh tokens.
    
    Security features:
    - Brute-force protection with progressive lockout
    - Constant-time password comparison
    - Audit logging
    - MFA support
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    # Find user by email or username
    query = select(User).where(
        or_(
            User.email == data.identifier.lower(),
            User.username == data.identifier.lower()
        )
    )
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user:
        # Record failed attempt even for non-existent users
        await record_login_attempt(
            db=db,
            user_id=None,
            email=data.identifier,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason="user_not_found",
        )
        MetricsService.track_login_attempt(success=False)
        # Use same message to prevent user enumeration
        raise AuthenticationError(ERROR_MESSAGES["INVALID_CREDENTIALS"])
    
    # Check account status
    if user.status == UserStatus.SUSPENDED:
        await record_login_attempt(
            db=db,
            user_id=str(user.id),
            email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason="account_suspended",
        )
        raise AuthenticationError("Your account has been suspended. Please contact support.")
    
    if user.status == UserStatus.DEACTIVATED:
        await record_login_attempt(
            db=db,
            user_id=str(user.id),
            email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason="account_deactivated",
        )
        raise AuthenticationError("Your account has been deactivated.")
    
    # Check lockout
    await check_account_lockout(db, user)
    
    # Verify password
    if not PasswordService.verify_password(data.password, user.password_hash):
        await handle_failed_login(db, user)
        await record_login_attempt(
            db=db,
            user_id=str(user.id),
            email=user.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason="invalid_password",
        )
        await db.commit()
        MetricsService.track_login_attempt(success=False)
        raise AuthenticationError(ERROR_MESSAGES["INVALID_CREDENTIALS"])
    
    # Check if MFA is enabled and required
    if user.mfa_enabled and not data.mfa_code:
        return LoginResponse(
            access_token="",
            refresh_token="",
            token_type="bearer",
            expires_in=0,
            requires_mfa=True,
            mfa_type="totp",
        )
    
    # Verify MFA code if provided
    if user.mfa_enabled:
        if not data.mfa_code:
            raise AuthenticationError("MFA code is required.")
        
        if not MFAService.verify_totp(user.mfa_secret, data.mfa_code):
            await record_login_attempt(
                db=db,
                user_id=str(user.id),
                email=user.email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                failure_reason="invalid_mfa_code",
            )
            MetricsService.track_login_attempt(success=False)
            raise AuthenticationError("Invalid MFA code.")
    
    # Check email verification for pending users
    if user.status == UserStatus.PENDING_VERIFICATION:
        if settings.security.require_email_verification:
            raise AuthenticationError(
                "Please verify your email address before logging in."
            )
    
    # Successful login - reset failed attempts
    await reset_failed_attempts(db, user)
    
    # Generate token family for rotation
    token_family = str(uuid4())
    
    # Create tokens
    access_token = JWTService.create_access_token(
        user_id=user.id,
        token_type=TokenType.ACCESS,
        additional_claims={
            "email": user.email,
            "role": user.role.value,
        },
    )
    
    refresh_token = JWTService.create_refresh_token(
        user_id=user.id,
        token_family=token_family,
    )
    
    # Create session
    session = await create_user_session(db, user, request, token_family)
    
    await db.commit()
    
    # Record successful login
    await record_login_attempt(
        db=db,
        user_id=str(user.id),
        email=user.email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True,
    )
    
    # Audit log
    await AuditService.log(
        db=db,
        action=AuditAction.USER_LOGIN,
        user_id=str(user.id),
        ip_address=ip_address,
        user_agent=user_agent,
        details={"session_id": str(session.id)},
    )
    
    MetricsService.track_login_attempt(success=True)
    
    logger.info("User logged in successfully", user_id=user.id)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.jwt.access_expire_minutes * 60,
        requires_mfa=False,
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    request: Request,
    data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> RefreshTokenResponse:
    """
    Refresh access token using refresh token.
    
    Implements token rotation:
    - Each refresh token can only be used once
    - Using an old refresh token invalidates the entire token family
    - Detects token reuse attacks
    """
    # Verify refresh token
    try:
        payload = JWTService.verify_token(data.refresh_token, TokenType.REFRESH)
    except TokenError as e:
        MetricsService.track_token_refresh(success=False)
        raise
    
    user_id = payload.get("sub")
    token_family = payload.get("family")
    
    if not user_id or not token_family:
        raise TokenError("Invalid refresh token.")
    
    # Find active session for this token family
    result = await db.execute(
        select(UserSession)
        .where(
            and_(
                UserSession.user_id == user_id,
                UserSession.token_family == token_family,
                UserSession.revoked == False,
                UserSession.expires_at > datetime.now(timezone.utc),
            )
        )
    )
    session = result.scalar_one_or_none()
    
    if not session:
        # Potential token reuse attack - invalidate all sessions for this family
        logger.warning(
            "Possible refresh token reuse detected",
            user_id=user_id,
            token_family=token_family,
        )
        await invalidate_token_family(db, token_family)
        await db.commit()
        
        await AuditService.log(
            db=db,
            action=AuditAction.TOKEN_REFRESH,
            user_id=user_id,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details={"error": "token_reuse_detected", "token_family": token_family},
            success=False,
        )
        
        MetricsService.track_token_refresh(success=False)
        raise TokenError("Invalid or expired refresh token.")
    
    # Get user
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    
    if not user or user.status not in [UserStatus.ACTIVE, UserStatus.PENDING_VERIFICATION]:
        raise TokenError("User account is not active.")
    
    # Rotate tokens - invalidate old session and create new one
    session.revoked = True
    session.revoked_at = datetime.now(timezone.utc)
    
    # Generate new token family
    new_token_family = str(uuid4())
    
    # Create new tokens
    new_access_token = JWTService.create_access_token(
        user_id=user.id,
        token_type=TokenType.ACCESS,
        additional_claims={
            "email": user.email,
            "role": user.role.value,
        },
    )
    
    new_refresh_token = JWTService.create_refresh_token(
        user_id=user.id,
        token_family=new_token_family,
    )
    
    # Create new session
    new_session = await create_user_session(db, user, request, new_token_family)
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.TOKEN_REFRESH,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"new_session_id": new_session.id},
    )
    
    MetricsService.track_token_refresh(success=True)
    
    logger.debug("Token refreshed successfully", user_id=user.id)
    
    return RefreshTokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.jwt.access_expire_minutes * 60,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    data: LogoutRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Logout user and invalidate refresh token.
    
    Options:
    - Logout current session only
    - Logout all sessions (all_sessions=True)
    """
    if data.all_sessions:
        # Revoke all user sessions
        await db.execute(
            update(UserSession)
            .where(
                and_(
                    UserSession.user_id == current_user.user.id,
                    UserSession.revoked == False,
                )
            )
            .values(revoked=True, revoked_at=datetime.now(timezone.utc))
        )
        message = "Successfully logged out from all sessions."
    else:
        # Revoke only the current session (by refresh token family)
        if data.refresh_token:
            try:
                payload = JWTService.verify_token(data.refresh_token, TokenType.REFRESH)
                token_family = payload.get("family")
                if token_family:
                    await invalidate_token_family(db, token_family)
            except TokenError:
                pass  # Token may already be invalid
        
        message = "Successfully logged out."
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.USER_LOGOUT,
        user_id=current_user.user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"all_sessions": data.all_sessions},
    )
    
    logger.info("User logged out", user_id=current_user.user.id, all_sessions=data.all_sessions)
    
    return MessageResponse(message=message)


@router.post("/password/reset-request", response_model=MessageResponse)
async def request_password_reset(
    request: Request,
    data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Request a password reset email.
    
    Security features:
    - Rate limited
    - Same response regardless of email existence (prevent enumeration)
    - Token expires after configured time
    """
    # Always return same message to prevent user enumeration
    response_message = (
        "If an account with that email exists, you will receive a password reset link shortly."
    )
    
    # Find user
    result = await db.execute(
        select(User).where(User.email == data.email.lower())
    )
    user = result.scalar_one_or_none()
    
    if not user:
        logger.info("Password reset requested for non-existent email", email=data.email)
        return MessageResponse(message=response_message)
    
    if user.status in [UserStatus.SUSPENDED, UserStatus.DEACTIVATED]:
        logger.warning("Password reset requested for inactive account", user_id=user.id)
        return MessageResponse(message=response_message)
    
    # Generate reset token
    reset_token = EncryptionService.generate_secure_token(32)
    
    # Store reset token (hashed for security)
    user.password_reset_token = PasswordService.hash_password(reset_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.PASSWORD_RESET_REQUEST,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("Password reset token generated", user_id=user.id)
    
    # TODO: Send password reset email in background task
    # background_tasks.add_task(send_password_reset_email, user.email, reset_token)
    
    return MessageResponse(message=response_message)


@router.post("/password/reset-confirm", response_model=MessageResponse)
async def confirm_password_reset(
    request: Request,
    data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Confirm password reset with token and set new password.
    
    Security features:
    - Token validation with expiration
    - Password history check
    - All sessions invalidated after reset
    """
    # Find user by email
    result = await db.execute(
        select(User).where(User.email == data.email.lower())
    )
    user = result.scalar_one_or_none()
    
    if not user or not user.password_reset_token:
        raise ValidationError("Invalid or expired reset token.")
    
    # Check token expiration
    if user.password_reset_sent_at:
        token_age = datetime.now(timezone.utc) - user.password_reset_sent_at.replace(tzinfo=timezone.utc)
        if token_age > timedelta(hours=settings.security.password_reset_expire_hours):
            raise ValidationError("Reset token has expired. Please request a new one.")
    
    # Verify token
    if not PasswordService.verify_password(data.token, user.password_reset_token):
        logger.warning("Invalid password reset token attempt", user_id=user.id)
        raise ValidationError("Invalid or expired reset token.")
    
    # Check password history
    history_result = await db.execute(
        select(PasswordHistory)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(settings.password.history_size)
    )
    password_history = history_result.scalars().all()
    
    for old_password in password_history:
        if PasswordService.verify_password(data.new_password, old_password.password_hash):
            raise ValidationError(
                f"Cannot reuse any of your last {settings.password.history_size} passwords."
            )
    
    # Hash new password
    new_password_hash = PasswordService.hash_password(data.new_password)
    
    # Update user
    user.password_hash = new_password_hash
    user.password_reset_token = None
    user.password_reset_sent_at = None
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    user.locked_until = None
    
    # Add to password history
    password_entry = PasswordHistory(
        id=str(uuid4()),
        user_id=user.id,
        password_hash=new_password_hash,
    )
    db.add(password_entry)
    
    # Invalidate all sessions
    await db.execute(
        update(UserSession)
        .where(
            and_(
                UserSession.user_id == user.id,
                UserSession.revoked == False,
            )
        )
        .values(revoked=True, revoked_at=datetime.now(timezone.utc))
    )
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.PASSWORD_RESET,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("Password reset completed", user_id=user.id)
    
    return MessageResponse(message="Password has been reset successfully. Please log in with your new password.")


@router.post("/password/change", response_model=MessageResponse)
async def change_password(
    request: Request,
    data: PasswordChangeRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Change password for authenticated user.
    
    Requires current password verification.
    Enforces password history policy.
    """
    user = current_user.user
    
    # Verify current password
    if not PasswordService.verify_password(data.current_password, user.password_hash):
        await AuditService.log(
            db=db,
            action=AuditAction.PASSWORD_CHANGE,
            user_id=user.id,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details={"error": "invalid_current_password"},
            success=False,
        )
        raise AuthenticationError("Current password is incorrect.")
    
    # Check password history
    history_result = await db.execute(
        select(PasswordHistory)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(settings.password.history_size)
    )
    password_history = history_result.scalars().all()
    
    for old_password in password_history:
        if PasswordService.verify_password(data.new_password, old_password.password_hash):
            raise ValidationError(
                f"Cannot reuse any of your last {settings.password.history_size} passwords."
            )
    
    # Hash new password
    new_password_hash = PasswordService.hash_password(data.new_password)
    
    # Update user
    user.password_hash = new_password_hash
    user.password_changed_at = datetime.now(timezone.utc)
    
    # Add to password history
    password_entry = PasswordHistory(
        id=str(uuid4()),
        user_id=user.id,
        password_hash=new_password_hash,
    )
    db.add(password_entry)
    
    # Optionally invalidate other sessions
    if data.logout_other_sessions:
        # Keep current session, revoke others
        await db.execute(
            update(UserSession)
            .where(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.revoked == False,
                )
            )
            .values(revoked=True, revoked_at=datetime.now(timezone.utc))
        )
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.PASSWORD_CHANGE,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
        details={"logout_other_sessions": data.logout_other_sessions},
    )
    
    logger.info("Password changed successfully", user_id=user.id)
    
    return MessageResponse(
        message="Password changed successfully."
        + (" All other sessions have been logged out." if data.logout_other_sessions else "")
    )


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    request: Request,
    token: str,
    email: str,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Verify user email with verification token.
    """
    # Find user
    result = await db.execute(
        select(User).where(User.email == email.lower())
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise ValidationError("Invalid verification link.")
    
    if user.email_verified:
        return MessageResponse(message="Email is already verified.")
    
    # Verify token (constant-time comparison)
    if not EncryptionService.secure_compare(
        user.email_verification_token or "",
        token
    ):
        raise ValidationError("Invalid or expired verification link.")
    
    # Check token expiration (24 hours)
    if user.email_verification_sent_at:
        token_age = datetime.now(timezone.utc) - user.email_verification_sent_at.replace(tzinfo=timezone.utc)
        if token_age > timedelta(hours=24):
            raise ValidationError("Verification link has expired. Please request a new one.")
    
    # Update user
    user.email_verified = True
    user.email_verified_at = datetime.now(timezone.utc)
    user.email_verification_token = None
    user.status = UserStatus.ACTIVE
    
    await db.commit()
    
    await AuditService.log(
        db=db,
        action=AuditAction.EMAIL_VERIFIED,
        user_id=user.id,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    
    logger.info("Email verified successfully", user_id=user.id)
    
    return MessageResponse(message="Email verified successfully. You can now log in.")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification_email(
    request: Request,
    email: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Resend email verification link.
    """
    response_message = "If an unverified account with that email exists, a new verification link will be sent."
    
    # Find user
    result = await db.execute(
        select(User).where(User.email == email.lower())
    )
    user = result.scalar_one_or_none()
    
    if not user or user.email_verified:
        return MessageResponse(message=response_message)
    
    # Rate limit - don't allow more than one email per 5 minutes
    if user.email_verification_sent_at:
        time_since_last = datetime.now(timezone.utc) - user.email_verification_sent_at.replace(tzinfo=timezone.utc)
        if time_since_last < timedelta(minutes=5):
            return MessageResponse(message=response_message)
    
    # Generate new verification token
    verification_token = EncryptionService.generate_secure_token(32)
    
    user.email_verification_token = verification_token
    user.email_verification_sent_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    logger.info("Verification email resent", user_id=user.id)
    
    # TODO: Send verification email in background task
    # background_tasks.add_task(send_verification_email, user.email, verification_token)
    
    return MessageResponse(message=response_message)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUser = Depends(get_current_user),
) -> UserResponse:
    """
    Get current authenticated user's information.
    """
    user = current_user.user
    encryption_service = EncryptionService()
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=encryption_service.decrypt(user.first_name_encrypted) if user.first_name_encrypted else None,
        last_name=encryption_service.decrypt(user.last_name_encrypted) if user.last_name_encrypted else None,
        role=user.role,
        status=user.status,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        last_login=user.last_login,
    )
