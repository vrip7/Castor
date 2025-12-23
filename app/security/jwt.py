"""
JWT service for token generation and validation.
Implements secure token handling with refresh token rotation.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID, uuid4

from jose import JWTError, jwt
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.constants import TokenType
from app.core.exceptions import TokenExpiredError, TokenInvalidError


class TokenPayload(BaseModel):
    """JWT token payload structure."""
    sub: str  # Subject (user ID)
    exp: datetime  # Expiration time
    iat: datetime  # Issued at
    jti: str  # JWT ID (unique identifier)
    type: str  # Token type (access, refresh, etc.)
    iss: str  # Issuer
    aud: str  # Audience
    
    # Optional fields
    email: Optional[str] = None
    role: Optional[str] = None
    permissions: Optional[list] = None
    session_id: Optional[str] = None
    token_family: Optional[str] = None  # For refresh token rotation


class JWTService:
    """
    Service for JWT token generation and validation.
    
    Security features:
    - Short-lived access tokens (15 minutes default)
    - Refresh token rotation (detect token reuse)
    - Token family tracking for security
    - Cryptographically secure token IDs
    - Proper validation of all claims
    """
    
    def __init__(self):
        """Initialize JWT service with settings."""
        self.settings = get_settings()
        self._secret_key = self.settings.jwt.secret_key
        self._algorithm = self.settings.jwt.algorithm
        self._issuer = self.settings.jwt.issuer
        self._audience = self.settings.jwt.audience
        self._access_token_expire = timedelta(
            minutes=self.settings.jwt.access_token_expire_minutes
        )
        self._refresh_token_expire = timedelta(
            days=self.settings.jwt.refresh_token_expire_days
        )
    
    def create_access_token(
        self,
        user_id: UUID,
        email: str,
        role: str,
        permissions: list,
        session_id: UUID,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, datetime]:
        """
        Create a new access token.
        
        Args:
            user_id: User's unique identifier
            email: User's email address
            role: User's role
            permissions: List of user permissions
            session_id: Session identifier
            additional_claims: Optional additional JWT claims
        
        Returns:
            Tuple of (token_string, expiration_datetime)
        """
        now = datetime.now(timezone.utc)
        expires = now + self._access_token_expire
        
        payload = {
            "sub": str(user_id),
            "exp": expires,
            "iat": now,
            "jti": secrets.token_hex(16),
            "type": TokenType.ACCESS.value,
            "iss": self._issuer,
            "aud": self._audience,
            "email": email,
            "role": role,
            "permissions": permissions,
            "session_id": str(session_id)
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        return token, expires
    
    def create_refresh_token(
        self,
        user_id: UUID,
        session_id: UUID,
        token_family: Optional[UUID] = None
    ) -> Tuple[str, datetime, UUID, str]:
        """
        Create a new refresh token with token family tracking.
        
        Args:
            user_id: User's unique identifier
            session_id: Session identifier
            token_family: Optional existing token family (for rotation)
        
        Returns:
            Tuple of (token_string, expiration_datetime, token_family_id, token_hash)
        """
        now = datetime.now(timezone.utc)
        expires = now + self._refresh_token_expire
        
        # Create or reuse token family
        if token_family is None:
            token_family = uuid4()
        
        # Generate token ID
        jti = secrets.token_hex(32)
        
        payload = {
            "sub": str(user_id),
            "exp": expires,
            "iat": now,
            "jti": jti,
            "type": TokenType.REFRESH.value,
            "iss": self._issuer,
            "aud": self._audience,
            "session_id": str(session_id),
            "token_family": str(token_family)
        }
        
        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        
        # Hash token for storage (don't store raw refresh tokens)
        token_hash = hashlib.sha512(token.encode()).hexdigest()
        
        return token, expires, token_family, token_hash
    
    def create_password_reset_token(
        self,
        user_id: UUID,
        email: str,
        expires_minutes: int = 30
    ) -> Tuple[str, datetime]:
        """
        Create a password reset token.
        
        Args:
            user_id: User's unique identifier
            email: User's email for verification
            expires_minutes: Token validity in minutes
        
        Returns:
            Tuple of (token_string, expiration_datetime)
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=expires_minutes)
        
        payload = {
            "sub": str(user_id),
            "exp": expires,
            "iat": now,
            "jti": secrets.token_hex(16),
            "type": TokenType.RESET_PASSWORD.value,
            "iss": self._issuer,
            "aud": self._audience,
            "email": email
        }
        
        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        return token, expires
    
    def create_email_verification_token(
        self,
        user_id: UUID,
        email: str,
        expires_hours: int = 24
    ) -> Tuple[str, datetime]:
        """
        Create an email verification token.
        
        Args:
            user_id: User's unique identifier
            email: Email to verify
            expires_hours: Token validity in hours
        
        Returns:
            Tuple of (token_string, expiration_datetime)
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=expires_hours)
        
        payload = {
            "sub": str(user_id),
            "exp": expires,
            "iat": now,
            "jti": secrets.token_hex(16),
            "type": TokenType.EMAIL_VERIFICATION.value,
            "iss": self._issuer,
            "aud": self._audience,
            "email": email
        }
        
        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        return token, expires
    
    def verify_token(
        self,
        token: str,
        expected_type: Optional[TokenType] = None
    ) -> TokenPayload:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string
            expected_type: Optional expected token type for validation
        
        Returns:
            Decoded token payload
        
        Raises:
            TokenExpiredError: If token has expired
            TokenInvalidError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require": ["exp", "iat", "sub", "jti", "type"]
                }
            )
            
            # Verify token type if specified
            if expected_type and payload.get("type") != expected_type.value:
                raise TokenInvalidError(
                    detail=f"Expected {expected_type.value} token"
                )
            
            return TokenPayload(**payload)
            
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError(token_type=expected_type.value if expected_type else "")
        except JWTError as e:
            raise TokenInvalidError(detail=str(e))
    
    def verify_access_token(self, token: str) -> TokenPayload:
        """Verify an access token."""
        return self.verify_token(token, TokenType.ACCESS)
    
    def verify_refresh_token(self, token: str) -> TokenPayload:
        """Verify a refresh token."""
        return self.verify_token(token, TokenType.REFRESH)
    
    def get_token_hash(self, token: str) -> str:
        """
        Get SHA-512 hash of a token.
        
        Used for storing refresh tokens securely.
        """
        return hashlib.sha512(token.encode()).hexdigest()
    
    def decode_token_unsafe(self, token: str) -> Dict[str, Any]:
        """
        Decode token without verification.
        
        WARNING: Only use for debugging or when token validity doesn't matter.
        
        Args:
            token: JWT token string
        
        Returns:
            Decoded payload (unverified)
        """
        return jwt.decode(
            token,
            self._secret_key,
            algorithms=[self._algorithm],
            options={"verify_signature": False}
        )


# Singleton instance
_jwt_service: Optional[JWTService] = None


def get_jwt_service() -> JWTService:
    """Get or create JWT service singleton."""
    global _jwt_service
    if _jwt_service is None:
        _jwt_service = JWTService()
    return _jwt_service
