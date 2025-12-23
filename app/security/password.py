"""
Password hashing and validation service.
Uses Argon2id for secure password hashing.
"""

import re
import secrets
from typing import List, Optional, Tuple

from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    HashingError,
    InvalidHash,
    VerificationError,
    VerifyMismatchError
)

from app.core.config import get_settings
from app.core.exceptions import PasswordValidationError


class PasswordService:
    """
    Service for secure password hashing and validation.
    
    Uses Argon2id which is:
    - Memory-hard (resistant to GPU attacks)
    - Time-hard (resistant to ASIC attacks)
    - Combines Argon2i (side-channel resistant) and Argon2d (GPU resistant)
    
    Security considerations:
    - Uses recommended parameters from OWASP
    - Constant-time verification
    - Automatic salt generation
    - Password policy enforcement
    """
    
    # Special characters for password validation
    SPECIAL_CHARACTERS = r"!@#$%^&*()_+-=[]{}|;':\",./<>?"
    
    def __init__(self):
        """Initialize password service with settings."""
        self.settings = get_settings()
        
        # Initialize Argon2id hasher with secure parameters
        # These parameters follow OWASP recommendations
        self._hasher = PasswordHasher(
            time_cost=3,  # Number of iterations
            memory_cost=65536,  # 64 MB memory usage
            parallelism=4,  # Number of parallel threads
            hash_len=32,  # Length of the hash
            salt_len=16,  # Length of random salt
            type=Type.ID  # Argon2id variant
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id.
        
        Args:
            password: Plain text password
        
        Returns:
            Argon2 encoded hash string
        
        Raises:
            PasswordValidationError: If password doesn't meet requirements
        """
        # Validate password meets policy
        self.validate_password_strength(password)
        
        try:
            return self._hasher.hash(password)
        except HashingError as e:
            raise PasswordValidationError(
                detail="Failed to hash password",
                extra={"error": str(e)}
            )
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.
        
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            password: Plain text password to verify
            password_hash: Argon2 encoded hash
        
        Returns:
            True if password matches, False otherwise
        """
        try:
            self._hasher.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False
        except (InvalidHash, VerificationError):
            return False
    
    def needs_rehash(self, password_hash: str) -> bool:
        """
        Check if a password hash needs to be rehashed.
        
        This happens when hash parameters have been updated.
        
        Args:
            password_hash: Existing hash to check
        
        Returns:
            True if rehash is needed
        """
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHash:
            return True
    
    def validate_password_strength(self, password: str) -> List[str]:
        """
        Validate password meets security requirements.
        
        Args:
            password: Password to validate
        
        Returns:
            List of validation errors (empty if valid)
        
        Raises:
            PasswordValidationError: If password doesn't meet requirements
        """
        errors = []
        settings = self.settings.password
        
        # Check minimum length
        if len(password) < settings.min_length:
            errors.append(f"Password must be at least {settings.min_length} characters")
        
        # Check maximum length (prevent DoS with very long passwords)
        if len(password) > 128:
            errors.append("Password cannot exceed 128 characters")
        
        # Check for uppercase letters
        if settings.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letters
        if settings.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for digits
        if settings.require_digit and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        # Check for special characters
        if settings.require_special:
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', password):
                errors.append("Password must contain at least one special character")
        
        # Check for common patterns
        common_patterns = [
            r'(.)\1{2,}',  # Repeated characters (aaa, 111)
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        ]
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Password contains common patterns")
                break
        
        # Check for common passwords (basic check)
        common_passwords = {
            'password', 'password1', 'password123', '123456', '12345678',
            'qwerty', 'letmein', 'welcome', 'admin', 'login'
        }
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        if errors:
            raise PasswordValidationError(
                detail="Password does not meet security requirements",
                requirements=errors
            )
        
        return errors
    
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Length of password to generate (minimum 12)
        
        Returns:
            Secure random password meeting all requirements
        """
        if length < 12:
            length = 12
        
        # Character sets
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        special = '!@#$%^&*()_+-='
        
        # Ensure at least one from each required set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill remaining with random characters from all sets
        all_chars = lowercase + uppercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle to randomize positions
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
    
    def generate_reset_token(self) -> Tuple[str, str]:
        """
        Generate a secure password reset token.
        
        Returns:
            Tuple of (plain_token, hashed_token)
            Plain token is sent to user, hashed token is stored in DB
        """
        import hashlib
        
        # Generate URL-safe token
        token = secrets.token_urlsafe(32)
        
        # Hash for storage (not using Argon2 as we need fast lookup)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        return token, token_hash
    
    def verify_reset_token(self, token: str, token_hash: str) -> bool:
        """
        Verify a password reset token.
        
        Args:
            token: Plain token from user
            token_hash: Hashed token from database
        
        Returns:
            True if token is valid
        """
        import hashlib
        
        computed_hash = hashlib.sha256(token.encode()).hexdigest()
        return secrets.compare_digest(computed_hash, token_hash)


# Singleton instance
_password_service: Optional[PasswordService] = None


def get_password_service() -> PasswordService:
    """Get or create password service singleton."""
    global _password_service
    if _password_service is None:
        _password_service = PasswordService()
    return _password_service
