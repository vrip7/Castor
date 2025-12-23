"""
API Key service for generating and validating API keys.
Provides secure key generation with cryptographic best practices.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple

from app.core.config import get_settings
from app.core.exceptions import APIKeyError, APIKeyExpiredError, APIKeyRevokedError


class APIKeyService:
    """
    Service for API key generation and validation.
    
    Security features:
    - Cryptographically secure key generation
    - Keys are hashed before storage (never store raw keys)
    - Prefix for easy identification without revealing the key
    - Support for key rotation with grace periods
    - IP and origin restrictions
    - Scope-based access control
    """
    
    def __init__(self):
        """Initialize API key service with settings."""
        self.settings = get_settings()
        self._prefix = self.settings.api_key.prefix
        self._key_length = self.settings.api_key.length
        self._hash_algorithm = self.settings.api_key.hash_algorithm
        self._secret = self.settings.security.secret_key.encode()
    
    def generate_api_key(self) -> Tuple[str, str, str]:
        """
        Generate a new API key.
        
        Returns:
            Tuple of (full_key, key_prefix, key_hash)
            - full_key: Complete API key to give to user (only shown once)
            - key_prefix: First 12 chars for identification
            - key_hash: SHA-512 hash for storage
        """
        # Generate random key bytes
        random_bytes = secrets.token_bytes(self._key_length)
        
        # Convert to URL-safe base64 string
        key_body = secrets.token_urlsafe(self._key_length)
        
        # Combine prefix and body
        full_key = f"{self._prefix}{key_body}"
        
        # Extract prefix for identification (first 12 chars including prefix)
        key_prefix = full_key[:12]
        
        # Generate hash for storage
        key_hash = self._hash_key(full_key)
        
        return full_key, key_prefix, key_hash
    
    def _hash_key(self, key: str) -> str:
        """
        Hash an API key for storage.
        
        Uses HMAC-SHA512 with the application secret for additional security.
        
        Args:
            key: Raw API key
        
        Returns:
            Hex-encoded hash
        """
        return hmac.new(
            self._secret,
            key.encode(),
            hashlib.sha512
        ).hexdigest()
    
    def verify_key(self, provided_key: str, stored_hash: str) -> bool:
        """
        Verify an API key against its stored hash.
        
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            provided_key: Key provided by the client
            stored_hash: Hash stored in database
        
        Returns:
            True if key is valid
        """
        computed_hash = self._hash_key(provided_key)
        return secrets.compare_digest(computed_hash, stored_hash)
    
    def validate_key_format(self, key: str) -> bool:
        """
        Validate API key format.
        
        Args:
            key: API key to validate
        
        Returns:
            True if format is valid
        """
        if not key:
            return False
        
        # Check prefix
        if not key.startswith(self._prefix):
            return False
        
        # Check minimum length (prefix + at least 32 chars)
        if len(key) < len(self._prefix) + 32:
            return False
        
        return True
    
    def extract_prefix(self, key: str) -> str:
        """
        Extract the prefix portion of an API key.
        
        Used for quick lookup without exposing the full key.
        
        Args:
            key: Full API key
        
        Returns:
            Key prefix (first 12 characters)
        """
        return key[:12] if len(key) >= 12 else key
    
    def generate_signature(
        self,
        method: str,
        path: str,
        timestamp: str,
        body: Optional[str] = None,
        api_key: Optional[str] = None
    ) -> str:
        """
        Generate HMAC signature for request signing.
        
        This provides additional security by ensuring requests
        haven't been tampered with.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            timestamp: Request timestamp
            body: Optional request body
            api_key: Optional API key to include in signature
        
        Returns:
            Hex-encoded HMAC signature
        """
        # Create canonical string
        parts = [
            method.upper(),
            path,
            timestamp
        ]
        
        if body:
            # Hash body to handle large payloads
            body_hash = hashlib.sha256(body.encode()).hexdigest()
            parts.append(body_hash)
        
        if api_key:
            # Include key hash (not the key itself)
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            parts.append(key_hash)
        
        canonical_string = '\n'.join(parts)
        
        # Generate HMAC signature
        signature = hmac.new(
            self._secret,
            canonical_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(
        self,
        provided_signature: str,
        method: str,
        path: str,
        timestamp: str,
        body: Optional[str] = None,
        api_key: Optional[str] = None,
        max_age_seconds: int = 300
    ) -> bool:
        """
        Verify request signature.
        
        Args:
            provided_signature: Signature from request header
            method: HTTP method
            path: Request path
            timestamp: Request timestamp
            body: Optional request body
            api_key: Optional API key
            max_age_seconds: Maximum age of request (default 5 minutes)
        
        Returns:
            True if signature is valid and timestamp is within range
        """
        # Verify timestamp is recent (prevent replay attacks)
        try:
            request_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            age = abs((now - request_time).total_seconds())
            
            if age > max_age_seconds:
                return False
        except (ValueError, AttributeError):
            return False
        
        # Compute expected signature
        expected_signature = self.generate_signature(
            method, path, timestamp, body, api_key
        )
        
        # Constant-time comparison
        return secrets.compare_digest(provided_signature, expected_signature)
    
    def rotate_key(self, old_key: str) -> Tuple[str, str, str, str]:
        """
        Generate a new API key for rotation.
        
        During rotation, both old and new keys should be valid
        for a grace period.
        
        Args:
            old_key: Current API key being rotated
        
        Returns:
            Tuple of (new_key, new_prefix, new_hash, old_hash)
        """
        new_key, new_prefix, new_hash = self.generate_api_key()
        old_hash = self._hash_key(old_key)
        
        return new_key, new_prefix, new_hash, old_hash


# Singleton instance
_api_key_service: Optional[APIKeyService] = None


def get_api_key_service() -> APIKeyService:
    """Get or create API key service singleton."""
    global _api_key_service
    if _api_key_service is None:
        _api_key_service = APIKeyService()
    return _api_key_service
