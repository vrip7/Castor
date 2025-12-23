"""
Encryption service for end-to-end data encryption.
Uses AES-256-GCM for authenticated encryption.
"""

import base64
import hashlib
import os
import secrets
from typing import Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings
from app.core.exceptions import EncryptionError


class EncryptionService:
    """
    Service for encrypting and decrypting sensitive data.
    
    Uses AES-256-GCM which provides:
    - Confidentiality (data cannot be read without key)
    - Integrity (data cannot be modified without detection)
    - Authentication (verifies data came from trusted source)
    
    Security considerations:
    - Uses 256-bit keys for quantum resistance
    - Uses unique 96-bit nonces for each encryption
    - Nonces are prepended to ciphertext for easy decryption
    - Constant-time operations where possible
    """
    
    # GCM nonce size (96 bits / 12 bytes is recommended)
    NONCE_SIZE = 12
    # Key size in bytes (256 bits)
    KEY_SIZE = 32
    # Authentication tag size
    TAG_SIZE = 16
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize encryption service.
        
        Args:
            key: Optional encryption key. If not provided, uses settings.
        """
        if key is None:
            settings = get_settings()
            key = self._decode_key(settings.security.encryption_key)
        
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        
        self._key = key
        self._aesgcm = AESGCM(key)
    
    @staticmethod
    def _decode_key(key_string: str) -> bytes:
        """Decode key from base64 or hex string."""
        try:
            # Try base64 first
            return base64.b64decode(key_string)
        except Exception:
            try:
                # Try hex
                return bytes.fromhex(key_string)
            except Exception:
                # Use as raw bytes if short enough, otherwise hash it
                key_bytes = key_string.encode('utf-8')
                if len(key_bytes) == 32:
                    return key_bytes
                # Derive key using SHA-256
                return hashlib.sha256(key_bytes).digest()
    
    def encrypt(
        self,
        plaintext: Union[str, bytes],
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            associated_data: Optional additional authenticated data (AAD)
                           This data is authenticated but not encrypted.
        
        Returns:
            Encrypted data with nonce prepended: nonce || ciphertext || tag
        
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Convert string to bytes if needed
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate random nonce
            nonce = secrets.token_bytes(self.NONCE_SIZE)
            
            # Encrypt (returns ciphertext with tag appended)
            ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
            
            # Prepend nonce to ciphertext
            return nonce + ciphertext
            
        except Exception as e:
            raise EncryptionError(extra={"error": str(e)})
    
    def decrypt(
        self,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data with nonce prepended
            associated_data: Optional additional authenticated data (must match encryption)
        
        Returns:
            Decrypted plaintext as bytes
        
        Raises:
            EncryptionError: If decryption fails (wrong key, tampered data, etc.)
        """
        try:
            if len(ciphertext) < self.NONCE_SIZE + self.TAG_SIZE:
                raise ValueError("Ciphertext too short")
            
            # Extract nonce from beginning
            nonce = ciphertext[:self.NONCE_SIZE]
            actual_ciphertext = ciphertext[self.NONCE_SIZE:]
            
            # Decrypt and verify
            return self._aesgcm.decrypt(nonce, actual_ciphertext, associated_data)
            
        except Exception as e:
            raise EncryptionError(extra={"error": str(e)})
    
    def decrypt_to_string(
        self,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> str:
        """
        Decrypt ciphertext and return as string.
        
        Args:
            ciphertext: Encrypted data with nonce prepended
            associated_data: Optional additional authenticated data
        
        Returns:
            Decrypted plaintext as string
        """
        return self.decrypt(ciphertext, associated_data).decode('utf-8')
    
    @staticmethod
    def generate_key() -> Tuple[bytes, str]:
        """
        Generate a new random encryption key.
        
        Returns:
            Tuple of (raw_key_bytes, base64_encoded_key)
        """
        key = secrets.token_bytes(EncryptionService.KEY_SIZE)
        return key, base64.b64encode(key).decode('utf-8')
    
    def derive_key(
        self,
        password: str,
        salt: Optional[bytes] = None,
        iterations: int = 100000
    ) -> Tuple[bytes, bytes]:
        """
        Derive an encryption key from a password using PBKDF2.
        
        Args:
            password: Password to derive key from
            salt: Optional salt (generated if not provided)
            iterations: Number of PBKDF2 iterations
        
        Returns:
            Tuple of (derived_key, salt)
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of two byte strings.
        Prevents timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
        
        Returns:
            True if equal, False otherwise
        """
        return secrets.compare_digest(a, b)


# Singleton instance for convenience
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get or create encryption service singleton."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service
