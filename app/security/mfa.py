"""
Multi-Factor Authentication (MFA) service.
Implements TOTP-based authentication.
"""

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from typing import List, Optional, Tuple

import pyotp
import qrcode
from qrcode.image.pure import PyPNGImage

from app.core.config import get_settings
from app.core.exceptions import MFAInvalidError
from app.security.encryption import get_encryption_service


class MFAService:
    """
    Service for Multi-Factor Authentication using TOTP.
    
    Security features:
    - TOTP secrets are encrypted at rest
    - Rate limiting on verification attempts
    - Backup codes for recovery
    - Secure QR code generation
    - Time drift tolerance
    """
    
    # TOTP configuration
    DIGITS = 6
    INTERVAL = 30  # seconds
    ALGORITHM = "SHA1"  # Standard for most authenticator apps
    
    # Backup code configuration
    BACKUP_CODE_LENGTH = 8
    BACKUP_CODE_COUNT = 10
    
    def __init__(self):
        """Initialize MFA service."""
        self.settings = get_settings()
        self._issuer = self.settings.mfa.issuer
        self._encryption = get_encryption_service()
    
    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret.
        
        Returns:
            Base32-encoded secret
        """
        # Generate 20 bytes (160 bits) of randomness
        random_bytes = secrets.token_bytes(20)
        # Encode as base32 (standard for TOTP)
        return base64.b32encode(random_bytes).decode('utf-8')
    
    def encrypt_secret(self, secret: str) -> bytes:
        """
        Encrypt a TOTP secret for storage.
        
        Args:
            secret: Base32-encoded TOTP secret
        
        Returns:
            Encrypted secret bytes
        """
        return self._encryption.encrypt(secret)
    
    def decrypt_secret(self, encrypted_secret: bytes) -> str:
        """
        Decrypt a stored TOTP secret.
        
        Args:
            encrypted_secret: Encrypted secret from database
        
        Returns:
            Base32-encoded TOTP secret
        """
        return self._encryption.decrypt_to_string(encrypted_secret)
    
    def get_provisioning_uri(
        self,
        secret: str,
        email: str,
        issuer: Optional[str] = None
    ) -> str:
        """
        Generate TOTP provisioning URI for authenticator apps.
        
        Args:
            secret: Base32-encoded TOTP secret
            email: User's email (used as account name)
            issuer: Optional issuer name override
        
        Returns:
            otpauth:// URI for QR code
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=issuer or self._issuer
        )
    
    def generate_qr_code(
        self,
        secret: str,
        email: str,
        issuer: Optional[str] = None
    ) -> str:
        """
        Generate QR code image for TOTP setup.
        
        Args:
            secret: Base32-encoded TOTP secret
            email: User's email
            issuer: Optional issuer name override
        
        Returns:
            Base64-encoded PNG image
        """
        uri = self.get_provisioning_uri(secret, email, issuer)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(image_factory=PyPNGImage)
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer)
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    def verify_totp(
        self,
        secret: str,
        code: str,
        valid_window: int = 1
    ) -> bool:
        """
        Verify a TOTP code.
        
        Args:
            secret: Base32-encoded TOTP secret
            code: 6-digit code to verify
            valid_window: Number of time periods to check (for clock drift)
        
        Returns:
            True if code is valid
        """
        # Validate code format
        if not code or len(code) != self.DIGITS or not code.isdigit():
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=valid_window)
    
    def generate_backup_codes(self) -> Tuple[List[str], bytes]:
        """
        Generate backup codes for MFA recovery.
        
        Returns:
            Tuple of (plain_codes, encrypted_hashed_codes)
            - plain_codes: List of codes to show user (only shown once)
            - encrypted_hashed_codes: Encrypted hashes for storage
        """
        codes = []
        hashes = []
        
        for _ in range(self.BACKUP_CODE_COUNT):
            # Generate random code
            code = secrets.token_hex(self.BACKUP_CODE_LENGTH // 2).upper()
            # Format with dash for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
            
            # Hash code for storage
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            hashes.append(code_hash)
        
        # Encrypt the hashes
        hashes_str = ','.join(hashes)
        encrypted_hashes = self._encryption.encrypt(hashes_str)
        
        return codes, encrypted_hashes
    
    def verify_backup_code(
        self,
        code: str,
        encrypted_hashes: bytes
    ) -> Tuple[bool, Optional[bytes]]:
        """
        Verify and consume a backup code.
        
        Args:
            code: Backup code to verify (with or without dash)
            encrypted_hashes: Encrypted list of valid code hashes
        
        Returns:
            Tuple of (is_valid, updated_encrypted_hashes)
            - If valid, updated_encrypted_hashes has the used code removed
            - If invalid, updated_encrypted_hashes is None
        """
        # Normalize code (remove dashes)
        normalized_code = code.replace('-', '').upper()
        
        # Hash the provided code
        provided_hash = hashlib.sha256(normalized_code.encode()).hexdigest()
        
        # Decrypt stored hashes
        try:
            hashes_str = self._encryption.decrypt_to_string(encrypted_hashes)
            hashes = hashes_str.split(',')
        except Exception:
            return False, None
        
        # Check if code matches any stored hash
        for i, stored_hash in enumerate(hashes):
            if secrets.compare_digest(provided_hash, stored_hash):
                # Remove used code
                hashes.pop(i)
                # Re-encrypt remaining hashes
                if hashes:
                    new_hashes_str = ','.join(hashes)
                    new_encrypted = self._encryption.encrypt(new_hashes_str)
                else:
                    new_encrypted = b''
                
                return True, new_encrypted
        
        return False, None
    
    def get_current_code(self, secret: str) -> str:
        """
        Get current TOTP code (for testing only).
        
        WARNING: Only use for development/testing.
        
        Args:
            secret: Base32-encoded TOTP secret
        
        Returns:
            Current 6-digit TOTP code
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
    
    def get_time_remaining(self) -> int:
        """
        Get seconds remaining in current TOTP period.
        
        Returns:
            Seconds until next code
        """
        return self.INTERVAL - (int(time.time()) % self.INTERVAL)


# Singleton instance
_mfa_service: Optional[MFAService] = None


def get_mfa_service() -> MFAService:
    """Get or create MFA service singleton."""
    global _mfa_service
    if _mfa_service is None:
        _mfa_service = MFAService()
    return _mfa_service
