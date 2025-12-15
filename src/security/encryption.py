"""
AES-256-GCM encryption for secure API key storage.

This module provides government-ready encryption for storing sensitive credentials:
- PBKDF2 key derivation with 100,000 iterations
- Unique salt per encrypted value
- AES-256-GCM authenticated encryption
- Unique nonce per encryption
- 128-bit authentication tag for integrity

Storage format: base64(salt[16] + nonce[12] + tag[16] + ciphertext)
"""

import base64
import hashlib
import os
import secrets
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
SALT_LENGTH = 16  # 128-bit salt
NONCE_LENGTH = 12  # 96-bit nonce (recommended for GCM)
TAG_LENGTH = 16  # 128-bit authentication tag
KEY_LENGTH = 32  # 256-bit key for AES-256
PBKDF2_ITERATIONS = 100_000  # NIST recommended minimum


class EncryptionService:
    """
    Service for encrypting and decrypting sensitive data using AES-256-GCM.

    This implementation is designed for compliance with government security standards:
    - Uses PBKDF2 for key derivation from a master key
    - Each encrypted value has a unique salt and nonce
    - Authenticated encryption ensures both confidentiality and integrity
    """

    def __init__(self, master_key: bytes):
        """
        Initialize the encryption service.

        Args:
            master_key: 32-byte master encryption key.

        Raises:
            ValueError: If master_key is not exactly 32 bytes.
        """
        if len(master_key) != KEY_LENGTH:
            raise ValueError(f"Master key must be exactly {KEY_LENGTH} bytes")
        self._master_key = master_key

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive an encryption key from the master key using PBKDF2.

        Args:
            salt: Unique salt for this derivation.

        Returns:
            32-byte derived key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(self._master_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string using AES-256-GCM.

        Args:
            plaintext: The string to encrypt.

        Returns:
            Base64-encoded encrypted data containing:
            salt (16 bytes) + nonce (12 bytes) + tag (16 bytes) + ciphertext

        Raises:
            ValueError: If plaintext is empty.
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty string")

        # Generate unique salt and nonce
        salt = secrets.token_bytes(SALT_LENGTH)
        nonce = secrets.token_bytes(NONCE_LENGTH)

        # Derive key from master key using salt
        derived_key = self._derive_key(salt)

        # Encrypt using AES-256-GCM
        aesgcm = AESGCM(derived_key)
        plaintext_bytes = plaintext.encode("utf-8")

        # AESGCM.encrypt returns ciphertext + tag concatenated
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

        # Combine: salt + nonce + ciphertext_with_tag
        # Note: cryptography library appends 16-byte tag to ciphertext
        combined = salt + nonce + ciphertext_with_tag

        # Return as base64 for safe storage
        return base64.b64encode(combined).decode("ascii")

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt a string encrypted with encrypt().

        Args:
            encrypted_data: Base64-encoded encrypted data.

        Returns:
            The original plaintext string.

        Raises:
            ValueError: If encrypted_data is invalid or corrupted.
            cryptography.exceptions.InvalidTag: If authentication fails (tampering detected).
        """
        if not encrypted_data:
            raise ValueError("Cannot decrypt empty string")

        try:
            # Decode from base64
            combined = base64.b64decode(encrypted_data)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")

        # Minimum length: salt + nonce + tag + at least 1 byte ciphertext
        min_length = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH + 1
        if len(combined) < min_length:
            raise ValueError("Encrypted data is too short")

        # Extract components
        salt = combined[:SALT_LENGTH]
        nonce = combined[SALT_LENGTH : SALT_LENGTH + NONCE_LENGTH]
        ciphertext_with_tag = combined[SALT_LENGTH + NONCE_LENGTH :]

        # Derive the same key using the salt
        derived_key = self._derive_key(salt)

        # Decrypt and verify authentication tag
        aesgcm = AESGCM(derived_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        return plaintext_bytes.decode("utf-8")

    def rotate_encryption(self, encrypted_data: str, new_master_key: bytes) -> str:
        """
        Re-encrypt data with a new master key (for key rotation).

        Args:
            encrypted_data: Data encrypted with current master key.
            new_master_key: New 32-byte master key.

        Returns:
            Data encrypted with the new master key.
        """
        # Decrypt with current key
        plaintext = self.decrypt(encrypted_data)

        # Create new service with new key and encrypt
        new_service = EncryptionService(new_master_key)
        return new_service.encrypt(plaintext)

    @staticmethod
    def generate_master_key() -> str:
        """
        Generate a new random master key.

        Returns:
            64-character hex string (32 bytes).
        """
        return secrets.token_hex(KEY_LENGTH)

    @staticmethod
    def validate_master_key(key_hex: str) -> bool:
        """
        Validate that a hex string is a valid master key.

        Args:
            key_hex: Hex-encoded key to validate.

        Returns:
            True if valid, False otherwise.
        """
        try:
            key_bytes = bytes.fromhex(key_hex)
            return len(key_bytes) == KEY_LENGTH
        except (ValueError, TypeError):
            return False

    def clear_key(self) -> None:
        """
        Attempt to clear the master key from memory.

        Note: Python's garbage collection makes this imperfect,
        but it's better than leaving the key indefinitely.
        """
        # Overwrite with zeros (best effort in Python)
        if hasattr(self, "_master_key"):
            # Create a new bytes object of zeros
            zero_key = b"\x00" * KEY_LENGTH
            self._master_key = zero_key


def create_encryption_service(master_key_hex: Optional[str] = None) -> EncryptionService:
    """
    Create an encryption service from a hex-encoded master key.

    Args:
        master_key_hex: 64-character hex string. If None, reads from
                       MASTER_ENCRYPTION_KEY environment variable.

    Returns:
        Configured EncryptionService.

    Raises:
        ValueError: If key is missing or invalid.
    """
    if master_key_hex is None:
        master_key_hex = os.getenv("MASTER_ENCRYPTION_KEY")

    if not master_key_hex:
        raise ValueError(
            "Master encryption key not provided. "
            "Set MASTER_ENCRYPTION_KEY environment variable or pass key_hex. "
            f"Generate with: python -c \"import secrets; print(secrets.token_hex({KEY_LENGTH}))\""
        )

    if not EncryptionService.validate_master_key(master_key_hex):
        raise ValueError(
            f"Invalid master key. Must be a {KEY_LENGTH * 2}-character hex string "
            f"({KEY_LENGTH} bytes)."
        )

    master_key = bytes.fromhex(master_key_hex)
    return EncryptionService(master_key)
