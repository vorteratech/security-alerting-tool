"""Tests for the encryption module."""

import pytest

from src.security.encryption import EncryptionService, create_encryption_service


class TestEncryptionService:
    """Tests for EncryptionService."""

    def test_encrypt_decrypt_roundtrip(self, encryption_service):
        """Test that encryption and decryption are reversible."""
        original = "my-secret-api-key-12345"
        encrypted = encryption_service.encrypt(original)
        decrypted = encryption_service.decrypt(encrypted)

        assert decrypted == original
        assert encrypted != original

    def test_encrypt_produces_different_output(self, encryption_service):
        """Test that encrypting the same value twice produces different ciphertext."""
        value = "same-value"
        encrypted1 = encryption_service.encrypt(value)
        encrypted2 = encryption_service.encrypt(value)

        # Different due to random salt and nonce
        assert encrypted1 != encrypted2

        # But both decrypt to same value
        assert encryption_service.decrypt(encrypted1) == value
        assert encryption_service.decrypt(encrypted2) == value

    def test_encrypt_empty_string_raises(self, encryption_service):
        """Test that encrypting empty string raises ValueError."""
        with pytest.raises(ValueError, match="Cannot encrypt empty string"):
            encryption_service.encrypt("")

    def test_decrypt_empty_string_raises(self, encryption_service):
        """Test that decrypting empty string raises ValueError."""
        with pytest.raises(ValueError, match="Cannot decrypt empty string"):
            encryption_service.decrypt("")

    def test_decrypt_invalid_base64_raises(self, encryption_service):
        """Test that decrypting invalid base64 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid base64"):
            encryption_service.decrypt("not-valid-base64!!!")

    def test_decrypt_too_short_raises(self, encryption_service):
        """Test that decrypting too-short data raises ValueError."""
        import base64

        short_data = base64.b64encode(b"short").decode()
        with pytest.raises(ValueError, match="too short"):
            encryption_service.decrypt(short_data)

    def test_invalid_key_length_raises(self):
        """Test that invalid key length raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            EncryptionService(b"short-key")

    def test_generate_master_key(self):
        """Test master key generation."""
        key = EncryptionService.generate_master_key()

        assert len(key) == 64  # 32 bytes = 64 hex chars
        assert EncryptionService.validate_master_key(key)

    def test_validate_master_key_valid(self):
        """Test validation of valid key."""
        valid_key = "a" * 64
        assert EncryptionService.validate_master_key(valid_key)

    def test_validate_master_key_invalid_length(self):
        """Test validation of invalid length key."""
        assert not EncryptionService.validate_master_key("a" * 32)
        assert not EncryptionService.validate_master_key("a" * 128)

    def test_validate_master_key_invalid_hex(self):
        """Test validation of non-hex key."""
        assert not EncryptionService.validate_master_key("g" * 64)

    def test_key_rotation(self, encryption_service):
        """Test key rotation."""
        original = "secret-data"
        encrypted = encryption_service.encrypt(original)

        # Generate new key
        new_key = bytes.fromhex(EncryptionService.generate_master_key())

        # Rotate encryption
        re_encrypted = encryption_service.rotate_encryption(encrypted, new_key)

        # Verify new encryption works with new key
        new_service = EncryptionService(new_key)
        decrypted = new_service.decrypt(re_encrypted)

        assert decrypted == original

    def test_unicode_encryption(self, encryption_service):
        """Test encryption of unicode strings."""
        original = "API密钥-🔐-κλειδί"
        encrypted = encryption_service.encrypt(original)
        decrypted = encryption_service.decrypt(encrypted)

        assert decrypted == original

    def test_long_string_encryption(self, encryption_service):
        """Test encryption of long strings."""
        original = "x" * 10000
        encrypted = encryption_service.encrypt(original)
        decrypted = encryption_service.decrypt(encrypted)

        assert decrypted == original


class TestCreateEncryptionService:
    """Tests for create_encryption_service factory."""

    def test_create_with_valid_key(self):
        """Test creating service with valid key."""
        key = "a" * 64
        service = create_encryption_service(key)
        assert service is not None

    def test_create_with_invalid_key_raises(self):
        """Test creating service with invalid key raises."""
        with pytest.raises(ValueError, match="Invalid master key"):
            create_encryption_service("short")

    def test_create_without_key_raises(self, monkeypatch):
        """Test creating service without key raises."""
        monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)
        with pytest.raises(ValueError, match="not provided"):
            create_encryption_service(None)
