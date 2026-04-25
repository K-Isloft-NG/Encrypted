"""
Test suite for Codificator V2.

Run with:
    python -m pytest codificator_v2/tests/ -v
    
Or:
    python -m codificator_v2.tests.test_all
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestCryptoAEAD(unittest.TestCase):
    """Test AEAD encryption."""
    
    def test_aesgcm_roundtrip(self):
        """Test AES-GCM encrypt/decrypt roundtrip."""
        from codificator_v2.core import Algorithm
        from codificator_v2.core.crypto_aead import AEAD
        
        aead = AEAD(Algorithm.AES_256_GCM)
        key = AEAD.generate_key()
        plaintext = b"Hello, World! This is a test message."
        aad = b"authenticated metadata"
        
        nonce, ciphertext = aead.encrypt(key, plaintext, aad)
        decrypted = aead.decrypt(key, nonce, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_chacha20_roundtrip(self):
        """Test ChaCha20-Poly1305 encrypt/decrypt roundtrip."""
        from codificator_v2.core import Algorithm
        from codificator_v2.core.crypto_aead import AEAD
        
        aead = AEAD(Algorithm.CHACHA20_POLY1305)
        key = AEAD.generate_key()
        plaintext = b"Another test message for ChaCha20."
        aad = b"more metadata"
        
        nonce, ciphertext = aead.encrypt(key, plaintext, aad)
        decrypted = aead.decrypt(key, nonce, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_wrong_key_fails(self):
        """Test that wrong key fails authentication."""
        from codificator_v2.core import Algorithm
        from codificator_v2.core.crypto_aead import AEAD
        from codificator_v2.core.errors import IntegrityError
        
        aead = AEAD(Algorithm.AES_256_GCM)
        key1 = AEAD.generate_key()
        key2 = AEAD.generate_key()
        plaintext = b"Secret data"
        
        nonce, ciphertext = aead.encrypt(key1, plaintext, b"")
        
        with self.assertRaises(IntegrityError):
            aead.decrypt(key2, nonce, ciphertext, b"")
    
    def test_tamper_detection(self):
        """Test that tampering is detected."""
        from codificator_v2.core import Algorithm
        from codificator_v2.core.crypto_aead import AEAD
        from codificator_v2.core.errors import IntegrityError
        
        aead = AEAD(Algorithm.AES_256_GCM)
        key = AEAD.generate_key()
        plaintext = b"Important data"
        
        nonce, ciphertext = aead.encrypt(key, plaintext, b"")
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[5] ^= 0xFF
        
        with self.assertRaises(IntegrityError):
            aead.decrypt(key, nonce, bytes(tampered), b"")


class TestKDF(unittest.TestCase):
    """Test key derivation."""
    
    def test_derive_key(self):
        """Test scrypt key derivation."""
        from codificator_v2.core.kdf import KDF
        
        kdf = KDF(n=2**14)  # Lower for faster tests
        salt = KDF.generate_salt()
        
        key1 = kdf.derive("password123", salt)
        key2 = kdf.derive("password123", salt)
        key3 = kdf.derive("different", salt)
        
        self.assertEqual(len(key1), 32)
        self.assertEqual(key1, key2)  # Same password = same key
        self.assertNotEqual(key1, key3)  # Different password = different key
    
    def test_password_policy(self):
        """Test password validation."""
        from codificator_v2.core.kdf import PasswordPolicy
        
        policy = PasswordPolicy(min_length=12)
        
        # Too short
        valid, errors = policy.validate("short")
        self.assertFalse(valid)
        
        # Long enough
        valid, errors = policy.validate("longenoughpass")
        self.assertTrue(valid)
    
    def test_password_strength(self):
        """Test password strength checking."""
        from codificator_v2.core.kdf import PasswordPolicy
        
        policy = PasswordPolicy()
        
        # Weak
        strength, _ = policy.check_strength("password")
        self.assertIn(strength, ["WEAK", "MODERATE"])
        
        # Strong
        strength, _ = policy.check_strength("C0mpl3x!P@ss#2024")
        self.assertEqual(strength, "STRONG")


class TestVault(unittest.TestCase):
    """Test SecureVault file operations."""
    
    def test_encrypt_decrypt_small_file(self):
        """Test encryption/decryption of small file."""
        from codificator_v2.core.vault import SecureVault
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "original.txt"
            encrypted = Path(tmpdir) / "encrypted.codi"
            decrypted = Path(tmpdir) / "decrypted.txt"
            
            original_content = "This is test content!"
            src.write_text(original_content)
            
            vault = SecureVault(scrypt_n=2**14)
            vault.encrypt_file(src, encrypted, "SecurePassword123!")
            
            self.assertTrue(encrypted.exists())
            
            vault.decrypt_file(encrypted, decrypted, "SecurePassword123!")
            
            self.assertEqual(decrypted.read_text(), original_content)
    
    def test_encrypt_decrypt_chunked(self):
        """Test chunked encryption for larger files."""
        from codificator_v2.core.vault import SecureVault
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "large.bin"
            encrypted = Path(tmpdir) / "large.codi"
            decrypted = Path(tmpdir) / "large_dec.bin"
            
            # Create file larger than chunk size
            original_data = os.urandom(5 * 1024)  # 5 KB
            src.write_bytes(original_data)
            
            vault = SecureVault(
                scrypt_n=2**14,
                chunk_size=1024,
                chunk_threshold=0  # Force chunking
            )
            
            result = vault.encrypt_file(src, encrypted, "Password123456!", force_chunked=True)
            
            self.assertTrue(result["chunked"])
            self.assertGreater(result["chunk_count"], 1)
            
            vault.decrypt_file(encrypted, decrypted, "Password123456!")
            
            self.assertEqual(decrypted.read_bytes(), original_data)
    
    def test_wrong_password(self):
        """Test that wrong password fails."""
        from codificator_v2.core.vault import SecureVault
        from codificator_v2.core.errors import IntegrityError
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "test.txt"
            encrypted = Path(tmpdir) / "test.codi"
            decrypted = Path(tmpdir) / "test_dec.txt"
            
            src.write_text("Secret content")
            
            vault = SecureVault(scrypt_n=2**14)
            vault.encrypt_file(src, encrypted, "CorrectPassword!")
            
            with self.assertRaises(IntegrityError):
                vault.decrypt_file(encrypted, decrypted, "WrongPassword!")
    
    def test_file_info(self):
        """Test getting file info without password."""
        from codificator_v2.core.vault import SecureVault
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "test.txt"
            encrypted = Path(tmpdir) / "test.codi"
            
            src.write_text("Content")
            
            vault = SecureVault(scrypt_n=2**14)
            vault.encrypt_file(src, encrypted, "Password12345!")
            
            info = vault.get_file_info(encrypted)
            
            self.assertIn("version", info)
            self.assertIn("algorithm", info)


class TestKeyring(unittest.TestCase):
    """Test keyring operations."""
    
    def test_create_and_unlock(self):
        """Test keyring creation and unlock."""
        from codificator_v2.core.keyring import Keyring
        
        with tempfile.TemporaryDirectory() as tmpdir:
            keyring = Keyring(Path(tmpdir) / "test.keyring")
            
            keyring.create("MasterPassword!")
            self.assertFalse(keyring.is_locked)
            
            keyring.lock()
            self.assertTrue(keyring.is_locked)
            
            keyring.unlock("MasterPassword!")
            self.assertFalse(keyring.is_locked)
    
    def test_create_and_get_key(self):
        """Test creating and retrieving keys."""
        from codificator_v2.core.keyring import Keyring
        
        with tempfile.TemporaryDirectory() as tmpdir:
            keyring = Keyring(Path(tmpdir) / "test.keyring")
            keyring.create("MasterPassword!")
            
            key_id = keyring.create_key("test-key")
            
            self.assertIsNotNone(key_id)
            
            key_bytes = keyring.get_key(key_id)
            self.assertEqual(len(key_bytes), 32)
    
    def test_export_import(self):
        """Test key export and import."""
        from codificator_v2.core.keyring import Keyring
        
        with tempfile.TemporaryDirectory() as tmpdir:
            kr1 = Keyring(Path(tmpdir) / "kr1.keyring")
            kr1.create("Master1!")
            key_id = kr1.create_key("export-test")
            original_key = kr1.get_key(key_id)
            
            # Export
            exported = kr1.export_key(key_id, "ExportPassword!")
            
            # Import to new keyring
            kr2 = Keyring(Path(tmpdir) / "kr2.keyring")
            kr2.create("Master2!")
            
            new_key_id = kr2.import_key(exported, "ExportPassword!")
            imported_key = kr2.get_key(new_key_id)
            
            self.assertEqual(original_key, imported_key)


class TestBatch(unittest.TestCase):
    """Test batch operations."""
    
    def test_encrypt_folder(self):
        """Test batch folder encryption."""
        from codificator_v2.core.vault import SecureVault
        from codificator_v2.core.batch import BatchProcessor
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = Path(tmpdir) / "src"
            enc_dir = Path(tmpdir) / "enc"
            src_dir.mkdir()
            
            # Create test files
            (src_dir / "file1.txt").write_text("Content 1")
            (src_dir / "file2.txt").write_text("Content 2")
            
            vault = SecureVault(scrypt_n=2**14)
            processor = BatchProcessor(vault)
            
            result = processor.encrypt_folder(
                src_dir, enc_dir, "BatchPassword12!"
            )
            
            self.assertEqual(result.succeeded_files, 2)
            self.assertEqual(result.failed_files, 0)
    
    def test_dry_run(self):
        """Test batch dry run."""
        from codificator_v2.core.vault import SecureVault
        from codificator_v2.core.batch import BatchProcessor
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = Path(tmpdir) / "src"
            enc_dir = Path(tmpdir) / "enc"
            src_dir.mkdir()
            
            (src_dir / "file1.txt").write_text("Content")
            
            vault = SecureVault(scrypt_n=2**14)
            processor = BatchProcessor(vault)
            
            result = processor.encrypt_folder(
                src_dir, enc_dir, "Password12345!",
                dry_run=True
            )
            
            # Dry run should not create files
            self.assertFalse(enc_dir.exists())


class TestContainerFormats(unittest.TestCase):
    """Test container format handling."""
    
    def test_detect_version(self):
        """Test container version detection."""
        from codificator_v2.core.vault import SecureVault
        from codificator_v2.core.container_v2 import detect_version
        from codificator_v2.core import ContainerVersion
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "test.txt"
            src.write_text("Test")
            
            # Create V1 container
            v1_path = Path(tmpdir) / "v1.codi"
            vault_v1 = SecureVault(
                scrypt_n=2**14,
                container_version=ContainerVersion.V1
            )
            vault_v1.encrypt_file(src, v1_path, "Password12345!")
            
            # Create V2 container
            v2_path = Path(tmpdir) / "v2.codi"
            vault_v2 = SecureVault(
                scrypt_n=2**14,
                container_version=ContainerVersion.V2
            )
            vault_v2.encrypt_file(src, v2_path, "Password12345!")
            
            self.assertEqual(detect_version(v1_path), 1)
            self.assertEqual(detect_version(v2_path), 2)


class TestAudit(unittest.TestCase):
    """Test audit logging."""
    
    def test_log_event(self):
        """Test logging an event."""
        from codificator_v2.core.audit import AuditLogger
        from codificator_v2.core import OperationType
        
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(Path(tmpdir) / "audit.jsonl")
            
            logger.log_operation(
                operation=OperationType.ENCRYPT_FILE,
                src_path="/test/file.txt",
                dst_path="/test/file.codi",
                algorithm="AES-256-GCM",
                status="success"
            )
            
            events = logger.read_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["operation"], "encrypt_file")
    
    def test_paranoid_mode(self):
        """Test paranoid mode hashes paths."""
        from codificator_v2.core.audit import AuditLogger
        from codificator_v2.core import OperationType
        
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                Path(tmpdir) / "audit.jsonl",
                paranoid=True
            )
            
            logger.log_operation(
                operation=OperationType.ENCRYPT_FILE,
                src_path="/secret/path.txt",
                dst_path="/secret/path.codi",
                algorithm="AES-256-GCM",
                status="success"
            )
            
            events = logger.read_events()
            self.assertTrue(events[0]["src_path"].startswith("sha256:"))


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
