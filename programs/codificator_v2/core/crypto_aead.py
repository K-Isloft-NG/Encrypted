"""
AEAD (Authenticated Encryption with Associated Data) module.

Provides wrappers for AES-256-GCM and ChaCha20-Poly1305 using
the cryptography library.

Security notes:
- Nonces are always randomly generated and must NEVER be reused
- AAD is authenticated but not encrypted
- Tag is always 128 bits (16 bytes)
"""

from __future__ import annotations

import secrets
from typing import Tuple

from . import Algorithm, DEFAULT_NONCE_SIZE, DEFAULT_KEY_SIZE
from .errors import (
    CryptographyNotAvailable, IntegrityError, 
    EncryptionError, UnsupportedAlgorithmError
)

# Lazy import cryptography
_CRYPTO_AVAILABLE: bool | None = None
_AESGCM = None
_ChaCha20Poly1305 = None
_InvalidTag = None


def _ensure_crypto() -> None:
    """Ensure cryptography library is available and imported."""
    global _CRYPTO_AVAILABLE, _AESGCM, _ChaCha20Poly1305, _InvalidTag
    
    if _CRYPTO_AVAILABLE is not None:
        if not _CRYPTO_AVAILABLE:
            raise CryptographyNotAvailable()
        return
    
    try:
        from cryptography.hazmat.primitives.ciphers.aead import (
            AESGCM, ChaCha20Poly1305
        )
        from cryptography.exceptions import InvalidTag
        
        _AESGCM = AESGCM
        _ChaCha20Poly1305 = ChaCha20Poly1305
        _InvalidTag = InvalidTag
        _CRYPTO_AVAILABLE = True
    except ImportError:
        _CRYPTO_AVAILABLE = False
        raise CryptographyNotAvailable()


def is_crypto_available() -> bool:
    """Check if cryptography library is available."""
    global _CRYPTO_AVAILABLE
    if _CRYPTO_AVAILABLE is None:
        try:
            _ensure_crypto()
        except CryptographyNotAvailable:
            pass
    return _CRYPTO_AVAILABLE or False


class AEAD:
    """
    Authenticated Encryption with Associated Data.
    
    Supports:
    - AES-256-GCM
    - ChaCha20-Poly1305
    
    Usage:
        aead = AEAD(Algorithm.AES_256_GCM)
        nonce, ciphertext = aead.encrypt(key, plaintext, aad)
        plaintext = aead.decrypt(key, nonce, ciphertext, aad)
    """
    
    NONCE_SIZE = DEFAULT_NONCE_SIZE  # 12 bytes = 96 bits
    
    def __init__(self, algorithm: Algorithm = Algorithm.AES_256_GCM):
        """
        Initialize AEAD with specified algorithm.
        
        Args:
            algorithm: AEAD algorithm to use
        """
        _ensure_crypto()
        
        if algorithm not in (Algorithm.AES_256_GCM, Algorithm.CHACHA20_POLY1305):
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        
        self.algorithm = algorithm
    
    def _get_cipher(self, key: bytes):
        """Get cipher instance for the key."""
        if len(key) != DEFAULT_KEY_SIZE:
            raise EncryptionError(f"Key must be {DEFAULT_KEY_SIZE} bytes")
        
        if self.algorithm == Algorithm.AES_256_GCM:
            assert _AESGCM is not None
            return _AESGCM(key)
        elif self.algorithm == Algorithm.CHACHA20_POLY1305:
            assert _ChaCha20Poly1305 is not None
            return _ChaCha20Poly1305(key)
        else:
            raise UnsupportedAlgorithmError(f"Unknown algorithm: {self.algorithm}")
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a cryptographically secure random nonce."""
        return secrets.token_bytes(AEAD.NONCE_SIZE)
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure random key."""
        return secrets.token_bytes(DEFAULT_KEY_SIZE)
    
    def encrypt(self, key: bytes, plaintext: bytes, 
                aad: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypt data with AEAD.
        
        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt
            aad: Associated data to authenticate (not encrypted)
        
        Returns:
            Tuple of (nonce, ciphertext_with_tag)
        
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            cipher = self._get_cipher(key)
            nonce = self.generate_nonce()
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            return nonce, ciphertext
        except Exception as e:
            if "InvalidTag" in str(type(e)):
                raise IntegrityError()
            raise EncryptionError(f"Encryption failed: {e}")
    
    def encrypt_with_nonce(self, key: bytes, nonce: bytes,
                           plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt with a provided nonce.
        
        WARNING: Nonce must NEVER be reused with the same key!
        This method is for chunked encryption where nonces are
        derived deterministically per chunk.
        
        Args:
            key: 32-byte encryption key
            nonce: 12-byte nonce (must be unique for this key)
            plaintext: Data to encrypt
            aad: Associated data to authenticate
        
        Returns:
            Ciphertext with tag
        """
        if len(nonce) != self.NONCE_SIZE:
            raise EncryptionError(f"Nonce must be {self.NONCE_SIZE} bytes")
        
        try:
            cipher = self._get_cipher(key)
            return cipher.encrypt(nonce, plaintext, aad)
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")
    
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes,
                aad: bytes = b"") -> bytes:
        """
        Decrypt data with AEAD.
        
        Args:
            key: 32-byte encryption key
            nonce: Nonce used during encryption
            ciphertext: Encrypted data with tag
            aad: Associated data that was authenticated
        
        Returns:
            Decrypted plaintext
        
        Raises:
            IntegrityError: If authentication fails (wrong password or tampered)
        """
        try:
            cipher = self._get_cipher(key)
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            if "InvalidTag" in str(type(e)):
                raise IntegrityError()
            raise IntegrityError(f"Decryption failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"",
            algorithm: Algorithm = Algorithm.AES_256_GCM) -> Tuple[bytes, bytes]:
    """
    Encrypt data with AEAD.
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        aad: Associated data to authenticate
        algorithm: AEAD algorithm to use
    
    Returns:
        Tuple of (nonce, ciphertext_with_tag)
    """
    aead = AEAD(algorithm)
    return aead.encrypt(key, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"",
            algorithm: Algorithm = Algorithm.AES_256_GCM) -> bytes:
    """
    Decrypt data with AEAD.
    
    Args:
        key: 32-byte encryption key
        nonce: Nonce used during encryption
        ciphertext: Encrypted data with tag
        aad: Associated data that was authenticated
        algorithm: AEAD algorithm used
    
    Returns:
        Decrypted plaintext
    
    Raises:
        IntegrityError: If authentication fails
    """
    aead = AEAD(algorithm)
    return aead.decrypt(key, nonce, ciphertext, aad)


def generate_key() -> bytes:
    """Generate a random 256-bit key."""
    return AEAD.generate_key()


def generate_nonce() -> bytes:
    """Generate a random 96-bit nonce."""
    return AEAD.generate_nonce()
