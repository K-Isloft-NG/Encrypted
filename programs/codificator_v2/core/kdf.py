"""
Key Derivation Functions module.

Provides scrypt-based key derivation with password policy enforcement.

Security notes:
- scrypt is memory-hard, resistant to GPU/ASIC attacks
- Salt must be random and unique per encryption
- Default parameters are conservative (N=32768)
"""

from __future__ import annotations

import hashlib
import secrets
from typing import List, Optional, Tuple

from . import (
    ScryptParams, SecurityPolicy,
    DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P, DEFAULT_DKLEN,
    DEFAULT_MIN_PASSWORD_LENGTH
)
from .errors import (
    CryptographyNotAvailable, KeyDerivationError, 
    WeakPasswordError, PolicyViolationError
)

# Lazy import
_CRYPTO_AVAILABLE: bool | None = None
_Scrypt = None
_default_backend = None


def _ensure_crypto() -> None:
    """Ensure cryptography library is available."""
    global _CRYPTO_AVAILABLE, _Scrypt, _default_backend
    
    if _CRYPTO_AVAILABLE is not None:
        if not _CRYPTO_AVAILABLE:
            raise CryptographyNotAvailable()
        return
    
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend
        
        _Scrypt = Scrypt
        _default_backend = default_backend
        _CRYPTO_AVAILABLE = True
    except ImportError:
        _CRYPTO_AVAILABLE = False
        raise CryptographyNotAvailable()


class PasswordPolicy:
    """
    Password strength validation and policy enforcement.
    
    Usage:
        policy = PasswordPolicy(min_length=12)
        valid, errors = policy.validate("mypassword")
        strength, tips = policy.check_strength("mypassword")
    """
    
    # Common weak patterns to detect
    WEAK_PATTERNS = [
        'password', '123456', 'qwerty', 'abc123', 'letmein',
        'welcome', 'admin', 'login', '111111', '12345678'
    ]
    
    def __init__(self, 
                 min_length: int = DEFAULT_MIN_PASSWORD_LENGTH,
                 require_uppercase: bool = False,
                 require_lowercase: bool = False,
                 require_digits: bool = False,
                 require_special: bool = False):
        """
        Initialize password policy.
        
        Args:
            min_length: Minimum password length
            require_uppercase: Require at least one uppercase letter
            require_lowercase: Require at least one lowercase letter
            require_digits: Require at least one digit
            require_special: Require at least one special character
        """
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digits = require_digits
        self.require_special = require_special
    
    @classmethod
    def from_security_policy(cls, policy: SecurityPolicy) -> 'PasswordPolicy':
        """Create from SecurityPolicy."""
        return cls(
            min_length=policy.min_password_length,
            require_uppercase=policy.require_uppercase,
            require_lowercase=policy.require_lowercase,
            require_digits=policy.require_digits,
            require_special=policy.require_special,
        )
    
    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against policy.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")
        
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if self.require_special:
            special = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
            if not any(c in special for c in password):
                errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def check_strength(self, password: str) -> Tuple[str, List[str]]:
        """
        Check password strength and provide improvement tips.
        
        Returns:
            Tuple of (strength_level, list_of_tips)
            Strength levels: WEAK, MODERATE, STRONG, VERY_STRONG
        """
        tips = []
        score = 0
        
        # Length scoring
        if len(password) >= 20:
            score += 3
        elif len(password) >= 16:
            score += 2
        elif len(password) >= 12:
            score += 1
        else:
            tips.append("Use at least 12 characters (16+ recommended)")
        
        # Character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password)
        
        variety = sum([has_upper, has_lower, has_digit, has_special])
        score += variety
        
        if not has_upper:
            tips.append("Add uppercase letters")
        if not has_lower:
            tips.append("Add lowercase letters")
        if not has_digit:
            tips.append("Add numbers")
        if not has_special:
            tips.append("Add special characters (!@#$%...)")
        
        # Check for common patterns
        lower_pw = password.lower()
        for pattern in self.WEAK_PATTERNS:
            if pattern in lower_pw:
                score -= 2
                tips.append("Avoid common password patterns")
                break
        
        # Check for sequential characters
        if self._has_sequential(password):
            score -= 1
            tips.append("Avoid sequential characters (abc, 123)")
        
        # Check for repeated characters
        if self._has_repeated(password):
            score -= 1
            tips.append("Avoid repeated characters (aaa, 111)")
        
        # Determine strength level
        if score >= 7:
            strength = "VERY_STRONG"
        elif score >= 5:
            strength = "STRONG"
        elif score >= 3:
            strength = "MODERATE"
        else:
            strength = "WEAK"
        
        return strength, tips
    
    @staticmethod
    def _has_sequential(password: str) -> bool:
        """Check for sequential characters."""
        for i in range(len(password) - 2):
            if (ord(password[i]) + 1 == ord(password[i+1]) == ord(password[i+2]) - 1):
                return True
        return False
    
    @staticmethod
    def _has_repeated(password: str, min_repeat: int = 3) -> bool:
        """Check for repeated characters."""
        for i in range(len(password) - min_repeat + 1):
            if len(set(password[i:i+min_repeat])) == 1:
                return True
        return False


class KDF:
    """
    Key Derivation Function using scrypt.
    
    Usage:
        kdf = KDF()
        salt = kdf.generate_salt()
        key = kdf.derive(password, salt)
        
        # Or with full params
        params = ScryptParams(salt=salt, n=32768, r=8, p=1)
        key = kdf.derive_with_params(password, params)
    """
    
    DEFAULT_SALT_SIZE = 32  # 256 bits
    
    def __init__(self, 
                 n: int = DEFAULT_SCRYPT_N,
                 r: int = DEFAULT_SCRYPT_R,
                 p: int = DEFAULT_SCRYPT_P,
                 dklen: int = DEFAULT_DKLEN):
        """
        Initialize KDF with parameters.
        
        Args:
            n: CPU/memory cost parameter (power of 2)
            r: Block size parameter
            p: Parallelization parameter
            dklen: Derived key length in bytes
        """
        _ensure_crypto()
        self.n = n
        self.r = r
        self.p = p
        self.dklen = dklen
    
    @staticmethod
    def generate_salt(size: int = 32) -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(size)
    
    def derive(self, password: str, salt: bytes) -> bytes:
        """
        Derive a key from password using scrypt.
        
        Args:
            password: User password
            salt: Random salt (must be unique per encryption)
        
        Returns:
            Derived key bytes
        """
        params = ScryptParams(
            salt=salt, n=self.n, r=self.r, p=self.p, dklen=self.dklen
        )
        return self.derive_with_params(password, params)
    
    @staticmethod
    def derive_with_params(password: str, params: ScryptParams) -> bytes:
        """
        Derive a key using specified scrypt parameters.
        
        Args:
            password: User password
            params: scrypt parameters including salt
        
        Returns:
            Derived key bytes
        """
        _ensure_crypto()
        
        try:
            assert _Scrypt is not None
            assert _default_backend is not None
            kdf = _Scrypt(
                salt=params.salt,
                length=params.dklen,
                n=params.n,
                r=params.r,
                p=params.p,
                backend=_default_backend()
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise KeyDerivationError(f"Key derivation failed: {e}")
    
    @staticmethod
    def validate_params(params: ScryptParams, policy: Optional[SecurityPolicy] = None) -> None:
        """
        Validate scrypt parameters against policy.
        
        Raises:
            PolicyViolationError: If parameters don't meet policy requirements
        """
        if policy is None:
            return
        
        if params.n < policy.min_scrypt_n:
            raise PolicyViolationError(
                "scrypt_n",
                f"scrypt N must be at least {policy.min_scrypt_n}"
            )
        
        if params.r < policy.min_scrypt_r:
            raise PolicyViolationError(
                "scrypt_r",
                f"scrypt r must be at least {policy.min_scrypt_r}"
            )
        
        if params.p < policy.min_scrypt_p:
            raise PolicyViolationError(
                "scrypt_p",
                f"scrypt p must be at least {policy.min_scrypt_p}"
            )


class KeyCombiner:
    """
    Combine multiple key sources (password + keyfile) for 2FA.
    
    Method: HKDF-style combination using SHA-256
    combined_key = SHA-256(derived_key || keyfile_data)
    """
    
    KEYFILE_SIZE = 32  # 256 bits
    
    @staticmethod
    def generate_keyfile() -> bytes:
        """Generate random keyfile data."""
        return secrets.token_bytes(KeyCombiner.KEYFILE_SIZE)
    
    @staticmethod
    def combine(derived_key: bytes, keyfile_data: bytes) -> bytes:
        """
        Combine derived key with keyfile using SHA-256.
        
        Args:
            derived_key: Key derived from password
            keyfile_data: Raw keyfile bytes
        
        Returns:
            Combined 32-byte key
        """
        if len(keyfile_data) < KeyCombiner.KEYFILE_SIZE:
            raise KeyDerivationError(
                f"Keyfile must be at least {KeyCombiner.KEYFILE_SIZE} bytes"
            )
        
        # Use first 32 bytes of keyfile
        kf = keyfile_data[:KeyCombiner.KEYFILE_SIZE]
        
        # Combine using SHA-256
        combined = hashlib.sha256(derived_key + kf).digest()
        return combined
    
    @staticmethod
    def derive_combined(password: str, salt: bytes, keyfile_data: bytes,
                       kdf_params: Optional[ScryptParams] = None) -> bytes:
        """
        Derive key from password and combine with keyfile.
        
        Args:
            password: User password
            salt: Salt for KDF
            keyfile_data: Keyfile bytes
            kdf_params: Optional scrypt parameters
        
        Returns:
            Combined 32-byte key
        """
        if kdf_params is None:
            kdf_params = ScryptParams(salt=salt)
        else:
            kdf_params.salt = salt
        
        derived = KDF.derive_with_params(password, kdf_params)
        return KeyCombiner.combine(derived, keyfile_data)


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def derive_key(password: str, salt: Optional[bytes] = None,
               params: Optional[ScryptParams] = None) -> Tuple[bytes, ScryptParams]:
    """
    Derive a key from password.
    
    Args:
        password: User password
        salt: Optional salt (generated if not provided)
        params: Optional scrypt parameters
    
    Returns:
        Tuple of (derived_key, params_used)
    """
    if params is None:
        params = ScryptParams()
    
    if salt is not None:
        params.salt = salt
    elif not params.salt:
        params.salt = KDF.generate_salt()
    
    key = KDF.derive_with_params(password, params)
    return key, params


def validate_password(password: str, 
                      policy: Optional[SecurityPolicy] = None) -> Tuple[bool, List[str]]:
    """
    Validate password against policy.
    
    Args:
        password: Password to validate
        policy: Security policy (uses defaults if None)
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    if policy is None:
        pp = PasswordPolicy()
    else:
        pp = PasswordPolicy.from_security_policy(policy)
    
    return pp.validate(password)


def check_password_strength(password: str) -> Tuple[str, List[str]]:
    """
    Check password strength.
    
    Returns:
        Tuple of (strength_level, tips)
    """
    pp = PasswordPolicy()
    return pp.check_strength(password)
