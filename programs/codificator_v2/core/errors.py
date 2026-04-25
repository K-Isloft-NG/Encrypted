"""
Exception classes for Codificator V2.

All crypto-related errors intentionally provide vague messages
to prevent information leakage about encryption internals.
"""

from __future__ import annotations
from enum import IntEnum
from typing import Optional


class ExitCode(IntEnum):
    """CLI exit codes."""
    SUCCESS = 0
    GENERAL_ERROR = 1
    BAD_ARGS = 2
    CRYPTO_FAIL = 3
    IO_FAIL = 4
    AUTH_FAIL = 5
    CONFIG_ERROR = 6
    PERMISSION_ERROR = 7
    INTERRUPTED = 130


class CodificatorError(Exception):
    """Base exception for all Codificator errors."""
    exit_code: int = ExitCode.GENERAL_ERROR
    
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


# ══════════════════════════════════════════════════════════════════════════════
# CRYPTO ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class CryptoError(CodificatorError):
    """Base class for cryptographic errors."""
    exit_code = ExitCode.CRYPTO_FAIL


class IntegrityError(CryptoError):
    """
    Raised when authentication tag verification fails.
    
    SECURITY: Message intentionally vague - could be wrong password
    or tampered data. We don't reveal which.
    """
    def __init__(self, message: str = ""):
        default_msg = (
            "Integrity check failed. "
            "Either the password is wrong or the file has been tampered with."
        )
        super().__init__(message or default_msg)
    
    exit_code = ExitCode.AUTH_FAIL


class WeakPasswordError(CryptoError):
    """Raised when password doesn't meet policy requirements."""
    pass


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails."""
    pass


class EncryptionError(CryptoError):
    """Raised when encryption operation fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption operation fails."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# CONTAINER FORMAT ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class ContainerError(CodificatorError):
    """Base class for container format errors."""
    exit_code = ExitCode.CRYPTO_FAIL


class ContainerFormatError(ContainerError):
    """Raised when container format is invalid or corrupted."""
    pass


class ContainerVersionError(ContainerError):
    """Raised when container version is unsupported."""
    def __init__(self, version: int, supported: list[int]):
        super().__init__(
            f"Unsupported container version: {version}",
            f"Supported versions: {supported}"
        )
        self.version = version
        self.supported = supported


class UnsupportedAlgorithmError(ContainerError):
    """Raised when algorithm in container is not supported."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# IO ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class IOError(CodificatorError):
    """Base class for I/O errors."""
    exit_code = ExitCode.IO_FAIL


class FileNotFoundError(IOError):
    """Raised when a required file is not found."""
    def __init__(self, path: str):
        super().__init__(f"File not found: {path}")
        self.path = path


class DirectoryNotFoundError(IOError):
    """Raised when a required directory is not found."""
    def __init__(self, path: str):
        super().__init__(f"Directory not found: {path}")
        self.path = path


class FileExistsError(IOError):
    """Raised when output file already exists and overwrite not allowed."""
    def __init__(self, path: str):
        super().__init__(f"File already exists: {path}")
        self.path = path


class PermissionDeniedError(IOError):
    """Raised when file/directory access is denied."""
    exit_code = ExitCode.PERMISSION_ERROR
    
    def __init__(self, path: str):
        super().__init__(f"Permission denied: {path}")
        self.path = path


class DiskFullError(IOError):
    """Raised when disk is full during write operation."""
    pass


class FileLockError(IOError):
    """Raised when file cannot be locked for exclusive access."""
    def __init__(self, path: str):
        super().__init__(f"Cannot acquire lock on file: {path}")
        self.path = path


# ══════════════════════════════════════════════════════════════════════════════
# KEYRING ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class KeyringError(CodificatorError):
    """Base class for keyring errors."""
    exit_code = ExitCode.CRYPTO_FAIL


class KeyNotFoundError(KeyringError):
    """Raised when a key is not found in the keyring."""
    def __init__(self, key_id: str):
        super().__init__(f"Key not found: {key_id}")
        self.key_id = key_id


class KeyExistsError(KeyringError):
    """Raised when trying to create a key that already exists."""
    def __init__(self, key_id: str):
        super().__init__(f"Key already exists: {key_id}")
        self.key_id = key_id


class KeyringLockedError(KeyringError):
    """Raised when keyring is locked and operation requires unlock."""
    def __init__(self):
        super().__init__("Keyring is locked. Please unlock first.")


class KeyringCorruptedError(KeyringError):
    """Raised when keyring file is corrupted."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# BATCH OPERATION ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class BatchError(CodificatorError):
    """Base class for batch operation errors."""
    pass


class BatchInterruptedError(BatchError):
    """Raised when batch operation is interrupted."""
    exit_code = ExitCode.INTERRUPTED
    
    def __init__(self, processed: int, total: int, checkpoint_path: Optional[str] = None):
        super().__init__(f"Batch interrupted: {processed}/{total} files processed")
        self.processed = processed
        self.total = total
        self.checkpoint_path = checkpoint_path


class BatchPartialError(BatchError):
    """Raised when batch operation completes with some failures."""
    def __init__(self, succeeded: int, failed: int, errors: list[tuple[str, str]]):
        super().__init__(f"Batch completed with errors: {succeeded} succeeded, {failed} failed")
        self.succeeded = succeeded
        self.failed = failed
        self.errors = errors  # List of (path, error_message)


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG / POLICY ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class ConfigError(CodificatorError):
    """Base class for configuration errors."""
    exit_code = ExitCode.CONFIG_ERROR


class InvalidConfigError(ConfigError):
    """Raised when configuration is invalid."""
    pass


class PolicyViolationError(ConfigError):
    """Raised when an operation violates security policy."""
    def __init__(self, policy: str, message: str):
        super().__init__(f"Policy violation [{policy}]: {message}")
        self.policy = policy


class LockedSettingError(ConfigError):
    """Raised when trying to modify a locked setting."""
    def __init__(self, setting: str):
        super().__init__(f"Setting is locked by policy: {setting}")
        self.setting = setting


# ══════════════════════════════════════════════════════════════════════════════
# MIGRATION ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class MigrationError(CodificatorError):
    """Base class for migration errors."""
    pass


class AlreadyMigratedError(MigrationError):
    """Raised when file is already at target version."""
    def __init__(self, path: str, version: int):
        super().__init__(f"File already at version {version}: {path}")
        self.path = path
        self.version = version


# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY ERRORS
# ══════════════════════════════════════════════════════════════════════════════

class DependencyError(CodificatorError):
    """Raised when a required dependency is missing."""
    def __init__(self, package: str, install_cmd: str = ""):
        msg = f"Required package not installed: {package}"
        details = f"Install with: {install_cmd}" if install_cmd else None
        super().__init__(msg, details)
        self.package = package
        self.install_cmd = install_cmd


class CryptographyNotAvailable(DependencyError):
    """Raised when cryptography library is not installed."""
    def __init__(self):
        super().__init__("cryptography", "pip install cryptography")


class TextualNotAvailable(DependencyError):
    """Raised when textual library is not installed."""
    def __init__(self):
        super().__init__("textual", "pip install textual")
