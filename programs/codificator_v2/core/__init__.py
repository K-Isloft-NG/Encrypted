"""
Core module for Codificator V2.

This module contains all cryptographic and business logic,
completely separated from UI concerns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# Magic bytes for container format
CODI_MAGIC_V1 = b"CODI"
CODI_MAGIC_V2 = b"CDI2"

# File extension
CODI_EXTENSION = ".codi"

# Crypto defaults
DEFAULT_NONCE_SIZE = 12      # 96 bits for AES-GCM and ChaCha20-Poly1305
DEFAULT_TAG_SIZE = 16        # 128 bits
DEFAULT_KEY_SIZE = 32        # 256 bits

# KDF defaults (scrypt)
DEFAULT_SCRYPT_N = 2 ** 15   # 32768 - higher for V2
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_DKLEN = 32

# Chunking
DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024    # 1 MB
CHUNK_THRESHOLD = 10 * 1024 * 1024       # 10 MB - auto-chunk above
MAX_CHUNK_SIZE = 64 * 1024 * 1024        # 64 MB max

# Password policy defaults
DEFAULT_MIN_PASSWORD_LENGTH = 12
RECOMMENDED_MIN_PASSWORD_LENGTH = 16

# Batch defaults
DEFAULT_MAX_WORKERS = 4
DEFAULT_BATCH_CHUNK_SIZE = 100  # Files per checkpoint

# Keyring
KEYRING_FILENAME = ".codificator_keyring.enc"
KEYRING_VERSION = 1

# Audit
AUDIT_LOG_FILENAME = "codificator_audit.log.jsonl"
DEFAULT_AUDIT_MAX_SIZE = 10 * 1024 * 1024  # 10 MB

# Config
CONFIG_FILENAME = "codificator.toml"
CHECKPOINT_EXTENSION = ".checkpoint"


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════════════

class Algorithm(IntEnum):
    """Supported AEAD algorithms."""
    AES_256_GCM = 1
    CHACHA20_POLY1305 = 2


class KDFType(IntEnum):
    """Supported key derivation functions."""
    SCRYPT = 1


class CompressionType(IntEnum):
    """Supported compression algorithms (V2)."""
    NONE = 0
    ZLIB = 1


class ContainerVersion(IntEnum):
    """Container format versions."""
    V1 = 1
    V2 = 2


class KeySource(Enum):
    """Source of encryption key."""
    PASSWORD = auto()
    KEYRING = auto()
    KEYFILE = auto()
    PASSWORD_AND_KEYFILE = auto()  # 2FA


class OperationType(Enum):
    """Type of operation for audit/history."""
    ENCRYPT_FILE = "encrypt_file"
    DECRYPT_FILE = "decrypt_file"
    ENCRYPT_FOLDER = "encrypt_folder"
    DECRYPT_FOLDER = "decrypt_folder"
    VERIFY = "verify"
    KEY_CREATE = "key_create"
    KEY_ROTATE = "key_rotate"
    KEY_EXPORT = "key_export"
    KEY_IMPORT = "key_import"
    KEY_DELETE = "key_delete"
    MIGRATE = "migrate"


class ProfileType(Enum):
    """Security profile types."""
    PERSONAL = "personal"
    WORK = "work"
    FORENSIC = "forensic"
    CUSTOM = "custom"


class BatchStatus(Enum):
    """Status of batch operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    PARTIAL = "partial"


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - CRYPTO
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScryptParams:
    """Parameters for scrypt key derivation."""
    salt: bytes = field(default_factory=bytes)
    n: int = DEFAULT_SCRYPT_N
    r: int = DEFAULT_SCRYPT_R
    p: int = DEFAULT_SCRYPT_P
    dklen: int = DEFAULT_DKLEN
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict (without salt for logging)."""
        return {"n": self.n, "r": self.r, "p": self.p, "dklen": self.dklen}


@dataclass
class ChunkInfo:
    """Information about an encrypted chunk."""
    index: int
    nonce: bytes
    ciphertext_length: int
    offset: int = 0  # Offset in container file


@dataclass
class ChunkTable:
    """Table of all chunks in a chunked container."""
    chunk_size: int
    total_chunks: int
    chunks: List[ChunkInfo] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - CONTAINER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ContainerMetadata:
    """Metadata stored in container AAD (not encrypted)."""
    original_filename: Optional[str] = None
    created_at: str = ""
    tool_version: str = ""
    compressed: bool = False
    compression_type: CompressionType = CompressionType.NONE
    original_size: int = 0  # Pre-compression size
    chunked: bool = False
    chunk_size: int = 0
    chunk_count: int = 0
    
    def to_json_bytes(self) -> bytes:
        """Convert to compact JSON for AAD."""
        import json
        data = {
            "fn": self.original_filename,
            "ts": self.created_at,
            "tv": self.tool_version,
            "co": self.compressed,
            "ct": self.compression_type.value if self.compressed else 0,
            "os": self.original_size,
            "ch": self.chunked,
        }
        if self.chunked:
            data["cs"] = self.chunk_size
            data["cc"] = self.chunk_count
        return json.dumps(data, separators=(',', ':')).encode('utf-8')
    
    @classmethod
    def from_json_bytes(cls, data: bytes) -> 'ContainerMetadata':
        """Parse from JSON bytes."""
        import json
        d = json.loads(data.decode('utf-8'))
        return cls(
            original_filename=d.get("fn"),
            created_at=d.get("ts", ""),
            tool_version=d.get("tv", ""),
            compressed=d.get("co", False),
            compression_type=CompressionType(d.get("ct", 0)),
            original_size=d.get("os", 0),
            chunked=d.get("ch", False),
            chunk_size=d.get("cs", 0),
            chunk_count=d.get("cc", 0),
        )


@dataclass
class ContainerHeader:
    """Header for .codi container file."""
    version: ContainerVersion = ContainerVersion.V2
    algorithm: Algorithm = Algorithm.AES_256_GCM
    kdf: KDFType = KDFType.SCRYPT
    flags: int = 0
    scrypt_params: ScryptParams = field(default_factory=ScryptParams)
    nonce: bytes = field(default_factory=bytes)
    aad: bytes = field(default_factory=bytes)
    
    # Flag bits
    FLAG_HAS_AAD = 0x01
    FLAG_HAS_FILENAME = 0x02
    FLAG_CHUNKED = 0x04
    FLAG_COMPRESSED = 0x08
    FLAG_MULTI_FILE = 0x10  # V2: multiple files in one container


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - KEYRING
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class KeyEntry:
    """Entry in the keyring."""
    key_id: str
    name: str
    created_at: str
    algorithm: Algorithm = Algorithm.AES_256_GCM
    tags: List[str] = field(default_factory=list)
    description: str = ""
    last_used: Optional[str] = None
    use_count: int = 0
    # Note: actual key bytes stored separately, encrypted


@dataclass
class KeyringInfo:
    """Information about the keyring (without sensitive data)."""
    version: int
    created_at: str
    key_count: int
    keys: List[KeyEntry] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - BATCH
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FileTask:
    """A single file task in a batch operation."""
    src_path: Path
    dst_path: Path
    status: BatchStatus = BatchStatus.PENDING
    error: Optional[str] = None
    size_bytes: int = 0
    processed_bytes: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class BatchProgress:
    """Progress information for batch operation."""
    total_files: int = 0
    processed_files: int = 0
    succeeded_files: int = 0
    failed_files: int = 0
    skipped_files: int = 0
    total_bytes: int = 0
    processed_bytes: int = 0
    current_file: Optional[str] = None
    status: BatchStatus = BatchStatus.PENDING
    errors: List[tuple[str, str]] = field(default_factory=list)


@dataclass
class BatchCheckpoint:
    """Checkpoint for resuming interrupted batch operation."""
    operation_id: str
    operation_type: OperationType
    src_path: str
    dst_path: str
    password_hash: str  # For verification only, not the actual password
    algorithm: Algorithm
    total_files: int
    processed_files: List[str]  # Paths of completed files
    failed_files: List[tuple[str, str]]  # (path, error)
    created_at: str
    updated_at: str


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - MANIFEST
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ManifestFileEntry:
    """Entry for a single file in the manifest."""
    relative_path: str
    original_size: int
    encrypted_name: str  # Name of .codi file
    encrypted_size: int
    plaintext_sha256: Optional[str] = None  # Optional, configurable
    ciphertext_sha256: str = ""
    permissions: Optional[int] = None
    created_time: Optional[str] = None
    modified_time: Optional[str] = None


@dataclass
class FolderManifest:
    """Manifest for an encrypted folder."""
    version: int = 1
    created_at: str = ""
    tool_version: str = ""
    root_name: str = ""
    algorithm: Algorithm = Algorithm.AES_256_GCM
    total_files: int = 0
    total_size: int = 0
    files: List[ManifestFileEntry] = field(default_factory=list)
    include_plaintext_hash: bool = False
    
    def to_json(self) -> str:
        """Serialize to JSON."""
        import json
        from dataclasses import asdict
        return json.dumps(asdict(self), indent=2)
    
    @classmethod
    def from_json(cls, data: str) -> 'FolderManifest':
        """Deserialize from JSON."""
        import json
        d = json.loads(data)
        manifest = cls(
            version=d["version"],
            created_at=d["created_at"],
            tool_version=d["tool_version"],
            root_name=d["root_name"],
            algorithm=Algorithm(d["algorithm"]),
            total_files=d["total_files"],
            total_size=d["total_size"],
            include_plaintext_hash=d.get("include_plaintext_hash", False),
        )
        for f in d["files"]:
            manifest.files.append(ManifestFileEntry(**f))
        return manifest


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - POLICIES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityPolicy:
    """Security policy configuration."""
    name: str = "default"
    
    # Password requirements
    min_password_length: int = DEFAULT_MIN_PASSWORD_LENGTH
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digits: bool = False
    require_special: bool = False
    
    # Algorithm restrictions
    allowed_algorithms: List[Algorithm] = field(
        default_factory=lambda: [Algorithm.AES_256_GCM, Algorithm.CHACHA20_POLY1305]
    )
    default_algorithm: Algorithm = Algorithm.AES_256_GCM
    
    # KDF parameters (minimum values)
    min_scrypt_n: int = 2 ** 14
    min_scrypt_r: int = 8
    min_scrypt_p: int = 1
    
    # Chunking
    force_chunking: bool = False
    min_chunk_size: int = DEFAULT_CHUNK_SIZE
    max_chunk_size: int = MAX_CHUNK_SIZE
    
    # Compression
    allow_compression: bool = True
    default_compression: CompressionType = CompressionType.NONE
    
    # Audit
    paranoid_mode: bool = False
    log_plaintext_hash: bool = False
    
    # Locked settings (cannot be changed by user)
    locked_settings: List[str] = field(default_factory=list)


@dataclass
class AppConfig:
    """Application configuration."""
    profile: ProfileType = ProfileType.PERSONAL
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    
    # Defaults
    default_output_dir: Optional[str] = None
    confirm_overwrite: bool = True
    show_progress: bool = True
    
    # Batch
    max_workers: int = DEFAULT_MAX_WORKERS
    continue_on_error: bool = True
    
    # Audit
    audit_log_path: Optional[str] = None
    audit_max_size: int = DEFAULT_AUDIT_MAX_SIZE
    
    # Keyring
    keyring_path: Optional[str] = None
    auto_lock_timeout: int = 300  # seconds


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES - AUDIT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEvent:
    """Audit log event."""
    timestamp: str
    user: str
    host: str
    operation: OperationType
    status: str  # success, failed, etc.
    src_path: str
    dst_path: Optional[str] = None
    algorithm: Optional[str] = None
    kdf_params: Optional[Dict[str, Any]] = None
    ciphertext_sha256: Optional[str] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None
    file_count: Optional[int] = None
    total_bytes: Optional[int] = None
    
    def to_json(self) -> str:
        """Serialize to JSON line."""
        import json
        from dataclasses import asdict
        data = {k: v for k, v in asdict(self).items() if v is not None}
        data["operation"] = self.operation.value
        return json.dumps(data, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_algorithm_info(algo: Algorithm) -> Dict[str, Any]:
    """Get information about an algorithm."""
    info = {
        Algorithm.AES_256_GCM: {
            "name": "AES-256-GCM",
            "display_name": "AES-256-GCM",
            "description": "Advanced Encryption Standard with Galois/Counter Mode",
            "key_size": 256,
            "nonce_size": 96,
            "tag_size": 128,
            "recommended": True,
        },
        Algorithm.CHACHA20_POLY1305: {
            "name": "ChaCha20-Poly1305",
            "display_name": "ChaCha20-Poly1305",
            "description": "ChaCha20 stream cipher with Poly1305 MAC",
            "key_size": 256,
            "nonce_size": 96,
            "tag_size": 128,
            "recommended": True,
        },
    }
    return info.get(algo, {})


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    size: float = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"
