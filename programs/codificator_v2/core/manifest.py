"""
Folder manifest module for perfect restore support.

Features:
- Record file tree structure
- Store file metadata (sizes, hashes, timestamps)
- Encrypted manifest storage
- Verification during restore
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import version
from . import (
    Algorithm, FolderManifest, ManifestFileEntry,
    CODI_EXTENSION
)
from .errors import IntegrityError, ContainerFormatError
from .vault import SecureVault
from .io_utils import (
    normalize_path, ensure_parent_exists, compute_sha256,
    iter_files, FileFilter, get_file_times
)


MANIFEST_FILENAME = ".codificator_manifest.codi"
MANIFEST_VERSION = 1


class ManifestBuilder:
    """
    Builds a manifest for a folder encryption operation.
    
    The manifest records:
    - Original file tree structure
    - File sizes and hashes
    - Timestamps and permissions (optional)
    - Mapping from original paths to encrypted names
    
    Usage:
        builder = ManifestBuilder(src_dir, dst_dir)
        
        for src_path in files:
            dst_path = builder.add_file(src_path, ciphertext_sha256)
        
        manifest = builder.build()
        builder.save(password)
    """
    
    def __init__(self, src_dir: Path, dst_dir: Path,
                 algorithm: Algorithm = Algorithm.AES_256_GCM,
                 include_plaintext_hash: bool = False,
                 include_timestamps: bool = True):
        """
        Initialize manifest builder.
        
        Args:
            src_dir: Source directory being encrypted
            dst_dir: Destination directory for encrypted files
            algorithm: Encryption algorithm being used
            include_plaintext_hash: Include SHA-256 of plaintext (security consideration!)
            include_timestamps: Include file timestamps in manifest
        """
        self.src_dir = normalize_path(src_dir)
        self.dst_dir = normalize_path(dst_dir)
        self.algorithm = algorithm
        self.include_plaintext_hash = include_plaintext_hash
        self.include_timestamps = include_timestamps
        
        self._entries: List[ManifestFileEntry] = []
        self._total_size = 0
    
    def add_file(self, src_path: Path, dst_path: Path,
                 ciphertext_sha256: str) -> ManifestFileEntry:
        """
        Add a file to the manifest.
        
        Args:
            src_path: Original file path
            dst_path: Encrypted file path
            ciphertext_sha256: SHA-256 hash of encrypted file
        
        Returns:
            ManifestFileEntry for the file
        """
        src_path = normalize_path(src_path)
        dst_path = normalize_path(dst_path)
        
        # Get relative path from source root
        rel_path = str(src_path.relative_to(self.src_dir))
        
        # Get file info
        stat = src_path.stat()
        original_size = stat.st_size
        self._total_size += original_size
        
        # Compute plaintext hash if requested
        plaintext_sha256 = None
        if self.include_plaintext_hash:
            plaintext_sha256 = compute_sha256(src_path)
        
        # Get timestamps if requested
        created_time = None
        modified_time = None
        permissions = None
        
        if self.include_timestamps:
            times = get_file_times(src_path)
            created_time = times.get("created")
            modified_time = times.get("modified")
            
            # Get permissions on Unix
            if platform.system() != 'Windows':
                permissions = stat.st_mode & 0o777
        
        # Get encrypted filename (relative to dst_dir)
        encrypted_name = str(dst_path.relative_to(self.dst_dir))
        encrypted_size = dst_path.stat().st_size
        
        entry = ManifestFileEntry(
            relative_path=rel_path,
            original_size=original_size,
            encrypted_name=encrypted_name,
            encrypted_size=encrypted_size,
            plaintext_sha256=plaintext_sha256,
            ciphertext_sha256=ciphertext_sha256,
            permissions=permissions,
            created_time=created_time,
            modified_time=modified_time,
        )
        
        self._entries.append(entry)
        return entry
    
    def build(self) -> FolderManifest:
        """Build the final manifest."""
        return FolderManifest(
            version=MANIFEST_VERSION,
            created_at=datetime.utcnow().isoformat() + "Z",
            tool_version=f"{version.PROGRAM_NAME} v{version.__version__}",
            root_name=self.src_dir.name,
            algorithm=self.algorithm,
            total_files=len(self._entries),
            total_size=self._total_size,
            files=self._entries,
            include_plaintext_hash=self.include_plaintext_hash,
        )
    
    def save(self, manifest: FolderManifest, password: str,
             keyfile: Optional[Path] = None) -> Path:
        """
        Save and encrypt the manifest.
        
        Args:
            manifest: Manifest to save
            password: Password for encryption
            keyfile: Optional keyfile for 2FA
        
        Returns:
            Path to encrypted manifest file
        """
        # Serialize manifest
        manifest_json = manifest.to_json()
        
        # Write to temp file then encrypt
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(manifest_json)
            temp_path = Path(f.name)
        
        try:
            # Encrypt manifest
            manifest_path = self.dst_dir / MANIFEST_FILENAME
            
            vault = SecureVault(algorithm=self.algorithm)
            vault.encrypt_file(temp_path, manifest_path, password, keyfile,
                              include_filename=False)
            
            return manifest_path
        finally:
            # Clean up temp file
            try:
                temp_path.unlink()
            except:
                pass


class ManifestReader:
    """
    Reads and verifies a folder manifest.
    
    Usage:
        reader = ManifestReader(manifest_path)
        manifest = reader.load(password)
        
        for entry in manifest.files:
            reader.verify_file(entry, decrypted_path)
    """
    
    def __init__(self, manifest_path: Path):
        """
        Initialize manifest reader.
        
        Args:
            manifest_path: Path to encrypted manifest file
        """
        self.manifest_path = normalize_path(manifest_path)
        self._manifest: Optional[FolderManifest] = None
    
    def load(self, password: str, keyfile: Optional[Path] = None) -> FolderManifest:
        """
        Load and decrypt the manifest.
        
        Args:
            password: Password for decryption
            keyfile: Optional keyfile
        
        Returns:
            Loaded FolderManifest
        """
        import tempfile
        
        # Decrypt to temp file
        with tempfile.NamedTemporaryFile(mode='r', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            vault = SecureVault()
            vault.decrypt_file(self.manifest_path, temp_path, password, keyfile)
            
            # Read and parse
            manifest_json = temp_path.read_text(encoding='utf-8')
            self._manifest = FolderManifest.from_json(manifest_json)
            
            return self._manifest
        finally:
            try:
                temp_path.unlink()
            except:
                pass
    
    def verify_file(self, entry: ManifestFileEntry, 
                    decrypted_path: Path) -> Tuple[bool, List[str]]:
        """
        Verify a decrypted file against manifest entry.
        
        Args:
            entry: Manifest entry for the file
            decrypted_path: Path to decrypted file
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if not decrypted_path.exists():
            return False, ["File not found"]
        
        stat = decrypted_path.stat()
        
        # Verify size
        if stat.st_size != entry.original_size:
            issues.append(f"Size mismatch: expected {entry.original_size}, got {stat.st_size}")
        
        # Verify plaintext hash if available
        if entry.plaintext_sha256:
            actual_hash = compute_sha256(decrypted_path)
            if actual_hash != entry.plaintext_sha256:
                issues.append("Content hash mismatch")
        
        return len(issues) == 0, issues
    
    def verify_all(self, dst_dir: Path) -> Tuple[int, int, List[Tuple[str, List[str]]]]:
        """
        Verify all files in manifest against decrypted files.
        
        Args:
            dst_dir: Directory containing decrypted files
        
        Returns:
            Tuple of (verified_count, failed_count, failures)
            where failures is list of (path, issues)
        """
        if self._manifest is None:
            raise ValueError("Manifest not loaded")
        
        verified = 0
        failed = 0
        failures = []
        
        for entry in self._manifest.files:
            decrypted_path = dst_dir / entry.relative_path
            is_valid, issues = self.verify_file(entry, decrypted_path)
            
            if is_valid:
                verified += 1
            else:
                failed += 1
                failures.append((entry.relative_path, issues))
        
        return verified, failed, failures
    
    def get_file_list(self) -> List[str]:
        """Get list of files in manifest."""
        if self._manifest is None:
            raise ValueError("Manifest not loaded")
        return [e.relative_path for e in self._manifest.files]
    
    def get_info(self) -> Dict[str, Any]:
        """Get manifest information."""
        if self._manifest is None:
            raise ValueError("Manifest not loaded")
        
        return {
            "version": self._manifest.version,
            "created_at": self._manifest.created_at,
            "tool_version": self._manifest.tool_version,
            "root_name": self._manifest.root_name,
            "algorithm": self._manifest.algorithm.name,
            "total_files": self._manifest.total_files,
            "total_size": self._manifest.total_size,
            "include_plaintext_hash": self._manifest.include_plaintext_hash,
        }


def restore_timestamps(dst_path: Path, entry: ManifestFileEntry) -> None:
    """
    Restore file timestamps from manifest entry.
    
    Args:
        dst_path: Path to restored file
        entry: Manifest entry with timestamps
    """
    from .io_utils import set_file_times
    
    modified = None
    if entry.modified_time:
        try:
            dt = datetime.fromisoformat(entry.modified_time.replace("Z", "+00:00"))
            modified = dt.timestamp()
        except:
            pass
    
    if modified:
        set_file_times(dst_path, modified=modified)


def restore_permissions(dst_path: Path, entry: ManifestFileEntry) -> None:
    """
    Restore file permissions from manifest entry (Unix only).
    
    Args:
        dst_path: Path to restored file
        entry: Manifest entry with permissions
    """
    if entry.permissions is not None and platform.system() != 'Windows':
        try:
            os.chmod(dst_path, entry.permissions)
        except:
            pass
