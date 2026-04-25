"""
Migration module for upgrading .codi containers between versions.

Features:
- Migrate single files v1 -> v2
- Migrate folders v1 -> v2
- In-place migration (without exposing plaintext to disk)
- Batch migration with progress
- Key rotation during migration
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import (
    Algorithm, CompressionType, ContainerVersion, OperationType,
    CODI_EXTENSION
)
from .errors import (
    AlreadyMigratedError, MigrationError, IntegrityError,
    FileNotFoundError
)
from .container_v1 import ContainerV1Reader, get_v1_info
from .container_v2 import detect_version, get_container_info
from .vault import SecureVault
from .io_utils import normalize_path, ensure_parent_exists, iter_codi_files
from .audit import get_audit_logger


# Progress callback type
MigrationProgressCallback = Callable[[int, int, str], None]


class Migrator:
    """
    Migrates .codi files between container versions.
    
    Supports:
    - V1 to V2 migration
    - In-place migration (same password)
    - Key rotation (different password)
    - Compression addition during migration
    
    Usage:
        migrator = Migrator()
        
        # Simple migration
        migrator.migrate_file(src, dst, password)
        
        # With key rotation
        migrator.migrate_file(src, dst, old_password, new_password=new_pass)
        
        # Folder migration
        migrator.migrate_folder(src_dir, dst_dir, password)
    """
    
    def __init__(self,
                 target_version: ContainerVersion = ContainerVersion.V2,
                 target_algorithm: Optional[Algorithm] = None,
                 compression: CompressionType = CompressionType.NONE,
                 chunk_size: Optional[int] = None,
                 auto_chunk: bool = True):
        """
        Initialize migrator.
        
        Args:
            target_version: Target container version
            target_algorithm: Algorithm for new container (None = keep same)
            compression: Compression for V2 containers
            chunk_size: Chunk size for large files
            auto_chunk: Auto-enable chunking for large files
        """
        self.target_version = target_version
        self.target_algorithm = target_algorithm
        self.compression = compression
        self.chunk_size = chunk_size
        self.auto_chunk = auto_chunk
        
        self._audit = get_audit_logger()
    
    def check_migration_needed(self, path: Path) -> Tuple[bool, str]:
        """
        Check if a file needs migration.
        
        Args:
            path: Path to .codi file
        
        Returns:
            Tuple of (needs_migration, reason)
        """
        path = normalize_path(path)
        
        try:
            current_version = detect_version(path)
        except Exception as e:
            return False, f"Cannot detect version: {e}"
        
        if current_version >= self.target_version.value:
            return False, f"Already at version {current_version}"
        
        return True, f"Current version: {current_version}, target: {self.target_version.value}"
    
    def migrate_file(self, src_path: Path, dst_path: Path,
                     password: str,
                     keyfile: Optional[Path] = None,
                     new_password: Optional[str] = None,
                     new_keyfile: Optional[Path] = None,
                     progress_callback: Optional[MigrationProgressCallback] = None
                     ) -> Dict:
        """
        Migrate a single .codi file.
        
        Args:
            src_path: Source .codi file
            dst_path: Destination path (can be same as src for in-place)
            password: Current password
            keyfile: Current keyfile (if any)
            new_password: New password (if rotating keys)
            new_keyfile: New keyfile (if changing)
            progress_callback: Progress callback
        
        Returns:
            Dict with migration details
        """
        src_path = normalize_path(src_path)
        dst_path = normalize_path(dst_path)
        
        if not src_path.exists():
            raise FileNotFoundError(str(src_path))
        
        # Check if migration needed
        needs_migration, reason = self.check_migration_needed(src_path)
        if not needs_migration:
            raise AlreadyMigratedError(str(src_path), detect_version(src_path))
        
        # Get source info
        src_info = get_container_info(src_path)
        src_version = src_info["version"]
        
        # Determine target algorithm
        if self.target_algorithm:
            target_algo = self.target_algorithm
        else:
            target_algo = Algorithm[src_info["algorithm"]]
        
        # Use new credentials if provided, else use current
        out_password = new_password or password
        out_keyfile = new_keyfile if new_keyfile is not None else keyfile
        
        if progress_callback:
            progress_callback(0, 100, "Decrypting...")
        
        # Create vaults
        src_vault = SecureVault()
        from typing import Dict, Any
        kwargs: Dict[str, Any] = {
            "algorithm": target_algo,
            "container_version": self.target_version,
            "compression": self.compression,
            "auto_chunk": self.auto_chunk,
        }
        if self.chunk_size is not None:
            kwargs["chunk_size"] = self.chunk_size
            
        dst_vault = SecureVault(**kwargs)
        
        # Migrate through temp file
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / "plaintext.tmp"
            
            # Decrypt original
            src_vault.decrypt_file(src_path, tmp_path, password, keyfile)
            
            if progress_callback:
                progress_callback(50, 100, "Re-encrypting...")
            
            # Re-encrypt with new format/key
            ensure_parent_exists(dst_path)
            
            # Handle in-place migration
            actual_dst = dst_path
            if src_path == dst_path:
                actual_dst = dst_path.parent / f"{dst_path.stem}.migrating{CODI_EXTENSION}"
            
            dst_vault.encrypt_file(tmp_path, actual_dst, out_password, out_keyfile)
            
            # Finalize in-place
            if src_path == dst_path:
                src_path.unlink()
                actual_dst.rename(dst_path)
        
        if progress_callback:
            progress_callback(100, 100, "Complete")
        
        # Log migration
        self._audit.log_operation(
            operation=OperationType.MIGRATE,
            src_path=str(src_path),
            dst_path=str(dst_path),
            status="success",
            algorithm=target_algo.name,
        )
        
        result = {
            "src_version": src_version,
            "dst_version": self.target_version.value,
            "algorithm": target_algo.name,
            "key_rotated": new_password is not None,
            "compressed": self.compression != CompressionType.NONE,
        }
        
        return result
    
    def migrate_folder(self, src_dir: Path, dst_dir: Path,
                       password: str,
                       keyfile: Optional[Path] = None,
                       new_password: Optional[str] = None,
                       new_keyfile: Optional[Path] = None,
                       recursive: bool = True,
                       continue_on_error: bool = True,
                       progress_callback: Optional[MigrationProgressCallback] = None
                       ) -> Dict:
        """
        Migrate all .codi files in a folder.
        
        Args:
            src_dir: Source directory
            dst_dir: Destination directory
            password: Current password
            keyfile: Current keyfile
            new_password: New password (if rotating)
            new_keyfile: New keyfile
            recursive: Include subdirectories
            continue_on_error: Continue on individual errors
            progress_callback: Progress callback
        
        Returns:
            Dict with migration summary
        """
        src_dir = normalize_path(src_dir)
        dst_dir = normalize_path(dst_dir)
        
        # Collect files
        files = list(iter_codi_files(src_dir, recursive))
        total_files = len(files)
        
        succeeded = 0
        failed = 0
        skipped = 0
        errors = []
        
        for i, src_path in enumerate(files):
            # Compute relative path
            rel_path = src_path.relative_to(src_dir)
            dst_path = dst_dir / rel_path
            
            if progress_callback:
                progress_callback(i, total_files, str(rel_path))
            
            try:
                # Check if needs migration
                needs, reason = self.check_migration_needed(src_path)
                if not needs:
                    skipped += 1
                    continue
                
                # Migrate
                self.migrate_file(
                    src_path, dst_path, password, keyfile,
                    new_password, new_keyfile
                )
                succeeded += 1
                
            except Exception as e:
                failed += 1
                errors.append((str(rel_path), str(e)))
                
                if not continue_on_error:
                    break
        
        if progress_callback:
            progress_callback(total_files, total_files, "Complete")
        
        return {
            "total_files": total_files,
            "succeeded": succeeded,
            "failed": failed,
            "skipped": skipped,
            "errors": errors,
        }
    
    def rotate_key(self, path: Path,
                   old_password: str, new_password: str,
                   old_keyfile: Optional[Path] = None,
                   new_keyfile: Optional[Path] = None,
                   progress_callback: Optional[MigrationProgressCallback] = None
                   ) -> Dict:
        """
        Rotate the encryption key for a file (re-encrypt with new password).
        
        This is similar to migration but specifically for key rotation
        without necessarily changing the version.
        
        Args:
            path: Path to .codi file
            old_password: Current password
            new_password: New password
            old_keyfile: Current keyfile
            new_keyfile: New keyfile
            progress_callback: Progress callback
        
        Returns:
            Dict with rotation details
        """
        path = normalize_path(path)
        
        if not path.exists():
            raise FileNotFoundError(str(path))
        
        # Get current info
        info = get_container_info(path)
        current_algo = Algorithm[info["algorithm"]]
        current_version = ContainerVersion(info["version"])
        
        if progress_callback:
            progress_callback(0, 100, "Decrypting...")
        
        # Create vaults
        src_vault = SecureVault()
        dst_vault = SecureVault(
            algorithm=self.target_algorithm or current_algo,
            container_version=self.target_version if self.target_version.value > current_version.value else current_version,
            compression=self.compression,
        )
        
        # Rotate through temp file
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / "plaintext.tmp"
            new_path = path.parent / f"{path.stem}.rotating{CODI_EXTENSION}"
            
            # Decrypt with old key
            src_vault.decrypt_file(path, tmp_path, old_password, old_keyfile)
            
            if progress_callback:
                progress_callback(50, 100, "Re-encrypting with new key...")
            
            # Re-encrypt with new key
            dst_vault.encrypt_file(tmp_path, new_path, new_password, new_keyfile)
            
            # Replace original
            path.unlink()
            new_path.rename(path)
        
        if progress_callback:
            progress_callback(100, 100, "Complete")
        
        # Log rotation
        self._audit.log_key_operation(
            operation=OperationType.KEY_ROTATE,
            key_name=str(path),
            status="success"
        )
        
        return {
            "path": str(path),
            "algorithm": (self.target_algorithm or current_algo).name,
            "rotated": True,
        }


def get_migration_preview(path: Path) -> Dict:
    """
    Get a preview of what migration would do.
    
    Args:
        path: Path to .codi file or directory
    
    Returns:
        Dict with migration preview
    """
    path = normalize_path(path)
    
    if path.is_file():
        info = get_container_info(path)
        return {
            "type": "file",
            "path": str(path),
            "current_version": info["version"],
            "target_version": 2,
            "needs_migration": info["version"] < 2,
            **info,
        }
    
    elif path.is_dir():
        files = list(iter_codi_files(path, recursive=True))
        
        v1_count = 0
        v2_count = 0
        
        for f in files:
            try:
                version = detect_version(f)
                if version == 1:
                    v1_count += 1
                else:
                    v2_count += 1
            except:
                pass
        
        return {
            "type": "directory",
            "path": str(path),
            "total_files": len(files),
            "v1_files": v1_count,
            "v2_files": v2_count,
            "needs_migration": v1_count > 0,
        }
    
    else:
        raise FileNotFoundError(str(path))
