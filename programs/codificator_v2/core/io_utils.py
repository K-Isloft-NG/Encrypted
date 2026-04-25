"""
I/O utilities for safe file operations.

Features:
- Atomic writes (temp file + rename)
- File locking (cross-platform)
- Path normalization for Windows
- Filter utilities for batch operations
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import platform
import shutil
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Callable, Generator, List, Optional, Set

from .errors import (
    FileNotFoundError, FileExistsError, DirectoryNotFoundError,
    PermissionDeniedError, FileLockError, DiskFullError
)


# ══════════════════════════════════════════════════════════════════════════════
# PATH UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def normalize_path(path: str | Path) -> Path:
    """
    Normalize path for cross-platform compatibility.
    
    - Resolves ~ to home directory
    - Normalizes separators
    - Handles Windows long paths
    
    Args:
        path: Path string or Path object
    
    Returns:
        Normalized Path object
    """
    p = Path(path).expanduser()
    
    # On Windows, handle long paths
    if platform.system() == 'Windows':
        # Convert to absolute path
        p = p.resolve()
        
        # Add long path prefix if needed
        str_path = str(p)
        if len(str_path) > 260 and not str_path.startswith('\\\\?\\'):
            p = Path('\\\\?\\' + str_path)
    
    return p


def safe_path_join(base: Path, *parts: str) -> Path:
    """
    Safely join path parts, preventing path traversal attacks.
    
    Args:
        base: Base path
        *parts: Path parts to join
    
    Returns:
        Joined path that is guaranteed to be under base
    
    Raises:
        ValueError: If resulting path escapes base
    """
    result = base
    for part in parts:
        # Normalize and remove any traversal attempts
        clean_part = part.replace('..', '').lstrip('/\\')
        result = result / clean_part
    
    # Verify result is under base
    try:
        result.resolve().relative_to(base.resolve())
    except ValueError:
        raise ValueError(f"Path traversal detected: {'/'.join(parts)}")
    
    return result


def ensure_parent_exists(path: Path) -> None:
    """Create parent directories if they don't exist."""
    path.parent.mkdir(parents=True, exist_ok=True)


def get_unique_path(path: Path) -> Path:
    """
    Get a unique path by appending a number if file exists.
    
    Args:
        path: Desired path
    
    Returns:
        Unique path (original or with suffix like .1, .2, etc.)
    """
    if not path.exists():
        return path
    
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    
    counter = 1
    while True:
        new_path = parent / f"{stem}.{counter}{suffix}"
        if not new_path.exists():
            return new_path
        counter += 1
        if counter > 10000:
            raise FileExistsError(str(path))


# ══════════════════════════════════════════════════════════════════════════════
# FILE LOCKING
# ══════════════════════════════════════════════════════════════════════════════

class FileLock:
    """
    Cross-platform file locking.
    
    Uses:
    - fcntl.flock() on Unix
    - msvcrt.locking() on Windows
    
    Usage:
        with FileLock(path):
            # Exclusive access to file
            ...
    """
    
    def __init__(self, path: Path, timeout: float = 10.0):
        """
        Initialize file lock.
        
        Args:
            path: Path to file to lock
            timeout: Timeout in seconds
        """
        self.path = normalize_path(path)
        self.timeout = timeout
        self._lock_path = self.path.parent / f".{self.path.name}.lock"
        self._lock_file: Optional[BinaryIO] = None
    
    def acquire(self) -> None:
        """Acquire the lock."""
        start_time = time.time()
        
        while True:
            try:
                # Create lock file exclusively
                self._lock_file = open(self._lock_path, 'xb')
                
                # Write PID for debugging
                self._lock_file.write(str(os.getpid()).encode())
                self._lock_file.flush()
                return
                
            except OSError:
                # Lock file exists, wait and retry
                if time.time() - start_time > self.timeout:
                    raise FileLockError(str(self.path))
                time.sleep(0.1)
    
    def release(self) -> None:
        """Release the lock."""
        if self._lock_file:
            try:
                self._lock_file.close()
            except:
                pass
            
            try:
                self._lock_path.unlink()
            except:
                pass
            
            self._lock_file = None
    
    def __enter__(self) -> 'FileLock':
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


@contextmanager
def file_lock(path: Path, timeout: float = 10.0):
    """Context manager for file locking."""
    lock = FileLock(path, timeout)
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()


# ══════════════════════════════════════════════════════════════════════════════
# ATOMIC WRITES
# ══════════════════════════════════════════════════════════════════════════════

class AtomicWriter:
    """
    Atomic file writer using temp file + rename.
    
    Ensures file is either fully written or not at all,
    preventing corruption from crashes/interrupts.
    
    Usage:
        with AtomicWriter(path) as f:
            f.write(data)
        # File only appears at path after successful close
    """
    
    def __init__(self, path: Path, mode: str = 'wb'):
        """
        Initialize atomic writer.
        
        Args:
            path: Final destination path
            mode: File mode ('wb' or 'w')
        """
        self.path = normalize_path(path)
        self.mode = mode
        self._temp_path: Optional[Path] = None
        self._file: Optional[BinaryIO] = None
    
    def __enter__(self) -> BinaryIO:
        # Create temp file in same directory (for atomic rename)
        ensure_parent_exists(self.path)
        
        fd, temp_path = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp"
        )
        self._temp_path = Path(temp_path)
        
        # Convert fd to file object
        import typing
        file_obj = typing.cast(BinaryIO, os.fdopen(fd, self.mode))
        self._file = file_obj
        return file_obj
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._file:
            try:
                self._file.close()
            except:
                pass
        
        if exc_type is None and self._temp_path:
            # Success - atomic rename
            try:
                # On Windows, we may need to remove existing file first
                if platform.system() == 'Windows' and self.path.exists():
                    self.path.unlink()
                
                self._temp_path.rename(self.path)
            except OSError as e:
                # Cleanup temp on failure
                try:
                    self._temp_path.unlink()
                except:
                    pass
                raise
        elif self._temp_path:
            # Error - cleanup temp
            try:
                self._temp_path.unlink()
            except:
                pass


@contextmanager
def atomic_write(path: Path, mode: str = 'wb'):
    """Context manager for atomic writes."""
    writer = AtomicWriter(path, mode)
    with writer as f:
        yield f


# ══════════════════════════════════════════════════════════════════════════════
# STREAMING / CHUNKED I/O
# ══════════════════════════════════════════════════════════════════════════════

def read_chunks(path: Path, chunk_size: int) -> Generator[bytes, None, None]:
    """
    Read file in chunks.
    
    Args:
        path: Path to file
        chunk_size: Size of each chunk
    
    Yields:
        Chunks of data
    """
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def copy_with_progress(src: Path, dst: Path, 
                       callback: Optional[Callable[[int, int], None]] = None,
                       chunk_size: int = 1024 * 1024) -> None:
    """
    Copy file with progress callback.
    
    Args:
        src: Source path
        dst: Destination path
        callback: Progress callback(bytes_copied, total_bytes)
        chunk_size: Copy chunk size
    """
    total_size = src.stat().st_size
    copied = 0
    
    ensure_parent_exists(dst)
    
    with open(src, 'rb') as fsrc, open(dst, 'wb') as fdst:
        while True:
            chunk = fsrc.read(chunk_size)
            if not chunk:
                break
            fdst.write(chunk)
            copied += len(chunk)
            if callback:
                callback(copied, total_size)


# ══════════════════════════════════════════════════════════════════════════════
# HASHING
# ══════════════════════════════════════════════════════════════════════════════

def compute_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Compute SHA-256 hash of a file.
    
    Args:
        path: Path to file
        chunk_size: Read chunk size
    
    Returns:
        Hex-encoded SHA-256 hash
    """
    hasher = hashlib.sha256()
    
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    
    return hasher.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_path(path: str) -> str:
    """Hash a path for paranoid audit logging."""
    return f"sha256:{hashlib.sha256(path.encode()).hexdigest()[:16]}"


# ══════════════════════════════════════════════════════════════════════════════
# FILE FILTERS
# ══════════════════════════════════════════════════════════════════════════════

class FileFilter:
    """
    Filter for batch file operations.
    
    Supports:
    - Include patterns (*.txt, *.json)
    - Exclude patterns (node_modules, *.tmp)
    - Size limits
    """
    
    def __init__(self,
                 include_patterns: Optional[List[str]] = None,
                 exclude_patterns: Optional[List[str]] = None,
                 min_size: Optional[int] = None,
                 max_size: Optional[int] = None,
                 exclude_hidden: bool = True):
        """
        Initialize filter.
        
        Args:
            include_patterns: Glob patterns to include (if specified, only these match)
            exclude_patterns: Glob patterns to exclude
            min_size: Minimum file size in bytes
            max_size: Maximum file size in bytes
            exclude_hidden: Exclude hidden files (starting with .)
        """
        self.include_patterns = include_patterns or []
        self.exclude_patterns = exclude_patterns or []
        self.min_size = min_size
        self.max_size = max_size
        self.exclude_hidden = exclude_hidden
    
    def matches(self, path: Path, size: Optional[int] = None) -> bool:
        """
        Check if file matches filter criteria.
        
        Args:
            path: File path
            size: File size (will be read if not provided)
        
        Returns:
            True if file should be included
        """
        name = path.name
        str_path = str(path)
        
        # Check hidden
        if self.exclude_hidden and name.startswith('.'):
            return False
        
        # Check size
        if size is None:
            try:
                size = path.stat().st_size
            except:
                return False
        
        if self.min_size is not None and size < self.min_size:
            return False
        if self.max_size is not None and size > self.max_size:
            return False
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(name, pattern):
                return False
            if fnmatch.fnmatch(str_path, f"*{pattern}*"):
                return False
        
        # Check include patterns (if specified, at least one must match)
        if self.include_patterns:
            for pattern in self.include_patterns:
                if fnmatch.fnmatch(name, pattern):
                    return True
            return False
        
        return True


def iter_files(directory: Path, 
               recursive: bool = True,
               file_filter: Optional[FileFilter] = None,
               skip_codi: bool = True) -> Generator[Path, None, None]:
    """
    Iterate over files in directory.
    
    Args:
        directory: Directory to iterate
        recursive: Include subdirectories
        file_filter: Optional filter
        skip_codi: Skip .codi files (for encryption)
    
    Yields:
        Path objects for matching files
    """
    from . import CODI_EXTENSION
    
    if file_filter is None:
        file_filter = FileFilter()
    
    pattern = "**/*" if recursive else "*"
    
    for path in directory.glob(pattern):
        if not path.is_file():
            continue
        
        # Skip .codi files if requested
        if skip_codi and path.suffix == CODI_EXTENSION:
            continue
        
        # Apply filter
        try:
            size = path.stat().st_size
            if file_filter.matches(path, size):
                yield path
        except (OSError, PermissionError):
            continue


def iter_codi_files(directory: Path, 
                    recursive: bool = True) -> Generator[Path, None, None]:
    """
    Iterate over .codi files in directory.
    
    Args:
        directory: Directory to iterate
        recursive: Include subdirectories
    
    Yields:
        Path objects for .codi files
    """
    from . import CODI_EXTENSION
    
    pattern = f"**/*{CODI_EXTENSION}" if recursive else f"*{CODI_EXTENSION}"
    
    for path in directory.glob(pattern):
        if path.is_file():
            yield path


# ══════════════════════════════════════════════════════════════════════════════
# SAFE OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def safe_delete(path: Path, secure: bool = False) -> bool:
    """
    Safely delete a file.
    
    Args:
        path: Path to delete
        secure: If True, overwrite with random data first (slow)
    
    Returns:
        True if deleted, False if didn't exist
    """
    if not path.exists():
        return False
    
    if secure and path.is_file():
        # Overwrite with random data
        try:
            size = path.stat().st_size
            with open(path, 'r+b') as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        except:
            pass
    
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    except:
        return False


def get_file_times(path: Path) -> dict:
    """
    Get file timestamps.
    
    Returns:
        Dict with 'created', 'modified', 'accessed' times as ISO strings
    """
    from datetime import datetime
    
    stat = path.stat()
    
    result = {
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
    }
    
    # Created time is platform-specific
    if hasattr(stat, 'st_birthtime'):
        # macOS
        result['created'] = datetime.fromtimestamp(getattr(stat, 'st_birthtime')).isoformat()
    elif platform.system() == 'Windows':
        # Windows
        result['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
    else:
        # Linux - st_ctime is "change time", not creation
        result['created'] = result['modified']
    
    return result


def set_file_times(path: Path, modified: Optional[float] = None, 
                   accessed: Optional[float] = None) -> None:
    """
    Set file timestamps.
    
    Args:
        path: File path
        modified: Modified time as timestamp (or None to keep)
        accessed: Accessed time as timestamp (or None to keep)
    """
    stat = path.stat()
    
    atime = accessed if accessed is not None else stat.st_atime
    mtime = modified if modified is not None else stat.st_mtime
    
    os.utime(path, (atime, mtime))
