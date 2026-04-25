"""
Batch operations module for folder encryption/decryption.

Features:
- Recursive folder processing
- Include/exclude filters
- Dry-run mode
- Checkpoint/resume for interrupted operations
- Multi-threaded processing
- Progress reporting
"""

from __future__ import annotations

import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Callable, Dict, List, Optional, Tuple

from . import (
    Algorithm, OperationType, BatchStatus,
    BatchProgress, BatchCheckpoint, FileTask,
    CODI_EXTENSION, CHECKPOINT_EXTENSION, DEFAULT_MAX_WORKERS
)
from .errors import BatchInterruptedError, BatchPartialError
from .vault import SecureVault
from .io_utils import (
    normalize_path, ensure_parent_exists, atomic_write,
    FileFilter, iter_files, iter_codi_files
)


# Progress callback type
BatchProgressCallback = Callable[[BatchProgress], None]


class BatchProcessor:
    """
    Process folders for encryption/decryption.
    
    Features:
    - Multi-threaded processing
    - Checkpoint/resume support
    - Progress tracking
    - Continue on error option
    
    Usage:
        processor = BatchProcessor(vault)
        
        # With progress callback
        def on_progress(progress):
            print(f"{progress.processed_files}/{progress.total_files}")
        
        result = processor.encrypt_folder(
            src_dir, dst_dir, password,
            progress_callback=on_progress
        )
    """
    
    def __init__(self, vault: SecureVault, 
                 file_filter: Optional[FileFilter] = None,
                 max_workers: int = DEFAULT_MAX_WORKERS):
        """
        Initialize batch processor.
        
        Args:
            vault: SecureVault instance for crypto operations
            file_filter: Optional filter for file selection
            max_workers: Maximum concurrent workers
        """
        self.vault = vault
        self.filter = file_filter or FileFilter()
        self.max_workers = max_workers
        
        self._progress = BatchProgress()
        self._progress_lock = Lock()
        self._cancelled = False
    
    def cancel(self) -> None:
        """Cancel the current operation."""
        self._cancelled = True
    
    def _update_progress(self, **kwargs) -> None:
        """Thread-safe progress update."""
        with self._progress_lock:
            for key, value in kwargs.items():
                setattr(self._progress, key, value)
    
    def _compute_dst_path(self, src_path: Path, src_dir: Path,
                          dst_dir: Path, encrypt: bool = True) -> Path:
        """Compute destination path preserving directory structure."""
        rel_path = src_path.relative_to(src_dir)
        
        if encrypt:
            dst_path = dst_dir / (str(rel_path) + CODI_EXTENSION)
        else:
            # Remove .codi extension
            if str(rel_path).endswith(CODI_EXTENSION):
                new_name = str(rel_path)[:-len(CODI_EXTENSION)]
                dst_path = dst_dir / new_name
            else:
                dst_path = dst_dir / rel_path
        
        return dst_path
    
    def encrypt_folder(self, src_dir: Path, dst_dir: Path, password: str,
                       keyfile: Optional[Path] = None,
                       recursive: bool = True,
                       dry_run: bool = False,
                       continue_on_error: bool = True,
                       checkpoint_path: Optional[Path] = None,
                       progress_callback: Optional[BatchProgressCallback] = None
                       ) -> BatchProgress:
        """
        Encrypt all matching files in a folder.
        
        Args:
            src_dir: Source directory
            dst_dir: Destination directory
            password: Encryption password
            keyfile: Optional keyfile for 2FA
            recursive: Include subdirectories
            dry_run: Preview without executing
            continue_on_error: Continue on individual file errors
            checkpoint_path: Path for checkpoint file (for resume)
            progress_callback: Progress callback function
        
        Returns:
            BatchProgress with results
        """
        src_dir = normalize_path(src_dir)
        dst_dir = normalize_path(dst_dir)
        
        if not src_dir.is_dir():
            raise ValueError(f"Source is not a directory: {src_dir}")
        
        # Initialize progress
        self._progress = BatchProgress(status=BatchStatus.RUNNING)
        self._cancelled = False
        
        # Collect files
        files = list(iter_files(src_dir, recursive, self.filter))
        self._progress.total_files = len(files)
        self._progress.total_bytes = sum(f.stat().st_size for f in files)
        
        # Load checkpoint if exists
        completed_files = set()
        if checkpoint_path and checkpoint_path.exists():
            checkpoint = self._load_checkpoint(checkpoint_path)
            completed_files = set(checkpoint.processed_files)
        
        # Create tasks
        tasks = []
        for src_path in files:
            if str(src_path) in completed_files:
                self._progress.skipped_files += 1
                continue
            
            dst_path = self._compute_dst_path(src_path, src_dir, dst_dir, encrypt=True)
            tasks.append(FileTask(
                src_path=src_path,
                dst_path=dst_path,
                size_bytes=src_path.stat().st_size
            ))
        
        if dry_run:
            # Just return what would be done
            self._progress.status = BatchStatus.COMPLETED
            for task in tasks:
                self._progress.processed_files += 1
                self._progress.succeeded_files += 1
            return self._progress
        
        # Process files
        result = self._process_files(
            tasks, password, keyfile, encrypt=True,
            continue_on_error=continue_on_error,
            checkpoint_path=checkpoint_path,
            src_dir=src_dir, dst_dir=dst_dir,
            progress_callback=progress_callback
        )
        
        return result
    
    def decrypt_folder(self, src_dir: Path, dst_dir: Path, password: str,
                       keyfile: Optional[Path] = None,
                       recursive: bool = True,
                       dry_run: bool = False,
                       continue_on_error: bool = True,
                       checkpoint_path: Optional[Path] = None,
                       progress_callback: Optional[BatchProgressCallback] = None
                       ) -> BatchProgress:
        """
        Decrypt all .codi files in a folder.
        
        Args:
            src_dir: Source directory with .codi files
            dst_dir: Destination directory
            password: Decryption password
            keyfile: Optional keyfile
            recursive: Include subdirectories
            dry_run: Preview without executing
            continue_on_error: Continue on errors
            checkpoint_path: Checkpoint file path
            progress_callback: Progress callback
        
        Returns:
            BatchProgress with results
        """
        src_dir = normalize_path(src_dir)
        dst_dir = normalize_path(dst_dir)
        
        if not src_dir.is_dir():
            raise ValueError(f"Source is not a directory: {src_dir}")
        
        # Initialize progress
        self._progress = BatchProgress(status=BatchStatus.RUNNING)
        self._cancelled = False
        
        # Collect .codi files
        files = list(iter_codi_files(src_dir, recursive))
        self._progress.total_files = len(files)
        self._progress.total_bytes = sum(f.stat().st_size for f in files)
        
        # Load checkpoint
        completed_files = set()
        if checkpoint_path and checkpoint_path.exists():
            checkpoint = self._load_checkpoint(checkpoint_path)
            completed_files = set(checkpoint.processed_files)
        
        # Create tasks
        tasks = []
        for src_path in files:
            if str(src_path) in completed_files:
                self._progress.skipped_files += 1
                continue
            
            dst_path = self._compute_dst_path(src_path, src_dir, dst_dir, encrypt=False)
            tasks.append(FileTask(
                src_path=src_path,
                dst_path=dst_path,
                size_bytes=src_path.stat().st_size
            ))
        
        if dry_run:
            self._progress.status = BatchStatus.COMPLETED
            for task in tasks:
                self._progress.processed_files += 1
                self._progress.succeeded_files += 1
            return self._progress
        
        # Process files
        result = self._process_files(
            tasks, password, keyfile, encrypt=False,
            continue_on_error=continue_on_error,
            checkpoint_path=checkpoint_path,
            src_dir=src_dir, dst_dir=dst_dir,
            progress_callback=progress_callback
        )
        
        return result
    
    def _process_files(self, tasks: List[FileTask], password: str,
                       keyfile: Optional[Path], encrypt: bool,
                       continue_on_error: bool,
                       checkpoint_path: Optional[Path],
                       src_dir: Path, dst_dir: Path,
                       progress_callback: Optional[BatchProgressCallback]
                       ) -> BatchProgress:
        """Process files with multi-threading."""
        processed_files = []
        
        # Create checkpoint
        checkpoint = BatchCheckpoint(
            operation_id=str(uuid.uuid4()),
            operation_type=OperationType.ENCRYPT_FOLDER if encrypt else OperationType.DECRYPT_FOLDER,
            src_path=str(src_dir),
            dst_path=str(dst_dir),
            password_hash=hashlib.sha256(password.encode()).hexdigest()[:16],
            algorithm=self.vault.algorithm,
            total_files=len(tasks),
            processed_files=[],
            failed_files=[],
            created_at=datetime.utcnow().isoformat() + "Z",
            updated_at=datetime.utcnow().isoformat() + "Z",
        )
        
        def process_task(task: FileTask) -> Tuple[FileTask, Optional[str]]:
            """Process a single file task."""
            if self._cancelled:
                return task, "Cancelled"
            
            try:
                ensure_parent_exists(task.dst_path)
                
                if encrypt:
                    self.vault.encrypt_file(
                        task.src_path, task.dst_path, password, keyfile
                    )
                else:
                    self.vault.decrypt_file(
                        task.src_path, task.dst_path, password, keyfile
                    )
                
                task.status = BatchStatus.COMPLETED
                return task, None
                
            except Exception as e:
                task.status = BatchStatus.FAILED
                task.error = str(e)
                return task, str(e)
        
        # Process with thread pool
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(process_task, task): task for task in tasks}
            
            for future in as_completed(futures):
                task, error = future.result()
                
                with self._progress_lock:
                    self._progress.processed_files += 1
                    self._progress.processed_bytes += task.size_bytes
                    self._progress.current_file = str(task.src_path)
                    
                    if error:
                        self._progress.failed_files += 1
                        self._progress.errors.append((str(task.src_path), error))
                        checkpoint.failed_files.append((str(task.src_path), error))
                    else:
                        self._progress.succeeded_files += 1
                        processed_files.append(str(task.src_path))
                        checkpoint.processed_files.append(str(task.src_path))
                
                # Save checkpoint periodically
                if checkpoint_path and self._progress.processed_files % 10 == 0:
                    checkpoint.updated_at = datetime.utcnow().isoformat() + "Z"
                    self._save_checkpoint(checkpoint, checkpoint_path)
                
                # Report progress
                if progress_callback:
                    progress_callback(self._progress)
                
                # Check if cancelled or should stop on error
                if self._cancelled:
                    self._progress.status = BatchStatus.INTERRUPTED
                    break
                
                if error and not continue_on_error:
                    self._progress.status = BatchStatus.FAILED
                    break
        
        # Final status
        if self._cancelled:
            self._progress.status = BatchStatus.INTERRUPTED
        elif self._progress.failed_files > 0:
            self._progress.status = BatchStatus.PARTIAL
        else:
            self._progress.status = BatchStatus.COMPLETED
        
        # Cleanup checkpoint on success
        if checkpoint_path and self._progress.status == BatchStatus.COMPLETED:
            try:
                checkpoint_path.unlink()
            except:
                pass
        
        return self._progress
    
    def _save_checkpoint(self, checkpoint: BatchCheckpoint, path: Path) -> None:
        """Save checkpoint to file."""
        from dataclasses import asdict
        
        data = asdict(checkpoint)
        data["operation_type"] = checkpoint.operation_type.value
        data["algorithm"] = checkpoint.algorithm.value
        
        with atomic_write(path) as f:
            f.write(json.dumps(data, indent=2).encode())
    
    def _load_checkpoint(self, path: Path) -> BatchCheckpoint:
        """Load checkpoint from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        
        return BatchCheckpoint(
            operation_id=data["operation_id"],
            operation_type=OperationType(data["operation_type"]),
            src_path=data["src_path"],
            dst_path=data["dst_path"],
            password_hash=data["password_hash"],
            algorithm=Algorithm(data["algorithm"]),
            total_files=data["total_files"],
            processed_files=data["processed_files"],
            failed_files=[tuple(f) for f in data["failed_files"]],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


def format_batch_progress(progress: BatchProgress, verbose: bool = False) -> str:
    """Format batch progress for display."""
    lines = []
    
    status_emoji = {
        BatchStatus.PENDING: "⏳",
        BatchStatus.RUNNING: "🔄",
        BatchStatus.COMPLETED: "✅",
        BatchStatus.FAILED: "❌",
        BatchStatus.INTERRUPTED: "⚠️",
        BatchStatus.PARTIAL: "⚡",
    }
    
    lines.append(f"{status_emoji.get(progress.status, '❓')} Status: {progress.status.value}")
    lines.append(f"Files: {progress.processed_files}/{progress.total_files}")
    lines.append(f"  Succeeded: {progress.succeeded_files}")
    lines.append(f"  Failed: {progress.failed_files}")
    lines.append(f"  Skipped: {progress.skipped_files}")
    
    from . import format_size
    lines.append(f"Size: {format_size(progress.processed_bytes)}/{format_size(progress.total_bytes)}")
    
    if verbose and progress.errors:
        lines.append("")
        lines.append("Errors:")
        for path, error in progress.errors[:10]:
            lines.append(f"  • {Path(path).name}: {error}")
        if len(progress.errors) > 10:
            lines.append(f"  ... and {len(progress.errors) - 10} more")
    
    return '\n'.join(lines)
