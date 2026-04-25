"""
Audit logging module for compliance and security tracking.

Features:
- JSONL event logging
- Secret redaction (never logs passwords or keys)
- Paranoid mode (hash paths)
- Log rotation by size
- Query and filter events
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import (
    AuditEvent, OperationType,
    AUDIT_LOG_FILENAME, DEFAULT_AUDIT_MAX_SIZE
)
from .io_utils import normalize_path, ensure_parent_exists, atomic_write


def _get_username() -> str:
    """Get current username."""
    try:
        return getpass.getuser()
    except:
        return "unknown"


def _get_hostname() -> str:
    """Get current hostname."""
    try:
        return socket.gethostname()
    except:
        return "unknown"


def _hash_path(path: str) -> str:
    """Hash a path for paranoid mode."""
    return f"sha256:{hashlib.sha256(path.encode()).hexdigest()[:16]}"


class AuditLogger:
    """
    Audit logger with JSONL output.
    
    Security features:
    - Never logs passwords, keys, or plaintext content
    - Optional paranoid mode hashes file paths
    - Optional plaintext hash logging (disabled by default)
    
    Usage:
        logger = AuditLogger()
        logger.log_operation(
            OperationType.ENCRYPT_FILE,
            src_path="/path/to/file",
            status="success"
        )
    """
    
    def __init__(self, 
                 path: Optional[Path] = None,
                 paranoid: bool = False,
                 log_plaintext_hash: bool = False,
                 max_size: int = DEFAULT_AUDIT_MAX_SIZE,
                 enabled: bool = True):
        """
        Initialize audit logger.
        
        Args:
            path: Path to log file. If None, uses default location.
            paranoid: Hash all file paths in logs
            log_plaintext_hash: Include SHA-256 of plaintext (security risk!)
            max_size: Maximum log file size before rotation
            enabled: Enable/disable logging
        """
        if path is None:
            path = Path.home() / ".codificator" / AUDIT_LOG_FILENAME
        
        self.path = normalize_path(path)
        self.paranoid = paranoid
        self.log_plaintext_hash = log_plaintext_hash
        self.max_size = max_size
        self.enabled = enabled
        
        self._username = _get_username()
        self._hostname = _get_hostname()
    
    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        if not self.path.exists():
            return
        
        try:
            size = self.path.stat().st_size
            if size > self.max_size:
                # Rotate: rename to .1, .2, etc.
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                rotated = self.path.parent / f"{self.path.stem}_{timestamp}{self.path.suffix}"
                self.path.rename(rotated)
        except:
            pass
    
    def _sanitize_path(self, path: Optional[str]) -> Optional[str]:
        """Sanitize path based on paranoid mode."""
        if path is None:
            return None
        if self.paranoid:
            return _hash_path(path)
        return path
    
    def _write_event(self, event: AuditEvent) -> None:
        """Write event to log file."""
        if not self.enabled:
            return
        
        try:
            self._rotate_if_needed()
            ensure_parent_exists(self.path)
            
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write(event.to_json() + '\n')
        except:
            pass  # Audit logging should never break the app
    
    def log_operation(self,
                      operation: OperationType,
                      src_path: Optional[str] = None,
                      dst_path: Optional[str] = None,
                      status: str = "success",
                      algorithm: Optional[str] = None,
                      kdf_params: Optional[Dict[str, Any]] = None,
                      ciphertext_sha256: Optional[str] = None,
                      plaintext_sha256: Optional[str] = None,
                      error_code: Optional[int] = None,
                      error_message: Optional[str] = None,
                      duration_ms: Optional[int] = None,
                      file_count: Optional[int] = None,
                      total_bytes: Optional[int] = None) -> None:
        """
        Log an operation.
        
        Args:
            operation: Type of operation
            src_path: Source file/folder path
            dst_path: Destination path
            status: Operation status (success, failed, etc.)
            algorithm: Encryption algorithm used
            kdf_params: KDF parameters (without salt)
            ciphertext_sha256: Hash of ciphertext
            plaintext_sha256: Hash of plaintext (only if log_plaintext_hash=True)
            error_code: Error code if failed
            error_message: Error message if failed
            duration_ms: Operation duration in milliseconds
            file_count: Number of files processed (for batch)
            total_bytes: Total bytes processed
        """
        # Redact plaintext hash unless explicitly enabled
        if not self.log_plaintext_hash:
            plaintext_sha256 = None
        
        # Sanitize KDF params (remove salt)
        if kdf_params:
            kdf_params = {k: v for k, v in kdf_params.items() 
                         if k not in ('salt', 'key', 'password')}
        
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            user=self._username,
            host=self._hostname,
            operation=operation,
            status=status,
            src_path=self._sanitize_path(src_path) or "",
            dst_path=self._sanitize_path(dst_path),
            algorithm=algorithm,
            kdf_params=kdf_params,
            ciphertext_sha256=ciphertext_sha256,
            error_code=error_code,
            error_message=error_message,
            duration_ms=duration_ms,
            file_count=file_count,
            total_bytes=total_bytes,
        )
        
        self._write_event(event)
    
    def log_batch_start(self, operation: OperationType,
                        src_path: str, dst_path: str,
                        total_files: int) -> str:
        """
        Log the start of a batch operation.
        
        Returns:
            Operation ID for correlation
        """
        import uuid
        op_id = str(uuid.uuid4())[:8]
        
        self.log_operation(
            operation=operation,
            src_path=src_path,
            dst_path=dst_path,
            status="started",
            file_count=total_files,
        )
        
        return op_id
    
    def log_batch_end(self, operation: OperationType,
                      src_path: str, dst_path: str,
                      succeeded: int, failed: int,
                      duration_ms: int) -> None:
        """Log the end of a batch operation."""
        status = "success" if failed == 0 else "partial" if succeeded > 0 else "failed"
        
        self.log_operation(
            operation=operation,
            src_path=src_path,
            dst_path=dst_path,
            status=status,
            file_count=succeeded + failed,
            duration_ms=duration_ms,
            error_message=f"{failed} failures" if failed > 0 else None,
        )
    
    def log_key_operation(self, operation: OperationType,
                          key_name: str,
                          status: str = "success",
                          error_message: Optional[str] = None) -> None:
        """Log a keyring operation."""
        # Hash key name in paranoid mode
        name = _hash_path(key_name) if self.paranoid else key_name
        
        self.log_operation(
            operation=operation,
            src_path=f"keyring:{name}",
            status=status,
            error_message=error_message,
        )
    
    def read_events(self, 
                    limit: int = 100,
                    operation_filter: Optional[OperationType] = None,
                    status_filter: Optional[str] = None,
                    since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Read events from log file.
        
        Args:
            limit: Maximum events to return
            operation_filter: Filter by operation type
            status_filter: Filter by status
            since: Only events after this time
        
        Returns:
            List of event dictionaries (newest first)
        """
        if not self.path.exists():
            return []
        
        events = []
        
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Apply filters
                        if operation_filter and event.get("operation") != operation_filter.value:
                            continue
                        if status_filter and event.get("status") != status_filter:
                            continue
                        if since:
                            event_time = datetime.fromisoformat(
                                event["timestamp"].replace("Z", "+00:00")
                            )
                            if event_time < since:
                                continue
                        
                        events.append(event)
                    except:
                        continue
        except:
            return []
        
        # Return newest first, limited
        events.reverse()
        return events[:limit]
    
    def clear(self) -> None:
        """Clear all audit logs."""
        try:
            if self.path.exists():
                self.path.unlink()
        except:
            pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        events = self.read_events(limit=10000)
        
        if not events:
            return {
                "total_events": 0,
                "operations": {},
                "statuses": {},
            }
        
        operations: Dict[str, int] = {}
        statuses: Dict[str, int] = {}
        
        for event in events:
            op = event.get("operation", "unknown")
            operations[op] = operations.get(op, 0) + 1
            
            status = event.get("status", "unknown")
            statuses[status] = statuses.get(status, 0) + 1
        
        return {
            "total_events": len(events),
            "operations": operations,
            "statuses": statuses,
            "log_size": self.path.stat().st_size if self.path.exists() else 0,
        }


# Global logger instance
_global_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _global_logger
    if _global_logger is None:
        _global_logger = AuditLogger()
    return _global_logger


def configure_audit_logger(path: Optional[Path] = None,
                           paranoid: bool = False,
                           log_plaintext_hash: bool = False,
                           max_size: int = DEFAULT_AUDIT_MAX_SIZE,
                           enabled: bool = True) -> AuditLogger:
    """Configure and return the global audit logger."""
    global _global_logger
    _global_logger = AuditLogger(
        path=path,
        paranoid=paranoid,
        log_plaintext_hash=log_plaintext_hash,
        max_size=max_size,
        enabled=enabled,
    )
    return _global_logger
