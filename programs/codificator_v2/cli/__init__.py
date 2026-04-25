"""
Command-line interface for Codificator V2.

Provides stable CLI for automation and scripting.

Subcommands:
- encrypt-file: Encrypt a single file
- decrypt-file: Decrypt a single file
- encrypt-folder: Encrypt a folder
- decrypt-folder: Decrypt a folder
- verify: Verify a .codi file
- info: Show .codi file information
- keys: Key management (create, list, delete, export, import)
- migrate: Migrate v1 -> v2
- config: View/edit configuration

All commands support --json for machine-readable output.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..version import __version__, PROGRAM_NAME
from ..core import (
    Algorithm, CompressionType, ContainerVersion, ProfileType, OperationType,
    CODI_EXTENSION
)
from ..core.errors import (
    CodificatorError, ExitCode, IntegrityError, WeakPasswordError,
    PolicyViolationError
)
from ..core.vault import SecureVault
from ..core.batch import BatchProcessor, format_batch_progress
from ..core.keyring import Keyring
from ..core.migrate import Migrator, get_migration_preview
from ..core.policies import get_config, get_enforcer
from ..core.audit import get_audit_logger
from ..core.io_utils import FileFilter, normalize_path
from ..core.container_v2 import get_container_info


def get_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    """Get password from user with optional confirmation."""
    while True:
        password = getpass.getpass(prompt)
        
        if not confirm:
            return password
        
        confirm_pass = getpass.getpass("Confirm password: ")
        
        if password == confirm_pass:
            return password
        
        print("Passwords don't match. Try again.", file=sys.stderr)


def validate_password_policy(password: str) -> None:
    """Validate password against current policy."""
    try:
        get_enforcer().validate_password(password)
    except PolicyViolationError as e:
        print(f"Warning: {e}", file=sys.stderr)


class CLIFormatter:
    """Format CLI output."""
    
    def __init__(self, json_output: bool = False):
        self.json_output = json_output
    
    def output(self, data: Dict[str, Any], message: str = "") -> None:
        """Output data as JSON or human-readable."""
        if self.json_output:
            print(json.dumps(data, indent=2, default=str))
        else:
            if message:
                print(message)
            for key, value in data.items():
                if value is not None:
                    print(f"  {key}: {value}")
    
    def error(self, message: str, code: int = 1) -> None:
        """Output error."""
        if self.json_output:
            print(json.dumps({"error": message, "code": code}))
        else:
            print(f"Error: {message}", file=sys.stderr)
    
    def success(self, message: str) -> None:
        """Output success message."""
        if self.json_output:
            print(json.dumps({"status": "success", "message": message}))
        else:
            print(f"✓ {message}")
    
    def progress(self, current: int, total: int, message: str = "") -> None:
        """Show progress (only in non-JSON mode)."""
        if not self.json_output:
            percent = (current / total * 100) if total > 0 else 0
            print(f"\r[{percent:5.1f}%] {message}", end="", flush=True)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="codificator",
        description=f"{PROGRAM_NAME} - Enterprise Lite File Encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file
  %(prog)s encrypt-file --in secret.txt --out secret.codi
  
  # Decrypt a file
  %(prog)s decrypt-file --in secret.codi --out decrypted.txt
  
  # Encrypt a folder
  %(prog)s encrypt-folder --in ./documents --out ./encrypted --recursive
  
  # View file info
  %(prog)s info --in secret.codi
  
  # Migrate v1 to v2
  %(prog)s migrate --in old.codi --out new.codi
        """
    )
    
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # ══════════════════════════════════════════════════════════════════════════
    # ENCRYPT-FILE
    # ══════════════════════════════════════════════════════════════════════════
    encrypt_file = subparsers.add_parser("encrypt-file", help="Encrypt a file")
    encrypt_file.add_argument("--in", dest="input", required=True, help="Input file path")
    encrypt_file.add_argument("--out", dest="output", required=True, help="Output .codi file path")
    encrypt_file.add_argument("--algo", choices=["aesgcm", "chacha20poly1305"], 
                              default="aesgcm", help="Encryption algorithm")
    encrypt_file.add_argument("--password-prompt", action="store_true", 
                              help="Prompt for password")
    encrypt_file.add_argument("--keyfile", help="Path to keyfile for 2FA")
    encrypt_file.add_argument("--compress", action="store_true", help="Enable compression (V2)")
    encrypt_file.add_argument("--chunk-size", type=int, help="Chunk size in bytes")
    encrypt_file.add_argument("--no-chunking", action="store_true", help="Disable chunking")
    encrypt_file.add_argument("--scrypt-n", type=int, help="scrypt N parameter")
    encrypt_file.add_argument("--scrypt-r", type=int, help="scrypt r parameter")
    encrypt_file.add_argument("--scrypt-p", type=int, help="scrypt p parameter")
    encrypt_file.add_argument("--yes", "-y", action="store_true", help="Skip confirmations")
    
    # ══════════════════════════════════════════════════════════════════════════
    # DECRYPT-FILE
    # ══════════════════════════════════════════════════════════════════════════
    decrypt_file = subparsers.add_parser("decrypt-file", help="Decrypt a .codi file")
    decrypt_file.add_argument("--in", dest="input", required=True, help="Input .codi file")
    decrypt_file.add_argument("--out", dest="output", required=True, help="Output file path")
    decrypt_file.add_argument("--password-prompt", action="store_true", 
                              help="Prompt for password")
    decrypt_file.add_argument("--keyfile", help="Path to keyfile")
    decrypt_file.add_argument("--yes", "-y", action="store_true", help="Skip confirmations")
    
    # ══════════════════════════════════════════════════════════════════════════
    # ENCRYPT-FOLDER
    # ══════════════════════════════════════════════════════════════════════════
    encrypt_folder = subparsers.add_parser("encrypt-folder", help="Encrypt a folder")
    encrypt_folder.add_argument("--in", dest="input", required=True, help="Input folder")
    encrypt_folder.add_argument("--out", dest="output", required=True, help="Output folder")
    encrypt_folder.add_argument("--algo", choices=["aesgcm", "chacha20poly1305"],
                                default="aesgcm", help="Encryption algorithm")
    encrypt_folder.add_argument("--password-prompt", action="store_true",
                                help="Prompt for password")
    encrypt_folder.add_argument("--keyfile", help="Path to keyfile")
    encrypt_folder.add_argument("--recursive", "-r", action="store_true",
                                help="Include subdirectories")
    encrypt_folder.add_argument("--include", help="Include patterns (e.g., '*.txt,*.json')")
    encrypt_folder.add_argument("--exclude", help="Exclude patterns (e.g., 'node_modules,*.tmp')")
    encrypt_folder.add_argument("--max-size", type=int, help="Max file size in bytes")
    encrypt_folder.add_argument("--dry-run", action="store_true", help="Preview without executing")
    encrypt_folder.add_argument("--continue-on-error", action="store_true",
                                help="Continue on individual errors")
    encrypt_folder.add_argument("--jobs", "-j", type=int, default=4, help="Parallel jobs")
    encrypt_folder.add_argument("--yes", "-y", action="store_true", help="Skip confirmations")
    
    # ══════════════════════════════════════════════════════════════════════════
    # DECRYPT-FOLDER
    # ══════════════════════════════════════════════════════════════════════════
    decrypt_folder = subparsers.add_parser("decrypt-folder", help="Decrypt a folder")
    decrypt_folder.add_argument("--in", dest="input", required=True, help="Input folder")
    decrypt_folder.add_argument("--out", dest="output", required=True, help="Output folder")
    decrypt_folder.add_argument("--password-prompt", action="store_true",
                                help="Prompt for password")
    decrypt_folder.add_argument("--keyfile", help="Path to keyfile")
    decrypt_folder.add_argument("--recursive", "-r", action="store_true",
                                help="Include subdirectories")
    decrypt_folder.add_argument("--dry-run", action="store_true", help="Preview")
    decrypt_folder.add_argument("--continue-on-error", action="store_true",
                                help="Continue on errors")
    decrypt_folder.add_argument("--jobs", "-j", type=int, default=4, help="Parallel jobs")
    decrypt_folder.add_argument("--yes", "-y", action="store_true", help="Skip confirmations")
    
    # ══════════════════════════════════════════════════════════════════════════
    # VERIFY
    # ══════════════════════════════════════════════════════════════════════════
    verify = subparsers.add_parser("verify", help="Verify a .codi file")
    verify.add_argument("--in", dest="input", required=True, help="File to verify")
    verify.add_argument("--password-prompt", action="store_true", help="Prompt for password")
    verify.add_argument("--keyfile", help="Path to keyfile")
    
    # ══════════════════════════════════════════════════════════════════════════
    # INFO
    # ══════════════════════════════════════════════════════════════════════════
    info = subparsers.add_parser("info", help="Show .codi file information")
    info.add_argument("--in", dest="input", required=True, help="File to inspect")
    
    # ══════════════════════════════════════════════════════════════════════════
    # KEYS
    # ══════════════════════════════════════════════════════════════════════════
    keys = subparsers.add_parser("keys", help="Key management")
    keys_sub = keys.add_subparsers(dest="keys_command")
    
    keys_list = keys_sub.add_parser("list", help="List keys")
    keys_list.add_argument("--keyring", help="Keyring path")
    
    keys_create = keys_sub.add_parser("create", help="Create a new key")
    keys_create.add_argument("--name", required=True, help="Key name")
    keys_create.add_argument("--keyring", help="Keyring path")
    keys_create.add_argument("--tags", help="Comma-separated tags")
    
    keys_delete = keys_sub.add_parser("delete", help="Delete a key")
    keys_delete.add_argument("--name", required=True, help="Key name")
    keys_delete.add_argument("--keyring", help="Keyring path")
    keys_delete.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")
    
    keys_export = keys_sub.add_parser("export", help="Export a key")
    keys_export.add_argument("--name", required=True, help="Key name")
    keys_export.add_argument("--keyring", help="Keyring path")
    keys_export.add_argument("--out", help="Output file (or stdout)")
    
    keys_import = keys_sub.add_parser("import", help="Import a key")
    keys_import.add_argument("--in", dest="input", required=True, help="Input file")
    keys_import.add_argument("--keyring", help="Keyring path")
    keys_import.add_argument("--name", help="New name for key")
    
    # ══════════════════════════════════════════════════════════════════════════
    # MIGRATE
    # ══════════════════════════════════════════════════════════════════════════
    migrate = subparsers.add_parser("migrate", help="Migrate v1 to v2")
    migrate.add_argument("--in", dest="input", required=True, help="Input file/folder")
    migrate.add_argument("--out", dest="output", help="Output path (default: in-place)")
    migrate.add_argument("--password-prompt", action="store_true", help="Prompt for password")
    migrate.add_argument("--keyfile", help="Keyfile path")
    migrate.add_argument("--new-password", action="store_true", help="Set new password")
    migrate.add_argument("--new-keyfile", help="New keyfile path")
    migrate.add_argument("--compress", action="store_true", help="Enable compression")
    migrate.add_argument("--recursive", "-r", action="store_true", help="Recursive for folders")
    migrate.add_argument("--dry-run", action="store_true", help="Preview only")
    migrate.add_argument("--yes", "-y", action="store_true", help="Skip confirmations")
    
    # ══════════════════════════════════════════════════════════════════════════
    # CONFIG
    # ══════════════════════════════════════════════════════════════════════════
    config = subparsers.add_parser("config", help="View/edit configuration")
    config.add_argument("--show", action="store_true", help="Show current config")
    config.add_argument("--profile", choices=["personal", "work", "forensic"],
                       help="Set profile")
    config.add_argument("--reset", action="store_true", help="Reset to defaults")
    
    return parser


def cmd_encrypt_file(args, fmt: CLIFormatter) -> int:
    """Handle encrypt-file command."""
    src_path = normalize_path(args.input)
    dst_path = normalize_path(args.output)
    
    if not src_path.exists():
        fmt.error(f"Input file not found: {src_path}")
        return ExitCode.IO_FAIL
    
    # Get password
    if args.password_prompt:
        password = get_password(confirm=True)
        validate_password_policy(password)
    else:
        fmt.error("--password-prompt required")
        return ExitCode.BAD_ARGS
    
    # Algorithm
    algo = Algorithm.AES_256_GCM if args.algo == "aesgcm" else Algorithm.CHACHA20_POLY1305
    
    # Compression
    compression = CompressionType.ZLIB if args.compress else CompressionType.NONE
    
    # Keyfile
    keyfile = normalize_path(args.keyfile) if args.keyfile else None
    
    try:
        vault = SecureVault(
            algorithm=algo,
            compression=compression,
            scrypt_n=args.scrypt_n,
            scrypt_r=args.scrypt_r,
            scrypt_p=args.scrypt_p,
            chunk_size=args.chunk_size,
            auto_chunk=not args.no_chunking,
        )
        
        start_time = time.time()
        
        def progress(curr, total, msg):
            if not args.quiet:
                fmt.progress(curr, total, msg)
        
        result = vault.encrypt_file(
            src_path, dst_path, password, keyfile,
            progress_callback=progress if not fmt.json_output else None
        )
        
        duration_ms = int((time.time() - start_time) * 1000)
        result["duration_ms"] = duration_ms
        
        if not args.quiet and not fmt.json_output:
            print()  # Newline after progress
        
        fmt.output(result, "File encrypted successfully")
        return ExitCode.SUCCESS
        
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code
    except Exception as e:
        fmt.error(str(e))
        return ExitCode.GENERAL_ERROR


def cmd_decrypt_file(args, fmt: CLIFormatter) -> int:
    """Handle decrypt-file command."""
    src_path = normalize_path(args.input)
    dst_path = normalize_path(args.output)
    
    if not src_path.exists():
        fmt.error(f"Input file not found: {src_path}")
        return ExitCode.IO_FAIL
    
    if args.password_prompt:
        password = get_password(confirm=False)
    else:
        fmt.error("--password-prompt required")
        return ExitCode.BAD_ARGS
    
    keyfile = normalize_path(args.keyfile) if args.keyfile else None
    
    try:
        vault = SecureVault()
        
        start_time = time.time()
        
        result = vault.decrypt_file(src_path, dst_path, password, keyfile)
        
        duration_ms = int((time.time() - start_time) * 1000)
        result["duration_ms"] = duration_ms
        
        fmt.output(result, "File decrypted successfully")
        return ExitCode.SUCCESS
        
    except IntegrityError:
        fmt.error("Integrity check failed. Wrong password or file tampered.")
        return ExitCode.AUTH_FAIL
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code
    except Exception as e:
        fmt.error(str(e))
        return ExitCode.GENERAL_ERROR


def cmd_encrypt_folder(args, fmt: CLIFormatter) -> int:
    """Handle encrypt-folder command."""
    src_dir = normalize_path(args.input)
    dst_dir = normalize_path(args.output)
    
    if not src_dir.is_dir():
        fmt.error(f"Input is not a directory: {src_dir}")
        return ExitCode.IO_FAIL
    
    if args.password_prompt:
        password = get_password(confirm=True)
        validate_password_policy(password)
    else:
        fmt.error("--password-prompt required")
        return ExitCode.BAD_ARGS
    
    keyfile = normalize_path(args.keyfile) if args.keyfile else None
    
    # Build filter
    include = args.include.split(",") if args.include else None
    exclude = args.exclude.split(",") if args.exclude else None
    file_filter = FileFilter(
        include_patterns=include,
        exclude_patterns=exclude,
        max_size=args.max_size,
    )
    
    algo = Algorithm.AES_256_GCM if args.algo == "aesgcm" else Algorithm.CHACHA20_POLY1305
    
    try:
        vault = SecureVault(algorithm=algo)
        processor = BatchProcessor(vault, file_filter, max_workers=args.jobs)
        
        def progress(prog):
            if not args.quiet and not fmt.json_output:
                fmt.progress(prog.processed_files, prog.total_files, prog.current_file or "")
        
        result = processor.encrypt_folder(
            src_dir, dst_dir, password, keyfile,
            recursive=args.recursive,
            dry_run=args.dry_run,
            continue_on_error=args.continue_on_error,
            progress_callback=progress,
        )
        
        if not args.quiet and not fmt.json_output:
            print()
            print(format_batch_progress(result))
        
        if fmt.json_output:
            from dataclasses import asdict
            fmt.output(asdict(result))
        
        return ExitCode.SUCCESS if result.failed_files == 0 else ExitCode.GENERAL_ERROR
        
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code


def cmd_decrypt_folder(args, fmt: CLIFormatter) -> int:
    """Handle decrypt-folder command."""
    src_dir = normalize_path(args.input)
    dst_dir = normalize_path(args.output)
    
    if not src_dir.is_dir():
        fmt.error(f"Input is not a directory: {src_dir}")
        return ExitCode.IO_FAIL
    
    if args.password_prompt:
        password = get_password(confirm=False)
    else:
        fmt.error("--password-prompt required")
        return ExitCode.BAD_ARGS
    
    keyfile = normalize_path(args.keyfile) if args.keyfile else None
    
    try:
        vault = SecureVault()
        processor = BatchProcessor(vault, max_workers=args.jobs)
        
        def progress(prog):
            if not args.quiet and not fmt.json_output:
                fmt.progress(prog.processed_files, prog.total_files, prog.current_file or "")
        
        result = processor.decrypt_folder(
            src_dir, dst_dir, password, keyfile,
            recursive=args.recursive,
            dry_run=args.dry_run,
            continue_on_error=args.continue_on_error,
            progress_callback=progress,
        )
        
        if not args.quiet and not fmt.json_output:
            print()
            print(format_batch_progress(result))
        
        return ExitCode.SUCCESS if result.failed_files == 0 else ExitCode.GENERAL_ERROR
        
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code


def cmd_verify(args, fmt: CLIFormatter) -> int:
    """Handle verify command."""
    src_path = normalize_path(args.input)
    
    if not src_path.exists():
        fmt.error(f"File not found: {src_path}")
        return ExitCode.IO_FAIL
    
    if args.password_prompt:
        password = get_password(confirm=False)
    else:
        fmt.error("--password-prompt required")
        return ExitCode.BAD_ARGS
    
    keyfile = normalize_path(args.keyfile) if args.keyfile else None
    
    try:
        vault = SecureVault()
        is_valid, info = vault.verify_file(src_path, password, keyfile)
        
        if is_valid:
            fmt.output(info, "✓ File integrity verified")
            return ExitCode.SUCCESS
        else:
            fmt.output(info, "✗ Verification failed")
            return ExitCode.AUTH_FAIL
            
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code


def cmd_info(args, fmt: CLIFormatter) -> int:
    """Handle info command."""
    src_path = normalize_path(args.input)
    
    if not src_path.exists():
        fmt.error(f"File not found: {src_path}")
        return ExitCode.IO_FAIL
    
    try:
        info = get_container_info(src_path)
        fmt.output(info, f"Container information: {src_path}")
        return ExitCode.SUCCESS
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code


def cmd_migrate(args, fmt: CLIFormatter) -> int:
    """Handle migrate command."""
    src_path = normalize_path(args.input)
    dst_path = normalize_path(args.output) if args.output else src_path
    
    if not src_path.exists():
        fmt.error(f"Path not found: {src_path}")
        return ExitCode.IO_FAIL
    
    if args.dry_run:
        preview = get_migration_preview(src_path)
        fmt.output(preview, "Migration preview")
        return ExitCode.SUCCESS
    
    if args.password_prompt:
        password = get_password(prompt="Current password: ", confirm=False)
    else:
        fmt.error("--password-prompt required")
        return ExitCode.BAD_ARGS
    
    new_password = None
    if args.new_password:
        new_password = get_password(prompt="New password: ", confirm=True)
        validate_password_policy(new_password)
    
    keyfile = normalize_path(args.keyfile) if args.keyfile else None
    new_keyfile = normalize_path(args.new_keyfile) if args.new_keyfile else None
    
    compression = CompressionType.ZLIB if args.compress else CompressionType.NONE
    
    try:
        migrator = Migrator(compression=compression)
        
        if src_path.is_file():
            result = migrator.migrate_file(
                src_path, dst_path, password, keyfile,
                new_password, new_keyfile
            )
            fmt.output(result, "Migration complete")
        else:
            result = migrator.migrate_folder(
                src_path, dst_path, password, keyfile,
                new_password, new_keyfile,
                recursive=args.recursive
            )
            fmt.output(result, "Folder migration complete")
        
        return ExitCode.SUCCESS
        
    except CodificatorError as e:
        fmt.error(str(e), e.exit_code)
        return e.exit_code


def cmd_config(args, fmt: CLIFormatter) -> int:
    """Handle config command."""
    config = get_config()
    
    if args.reset:
        config.reset_to_defaults()
        config.save()
        fmt.success("Configuration reset to defaults")
        return ExitCode.SUCCESS
    
    if args.profile:
        profile = ProfileType(args.profile)
        config.set_profile(profile)
        config.save()
        fmt.success(f"Profile set to: {args.profile}")
    
    if args.show or not (args.profile or args.reset):
        info = config.get_profile_info()
        fmt.output(info, "Current configuration")
    
    return ExitCode.SUCCESS


def run_cli(argv: Optional[List[str]] = None) -> int:
    """Run the CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return ExitCode.SUCCESS
    
    fmt = CLIFormatter(json_output=args.json)
    
    commands = {
        "encrypt-file": cmd_encrypt_file,
        "decrypt-file": cmd_decrypt_file,
        "encrypt-folder": cmd_encrypt_folder,
        "decrypt-folder": cmd_decrypt_folder,
        "verify": cmd_verify,
        "info": cmd_info,
        "migrate": cmd_migrate,
        "config": cmd_config,
    }
    
    handler = commands.get(args.command)
    if handler:
        try:
            return handler(args, fmt)
        except KeyboardInterrupt:
            print("\nInterrupted", file=sys.stderr)
            return ExitCode.INTERRUPTED
    
    parser.print_help()
    return ExitCode.BAD_ARGS


# Alias for compatibility
main_cli = run_cli
