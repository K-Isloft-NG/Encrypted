#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           CODIFICATOR V2                                      ║
║                  Enterprise Lite File Encryption System                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Secure file encryption with modern AEAD algorithms.

INSTALLATION:
    pip install cryptography textual

USAGE:
    # Interactive TUI mode (default)
    python codificator_v2.py
    
    # CLI mode
    python codificator_v2.py encrypt-file --in file.txt --out file.codi --password-prompt
    python codificator_v2.py decrypt-file --in file.codi --out file.txt --password-prompt
    python codificator_v2.py encrypt-folder --in ./data --out ./encrypted --password-prompt
    python codificator_v2.py decrypt-folder --in ./encrypted --out ./decrypted --password-prompt
    python codificator_v2.py verify --in file.codi --password-prompt
    python codificator_v2.py info --in file.codi
    python codificator_v2.py keys list
    python codificator_v2.py migrate --in old.codi --out new.codi --password-prompt

CLI OPTIONS:
    --algo aesgcm|chacha20         AEAD algorithm (default: aesgcm)
    --version 1|2                  Container version (default: 2)
    --compress                     Enable compression (V2 only)
    --scrypt-n N                   scrypt CPU cost (default: 32768)
    --chunk-size SIZE              Chunk size in bytes
    --no-chunking                  Disable chunked encryption
    --keyfile PATH                 Use keyfile for 2FA
    --keyring-key NAME             Use key from keyring
    --include PATTERNS             Include patterns for batch
    --exclude PATTERNS             Exclude patterns for batch
    --recursive                    Process subdirectories
    --dry-run                      Preview without executing
    --continue-on-error            Continue batch on errors
    --jobs N                       Parallel jobs for batch
    --audit-log PATH               Custom audit log path
    --paranoid                     Hash paths in audit log
    --json                         JSON output for scripting
    --yes, -y                      Skip confirmations

SECURITY FEATURES:
    • AES-256-GCM (recommended) or ChaCha20-Poly1305 AEAD encryption
    • scrypt memory-hard key derivation (resistant to GPU attacks)
    • Optional keyfile for 2-factor authentication
    • Local encrypted keyring for key management
    • Automatic chunking for large files (streaming)
    • Audit logging with optional paranoid mode
    • Atomic writes with rollback on failure

.CODI CONTAINER FORMAT:
    V1: Basic format, compatible with Codificator V0
    V2: Adds compression, improved chunking, better metadata
    
    Both versions use authenticated encryption - tampering is detected.

LICENSE:
    For educational and enterprise use.
"""

import sys
import os

# Add the parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from codificator_v2.version import __version__, PROGRAM_NAME


def main():
    """Main entry point."""
    # Check if CLI arguments provided
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        # Check for TUI flag
        if arg == '--tui':
            return run_tui()
        
        # Check for version
        if arg in ('--version', '-V'):
            print(f"{PROGRAM_NAME} v{__version__}")
            return 0
        
        # Check for self-test
        if arg == '--self-test':
            return run_self_test()
        
        # Otherwise, CLI mode
        return run_cli()
    
    # Default: TUI mode
    return run_tui()


def run_tui():
    """Run TUI mode."""
    try:
        from codificator_v2.tui import run_tui as _run_tui
        return _run_tui()
    except ImportError as e:
        print(f"Error: Cannot start TUI - {e}")
        print("")
        print("Make sure dependencies are installed:")
        print("  pip install cryptography textual")
        print("")
        print("Or use CLI mode:")
        print(f"  python {sys.argv[0]} --help")
        return 1


def run_cli():
    """Run CLI mode."""
    try:
        from codificator_v2.cli import main_cli
        return main_cli()
    except ImportError as e:
        print(f"Error: Cannot start CLI - {e}")
        print("")
        print("Make sure cryptography is installed:")
        print("  pip install cryptography")
        return 1


def run_self_test():
    """Run self-tests."""
    print(f"{PROGRAM_NAME} v{__version__} - Self-Test Suite")
    print("=" * 60)
    
    try:
        from codificator_v2.tests.test_all import run_tests
        return run_tests()
    except ImportError as e:
        print(f"Error running tests: {e}")
        print("")
        print("Make sure dependencies are installed:")
        print("  pip install cryptography")
        return 1


if __name__ == "__main__":
    sys.exit(main())
