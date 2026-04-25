"""
Codificator V2 - Enterprise Lite File Encryption System

An advanced file encryption system with:
- AES-256-GCM and ChaCha20-Poly1305 AEAD encryption
- scrypt key derivation
- Local encrypted keyring
- Batch folder operations with resume
- TUI and CLI interfaces
- Audit logging

Installation:
    pip install cryptography textual

Usage:
    # TUI (interactive)
    python -m codificator_v2
    
    # CLI
    python -m codificator_v2 encrypt-file --in file.txt --out file.codi --password-prompt
    python -m codificator_v2 decrypt-file --in file.codi --out file.txt --password-prompt

Security Note:
    This tool uses industry-standard AEAD encryption (AES-256-GCM or ChaCha20-Poly1305)
    with scrypt key derivation. For sensitive data protection.
"""

from .version import __version__, PROGRAM_NAME

__all__ = ["__version__", "PROGRAM_NAME"]
