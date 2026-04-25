"""
Keyring module for managing encryption keys.

Features:
- Encrypted local key storage
- Create, list, rename, delete keys
- Import/export keys (encrypted)
- Key rotation (re-encrypt file with new key)
- Tags and metadata

The keyring is stored as an encrypted JSON file using the user's
master password. Keys are never stored in plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from . import (
    Algorithm, KeyEntry, KeyringInfo,
    DEFAULT_KEY_SIZE, KEYRING_FILENAME, KEYRING_VERSION
)
from .errors import (
    KeyNotFoundError, KeyExistsError, KeyringLockedError,
    KeyringCorruptedError, IntegrityError
)
from .crypto_aead import AEAD, generate_nonce
from .kdf import KDF
from .io_utils import normalize_path, atomic_write


class Keyring:
    """
    Secure keyring for managing encryption keys.
    
    Usage:
        # Create/open keyring
        keyring = Keyring(path)
        keyring.unlock("master_password")
        
        # Create a key
        key_id = keyring.create_key("my-key")
        
        # Get key for encryption
        key_bytes = keyring.get_key(key_id)
        
        # Lock when done
        keyring.lock()
    """
    
    def __init__(self, path: Optional[Path] = None):
        """
        Initialize keyring.
        
        Args:
            path: Path to keyring file. If None, uses default location.
        """
        if path is None:
            path = Path.home() / KEYRING_FILENAME
        
        self.path = normalize_path(path)
        self._master_key: Optional[bytes] = None
        self._data: Dict = {}
        self._locked = True
    
    @property
    def is_locked(self) -> bool:
        """Check if keyring is locked."""
        return self._locked
    
    @property
    def exists(self) -> bool:
        """Check if keyring file exists."""
        return self.path.exists()
    
    def create(self, master_password: str) -> None:
        """
        Create a new keyring with master password.
        
        Args:
            master_password: Master password for keyring
        
        Raises:
            FileExistsError: If keyring already exists
        """
        if self.path.exists():
            raise FileExistsError(f"Keyring already exists: {self.path}")
        
        # Initialize empty keyring
        self._data = {
            "version": KEYRING_VERSION,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "keys": {}  # key_id -> encrypted key data
        }
        
        # Derive master key
        salt = KDF.generate_salt()
        self._master_key = KDF().derive(master_password, salt)
        
        # Mark as unlocked BEFORE saving (save checks this)
        self._locked = False
        
        # Save with salt
        self._save(salt)
    
    def unlock(self, master_password: str) -> None:
        """
        Unlock keyring with master password.
        
        Args:
            master_password: Master password
        
        Raises:
            FileNotFoundError: If keyring doesn't exist
            IntegrityError: If password is wrong
        """
        if not self.path.exists():
            raise FileNotFoundError(f"Keyring not found: {self.path}")
        
        with open(self.path, 'rb') as f:
            # Read salt (first 32 bytes)
            salt = f.read(32)
            if len(salt) != 32:
                raise KeyringCorruptedError("Invalid keyring format")
            
            # Derive master key
            self._master_key = KDF().derive(master_password, salt)
            
            # Read nonce
            nonce = f.read(12)
            if len(nonce) != 12:
                raise KeyringCorruptedError("Invalid keyring format")
            
            # Read encrypted data
            encrypted = f.read()
        
        # Decrypt
        try:
            aead = AEAD(Algorithm.AES_256_GCM)
            decrypted = aead.decrypt(self._master_key, nonce, encrypted, b"keyring")
            self._data = json.loads(decrypted.decode('utf-8'))
            self._locked = False
        except IntegrityError:
            self._master_key = None
            self._locked = True
            raise IntegrityError("Wrong master password or corrupted keyring")
    
    def lock(self) -> None:
        """Lock the keyring, clearing sensitive data from memory."""
        if self._master_key:
            # Best effort to clear key from memory
            try:
                self._master_key = b'\x00' * len(self._master_key)
            except:
                pass
        
        self._master_key = None
        self._data = {}
        self._locked = True
    
    def _ensure_unlocked(self) -> None:
        """Ensure keyring is unlocked."""
        if self._locked:
            raise KeyringLockedError()
        assert self._master_key is not None
    
    def _save(self, salt: Optional[bytes] = None) -> None:
        """Save keyring to disk."""
        self._ensure_unlocked()
        
        if salt is None:
            # Read existing salt
            if self.path.exists():
                with open(self.path, 'rb') as f:
                    salt = f.read(32)
            else:
                salt = KDF.generate_salt()
        
        # Serialize data
        data_bytes = json.dumps(self._data, indent=2).encode('utf-8')
        
        # Encrypt
        aead = AEAD(Algorithm.AES_256_GCM)
        assert self._master_key is not None
        nonce, ciphertext = aead.encrypt(self._master_key, data_bytes, b"keyring")
        
        # Write: salt + nonce + ciphertext
        with atomic_write(self.path) as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)
    
    def create_key(self, name: str, 
                   algorithm: Algorithm = Algorithm.AES_256_GCM,
                   tags: Optional[List[str]] = None,
                   description: str = "") -> str:
        """
        Create a new random key.
        
        Args:
            name: Human-readable name for the key
            algorithm: Algorithm the key will be used with
            tags: Optional tags for organization
            description: Optional description
        
        Returns:
            Key ID (UUID)
        
        Raises:
            KeyExistsError: If a key with this name exists
        """
        self._ensure_unlocked()
        
        # Check for duplicate name
        for key_id, entry in self._data["keys"].items():
            if entry["name"] == name:
                raise KeyExistsError(name)
        
        # Generate key
        key_bytes = secrets.token_bytes(DEFAULT_KEY_SIZE)
        key_id = str(uuid.uuid4())
        
        # Encrypt key bytes with master key
        aead = AEAD(Algorithm.AES_256_GCM)
        assert self._master_key is not None
        nonce, encrypted_key = aead.encrypt(
            self._master_key, key_bytes, key_id.encode()
        )
        
        # Store entry
        entry = {
            "name": name,
            "algorithm": algorithm.value,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "tags": tags or [],
            "description": description,
            "last_used": None,
            "use_count": 0,
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
        }
        
        self._data["keys"][key_id] = entry
        self._save()
        
        return key_id
    
    def get_key(self, key_id: str) -> bytes:
        """
        Get decrypted key bytes.
        
        Args:
            key_id: Key ID
        
        Returns:
            32-byte key
        
        Raises:
            KeyNotFoundError: If key doesn't exist
        """
        self._ensure_unlocked()
        
        if key_id not in self._data["keys"]:
            raise KeyNotFoundError(key_id)
        
        entry = self._data["keys"][key_id]
        
        # Decrypt key
        nonce = base64.b64decode(entry["nonce"])
        encrypted_key = base64.b64decode(entry["encrypted_key"])
        
        aead = AEAD(Algorithm.AES_256_GCM)
        assert self._master_key is not None
        key_bytes = aead.decrypt(
            self._master_key, nonce, encrypted_key, key_id.encode()
        )
        
        # NOTE: get_key ne met plus à jour les stats automatiquement
        # C'est la fonction increment_use qui s'en charge pour plus de contrôle
        
        return key_bytes
    
    def get_key_by_name(self, name: str) -> bytes:
        """
        Get key by name.
        
        Args:
            name: Key name
        
        Returns:
            32-byte key
        """
        key_id = self._find_key_by_name(name)
        return self.get_key(key_id)
    
    def _find_key_by_name(self, name: str) -> str:
        """Find key ID by name."""
        for key_id, entry in self._data["keys"].items():
            if entry["name"] == name:
                return key_id
        raise KeyNotFoundError(name)
    
    def list_keys(self) -> List[KeyEntry]:
        """
        List all keys.
        
        Returns:
            List of KeyEntry objects (without actual key bytes)
        """
        self._ensure_unlocked()
        
        entries = []
        for key_id, data in self._data["keys"].items():
            entries.append(KeyEntry(
                key_id=key_id,
                name=data["name"],
                created_at=data["created_at"],
                algorithm=Algorithm(data["algorithm"]),
                tags=data.get("tags", []),
                description=data.get("description", ""),
                last_used=data.get("last_used"),
                use_count=data.get("use_count", 0),
            ))
        
        return sorted(entries, key=lambda e: e.created_at, reverse=True)
    
    def get_info(self) -> KeyringInfo:
        """Get keyring information."""
        self._ensure_unlocked()
        
        return KeyringInfo(
            version=self._data.get("version", 1),
            created_at=self._data.get("created_at", ""),
            key_count=len(self._data["keys"]),
            keys=self.list_keys(),
        )
    
    def rename_key(self, key_id: str, new_name: str) -> None:
        """
        Rename a key.
        
        Args:
            key_id: Key ID
            new_name: New name
        """
        self._ensure_unlocked()
        
        if key_id not in self._data["keys"]:
            raise KeyNotFoundError(key_id)
        
        # Check for duplicate name
        for k_id, entry in self._data["keys"].items():
            if entry["name"] == new_name and k_id != key_id:
                raise KeyExistsError(new_name)
        
        self._data["keys"][key_id]["name"] = new_name
        self._save()
    
    def update_tags(self, key_id: str, tags: List[str]) -> None:
        """Update key tags."""
        self._ensure_unlocked()
        
        if key_id not in self._data["keys"]:
            raise KeyNotFoundError(key_id)
        
        self._data["keys"][key_id]["tags"] = tags
        self._save()
    
    # [AJOUT] La méthode qui manquait pour mettre à jour le compteur !
    def increment_use(self, key_id: str) -> None:
        """
        Increment the usage counter for a key.
        
        Args:
            key_id: Key ID to update
        """
        self._ensure_unlocked()
        
        if key_id not in self._data["keys"]:
            raise KeyNotFoundError(key_id)
        
        # Mise à jour du compteur et de la date
        self._data["keys"][key_id]["use_count"] += 1
        self._data["keys"][key_id]["last_used"] = datetime.utcnow().isoformat() + "Z"
        self._save()

    def delete_key(self, key_id: str) -> None:
        """
        Delete a key.
        
        WARNING: This is irreversible! Files encrypted with this key
        cannot be decrypted after deletion.
        
        Args:
            key_id: Key ID
        """
        self._ensure_unlocked()
        
        if key_id not in self._data["keys"]:
            raise KeyNotFoundError(key_id)
        
        del self._data["keys"][key_id]
        self._save()
    
    def export_key(self, key_id: str, export_password: str) -> str:
        """
        Export a key encrypted with a password.
        
        Args:
            key_id: Key ID to export
            export_password: Password to encrypt the export
        
        Returns:
            Base64-encoded encrypted export
        """
        self._ensure_unlocked()
        
        # Get key bytes
        key_bytes = self.get_key(key_id)
        entry = self._data["keys"][key_id]
        
        # Create export package
        export_data = {
            "name": entry["name"],
            "algorithm": entry["algorithm"],
            "tags": entry.get("tags", []),
            "description": entry.get("description", ""),
            "key": base64.b64encode(key_bytes).decode(),
            "exported_at": datetime.utcnow().isoformat() + "Z",
        }
        
        # Encrypt with export password
        salt = KDF.generate_salt()
        export_key = KDF().derive(export_password, salt)
        
        aead = AEAD(Algorithm.AES_256_GCM)
        nonce, ciphertext = aead.encrypt(
            export_key, json.dumps(export_data).encode(), b"keyring_export"
        )
        
        # Package: salt + nonce + ciphertext
        package = salt + nonce + ciphertext
        return base64.b64encode(package).decode()
    
    def import_key(self, export_data: str, export_password: str,
                   new_name: Optional[str] = None) -> str:
        """
        Import a key from encrypted export.
        
        Args:
            export_data: Base64-encoded encrypted export
            export_password: Password to decrypt
            new_name: Optional new name (uses original if None)
        
        Returns:
            Key ID of imported key
        """
        self._ensure_unlocked()
        
        # Decode package
        package = base64.b64decode(export_data)
        salt = package[:32]
        nonce = package[32:44]
        ciphertext = package[44:]
        
        # Derive key and decrypt
        export_key = KDF().derive(export_password, salt)
        
        aead = AEAD(Algorithm.AES_256_GCM)
        try:
            decrypted = aead.decrypt(export_key, nonce, ciphertext, b"keyring_export")
        except IntegrityError:
            raise IntegrityError("Wrong password or corrupted export")
        
        data = json.loads(decrypted.decode())
        key_bytes = base64.b64decode(data["key"])
        
        # Use new name or original
        name = new_name or data["name"]
        
        # Check for duplicate name
        for k_id, entry in self._data["keys"].items():
            if entry["name"] == name:
                # Append timestamp to make unique
                name = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                break
        
        # Store in keyring
        key_id = str(uuid.uuid4())
        
        assert self._master_key is not None
        nonce, encrypted_key = aead.encrypt(
            self._master_key, key_bytes, key_id.encode()
        )
        
        entry = {
            "name": name,
            "algorithm": data.get("algorithm", Algorithm.AES_256_GCM.value),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "tags": data.get("tags", []),
            "description": data.get("description", "") + f" (imported)",
            "last_used": None,
            "use_count": 0,
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
        }
        
        self._data["keys"][key_id] = entry
        self._save()
        
        return key_id
    
    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Change the master password.
        
        Args:
            old_password: Current master password
            new_password: New master password
        """
        # Verify old password
        if self._locked:
            self.unlock(old_password)
        
        # Re-derive master key with new password
        salt = KDF.generate_salt()
        new_master_key = KDF().derive(new_password, salt)
        
        # Re-encrypt all keys with new master key
        aead = AEAD(Algorithm.AES_256_GCM)
        
        for key_id, entry in self._data["keys"].items():
            # Decrypt with old key
            old_nonce = base64.b64decode(entry["nonce"])
            old_encrypted = base64.b64decode(entry["encrypted_key"])
            assert self._master_key is not None
            key_bytes = aead.decrypt(
                self._master_key, old_nonce, old_encrypted, key_id.encode()
            )
            
            # Re-encrypt with new key
            new_nonce, new_encrypted = aead.encrypt(
                new_master_key, key_bytes, key_id.encode()
            )
            
            entry["nonce"] = base64.b64encode(new_nonce).decode()
            entry["encrypted_key"] = base64.b64encode(new_encrypted).decode()
        
        # Update master key
        self._master_key = new_master_key
        self._save(salt)