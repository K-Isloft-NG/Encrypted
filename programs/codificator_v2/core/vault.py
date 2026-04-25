"""
Secure Vault - Main encryption/decryption orchestrator.

This module provides the high-level API for encrypting and decrypting
files using the .codi container format.

Features:
- File encryption/decryption
- Automatic chunking for large files
- Compression support (V2)
- Key source flexibility (password, keyring, keyfile)
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple, Union

from .. import version
from . import (
    Algorithm, KDFType, CompressionType, ContainerVersion, KeySource,
    ScryptParams, ContainerHeader, ContainerMetadata, ChunkInfo,
    DEFAULT_CHUNK_SIZE, CHUNK_THRESHOLD, DEFAULT_NONCE_SIZE,
    CODI_EXTENSION
)
from .errors import (
    IntegrityError, EncryptionError, DecryptionError,
    FileNotFoundError, ContainerFormatError
)
from .crypto_aead import AEAD, generate_nonce
from .kdf import KDF, KeyCombiner
from .container_v1 import ContainerV1Reader, ContainerV1Writer
from .container_v2 import (
    ContainerV2Reader, ContainerV2Writer, Compression,
    detect_version, get_container_info
)
from .io_utils import (
    normalize_path, ensure_parent_exists, atomic_write,
    read_chunks, compute_sha256, compute_sha256_bytes
)


# Progress callback type
ProgressCallback = Callable[[int, int, str], None]  # (current, total, message)


class SecureVault:
    """
    High-level API for secure file encryption/decryption.
    
    Usage:
        vault = SecureVault()
        
        # Encrypt file
        vault.encrypt_file(src, dst, password="mypassword")
        
        # Decrypt file
        vault.decrypt_file(src, dst, password="mypassword")
        
        # With keyfile (2FA)
        vault.encrypt_file(src, dst, password="mypassword", keyfile=keyfile_path)
    """
    
    def __init__(self,
                 algorithm: Algorithm = Algorithm.AES_256_GCM,
                 container_version: ContainerVersion = ContainerVersion.V2,
                 compression: CompressionType = CompressionType.NONE,
                 scrypt_n: Optional[int] = None,
                 scrypt_r: Optional[int] = None,
                 scrypt_p: Optional[int] = None,
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 chunk_threshold: int = CHUNK_THRESHOLD,
                 auto_chunk: bool = True):
        """
        Initialize SecureVault.
        
        Args:
            algorithm: AEAD algorithm to use
            container_version: Container format version (V1 or V2)
            compression: Compression type (V2 only)
            scrypt_n: scrypt N parameter (CPU/memory cost)
            scrypt_r: scrypt r parameter (block size)
            scrypt_p: scrypt p parameter (parallelization)
            chunk_size: Size of chunks for large files
            chunk_threshold: Auto-chunk files larger than this
            auto_chunk: Automatically enable chunking for large files
        """
        from . import DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P
        
        self.algorithm = algorithm
        self.container_version = container_version
        self.compression = compression
        self.scrypt_n = scrypt_n or DEFAULT_SCRYPT_N
        self.scrypt_r = scrypt_r or DEFAULT_SCRYPT_R
        self.scrypt_p = scrypt_p or DEFAULT_SCRYPT_P
        self.chunk_size = chunk_size
        self.chunk_threshold = chunk_threshold
        self.auto_chunk = auto_chunk
        
        self._aead = AEAD(algorithm)
        self._kdf = KDF(n=self.scrypt_n, r=self.scrypt_r, p=self.scrypt_p)
    
    def _derive_key(self, password: str, salt: bytes,
                    keyfile: Optional[Path] = None) -> bytes:
        """Derive encryption key from password (and optionally keyfile)."""
        derived = self._kdf.derive(password, salt)
        
        if keyfile:
            keyfile_data = keyfile.read_bytes()
            derived = KeyCombiner.combine(derived, keyfile_data)
        
        return derived
    
    def encrypt_file(self, src_path: Union[str, Path], dst_path: Union[str, Path],
                     password: str,
                     keyfile: Optional[Union[str, Path]] = None,
                     include_filename: bool = True,
                     force_chunked: Optional[bool] = None,
                     progress_callback: Optional[ProgressCallback] = None) -> Dict:
        """
        Encrypt a file.
        
        Args:
            src_path: Source file path
            dst_path: Destination .codi file path
            password: Encryption password
            keyfile: Optional keyfile for 2FA
            include_filename: Include original filename in metadata
            force_chunked: Force chunked mode (None = auto-detect)
            progress_callback: Progress callback(bytes_done, total_bytes, message)
        
        Returns:
            Dict with operation details for audit
        """
        src_path = normalize_path(src_path)
        dst_path = normalize_path(dst_path)
        
        if keyfile:
            keyfile = normalize_path(keyfile)
        else:
            keyfile = None
        
        if not src_path.exists():
            raise FileNotFoundError(str(src_path))
        
        file_size = src_path.stat().st_size
        
        # Determine if chunking is needed
        use_chunked = force_chunked if force_chunked is not None else (
            self.auto_chunk and file_size > self.chunk_threshold
        )
        
        # Generate salt and derive key
        salt = KDF.generate_salt()
        key = self._derive_key(password, salt, keyfile)
        
        # Prepare metadata
        metadata = ContainerMetadata(
            original_filename=src_path.name if include_filename else None,
            created_at=datetime.utcnow().isoformat() + "Z",
            tool_version=f"{version.PROGRAM_NAME} v{version.__version__}",
            compressed=self.compression != CompressionType.NONE,
            compression_type=self.compression,
            original_size=file_size,
            chunked=use_chunked,
            chunk_size=self.chunk_size if use_chunked else 0,
        )
        
        # Build header flags
        flags = ContainerHeader.FLAG_HAS_AAD
        if include_filename:
            flags |= ContainerHeader.FLAG_HAS_FILENAME
        if use_chunked:
            flags |= ContainerHeader.FLAG_CHUNKED
        if self.compression != CompressionType.NONE:
            flags |= ContainerHeader.FLAG_COMPRESSED
        
        scrypt_params = ScryptParams(
            salt=salt, n=self.scrypt_n, r=self.scrypt_r, 
            p=self.scrypt_p, dklen=32
        )
        
        # Encrypt based on version
        if self.container_version == ContainerVersion.V1:
            result = self._encrypt_v1(
                src_path, dst_path, key, metadata, scrypt_params, flags,
                use_chunked, progress_callback
            )
        else:
            result = self._encrypt_v2(
                src_path, dst_path, key, metadata, scrypt_params, flags,
                use_chunked, progress_callback
            )
        
        result["src_size"] = file_size
        result["dst_size"] = dst_path.stat().st_size
        result["algorithm"] = self.algorithm.name
        result["chunked"] = use_chunked
        result["ciphertext_sha256"] = compute_sha256(dst_path)
        
        return result
    
    def _encrypt_v1(self, src_path: Path, dst_path: Path, key: bytes,
                    metadata: ContainerMetadata, scrypt_params: ScryptParams,
                    flags: int, use_chunked: bool,
                    progress_callback: Optional[ProgressCallback]) -> Dict:
        """Encrypt using V1 format."""
        aad = metadata.to_json_bytes()
        
        ensure_parent_exists(dst_path)
        
        with atomic_write(dst_path) as f:
            if use_chunked:
                chunks = self._encrypt_chunked_v1(src_path, key, aad, progress_callback)
                metadata.chunk_count = len(chunks)
                aad = metadata.to_json_bytes()
                
                header = ContainerHeader(
                    version=ContainerVersion.V1,
                    algorithm=self.algorithm,
                    kdf=KDFType.SCRYPT,
                    flags=flags,
                    scrypt_params=scrypt_params,
                    aad=aad
                )
                
                ContainerV1Writer.write_header(f, header)
                ContainerV1Writer.write_chunk_header(f, len(chunks))
                for nonce, ct in chunks:
                    ContainerV1Writer.write_chunk(f, nonce, ct)
            else:
                # Simple mode: read all, encrypt all
                plaintext = src_path.read_bytes()
                
                if progress_callback:
                    progress_callback(0, len(plaintext), "Encrypting...")
                
                nonce, ciphertext = self._aead.encrypt(key, plaintext, aad)
                
                header = ContainerHeader(
                    version=ContainerVersion.V1,
                    algorithm=self.algorithm,
                    kdf=KDFType.SCRYPT,
                    flags=flags,
                    scrypt_params=scrypt_params,
                    nonce=nonce,
                    aad=aad
                )
                
                ContainerV1Writer.write_header(f, header)
                ContainerV1Writer.write_payload_simple(f, ciphertext)
                
                if progress_callback:
                    progress_callback(len(plaintext), len(plaintext), "Complete")
        
        return {"chunk_count": metadata.chunk_count if use_chunked else 0}
    
    def _encrypt_v2(self, src_path: Path, dst_path: Path, key: bytes,
                    metadata: ContainerMetadata, scrypt_params: ScryptParams,
                    flags: int, use_chunked: bool,
                    progress_callback: Optional[ProgressCallback]) -> Dict:
        """Encrypt using V2 format."""
        ensure_parent_exists(dst_path)
        
        with atomic_write(dst_path) as f:
            if use_chunked:
                base_nonce = generate_nonce()
                
                # Calculate chunk count BEFORE encryption so AAD is consistent
                file_size = src_path.stat().st_size
                chunk_count = (file_size + self.chunk_size - 1) // self.chunk_size
                metadata.chunk_count = chunk_count
                
                # Now encrypt with the final AAD
                chunks = self._encrypt_chunked_v2(
                    src_path, key, base_nonce, metadata, progress_callback
                )
                
                # Update actual chunk count (should match)
                metadata.chunk_count = len(chunks)
                aad = metadata.to_json_bytes()
                
                header = ContainerHeader(
                    version=ContainerVersion.V2,
                    algorithm=self.algorithm,
                    kdf=KDFType.SCRYPT,
                    flags=flags,
                    scrypt_params=scrypt_params,
                    aad=aad
                )
                
                ContainerV2Writer.write_header(f, header, self.compression)
                ContainerV2Writer.write_chunk_table_header(
                    f, base_nonce, len(chunks), self.chunk_size
                )
                for idx, ct in enumerate(chunks):
                    ContainerV2Writer.write_chunk(f, idx, ct)
            else:
                # Read and optionally compress
                plaintext = src_path.read_bytes()
                
                if progress_callback:
                    progress_callback(0, len(plaintext), "Processing...")
                
                if self.compression != CompressionType.NONE:
                    plaintext = Compression.compress(plaintext, self.compression)
                
                aad = metadata.to_json_bytes()
                nonce, ciphertext = self._aead.encrypt(key, plaintext, aad)
                
                header = ContainerHeader(
                    version=ContainerVersion.V2,
                    algorithm=self.algorithm,
                    kdf=KDFType.SCRYPT,
                    flags=flags,
                    scrypt_params=scrypt_params,
                    aad=aad
                )
                
                ContainerV2Writer.write_header(f, header, self.compression)
                ContainerV2Writer.write_payload_simple(f, nonce, ciphertext)
                
                if progress_callback:
                    progress_callback(metadata.original_size, metadata.original_size, "Complete")
        
        return {"chunk_count": metadata.chunk_count if use_chunked else 0}
    
    def _encrypt_chunked_v1(self, src_path: Path, key: bytes, aad_base: bytes,
                           progress_callback: Optional[ProgressCallback]
                           ) -> List[Tuple[bytes, bytes]]:
        """Encrypt file in chunks (V1 format)."""
        chunks = []
        total_size = src_path.stat().st_size
        processed = 0
        
        for chunk_idx, chunk_data in enumerate(read_chunks(src_path, self.chunk_size)):
            # Include chunk index in AAD for ordering protection
            import struct
            chunk_aad = aad_base + struct.pack('<I', chunk_idx)
            
            nonce, ciphertext = self._aead.encrypt(key, chunk_data, chunk_aad)
            chunks.append((nonce, ciphertext))
            
            processed += len(chunk_data)
            if progress_callback is not None:
                progress_callback(processed, total_size, f"Chunk {chunk_idx + 1}")
        
        return chunks
    
    def _encrypt_chunked_v2(self, src_path: Path, key: bytes, base_nonce: bytes,
                           metadata: ContainerMetadata,
                           progress_callback: Optional[ProgressCallback]
                           ) -> List[bytes]:
        """Encrypt file in chunks (V2 format with derived nonces)."""
        chunks = []
        total_size = src_path.stat().st_size
        processed = 0
        aad_base = metadata.to_json_bytes()
        
        for chunk_idx, chunk_data in enumerate(read_chunks(src_path, self.chunk_size)):
            # Optionally compress chunk
            if self.compression != CompressionType.NONE:
                chunk_data = Compression.compress(chunk_data, self.compression)
            
            # Derive unique nonce for this chunk
            chunk_nonce = ContainerV2Writer.derive_chunk_nonce(base_nonce, chunk_idx)
            
            # Include chunk index in AAD
            import struct
            chunk_aad = aad_base + struct.pack('<I', chunk_idx)
            
            ciphertext = self._aead.encrypt_with_nonce(key, chunk_nonce, chunk_data, chunk_aad)
            chunks.append(ciphertext)
            
            processed += len(chunk_data)
            if progress_callback is not None:
                progress_callback(processed, total_size, f"Chunk {chunk_idx + 1}")
        
        return chunks
    
    def decrypt_file(self, src_path: Union[str, Path], dst_path: Union[str, Path],
                     password: str,
                     keyfile: Optional[Union[str, Path]] = None,
                     progress_callback: Optional[ProgressCallback] = None) -> Dict:
        """
        Decrypt a .codi file.
        
        Args:
            src_path: Source .codi file path
            dst_path: Destination file path
            password: Decryption password
            keyfile: Optional keyfile for 2FA
            progress_callback: Progress callback
        
        Returns:
            Dict with operation details
        
        Raises:
            IntegrityError: If authentication fails
        """
        src_path = normalize_path(src_path)
        dst_path = normalize_path(dst_path)
        
        if keyfile:
            keyfile = normalize_path(keyfile)
        else:
            keyfile = None
        
        if not src_path.exists():
            raise FileNotFoundError(str(src_path))
        
        # Detect version
        container_version = detect_version(src_path)
        
        if container_version == 1:
            return self._decrypt_v1(src_path, dst_path, password, keyfile, progress_callback)
        else:
            return self._decrypt_v2(src_path, dst_path, password, keyfile, progress_callback)
    
    def _decrypt_v1(self, src_path: Path, dst_path: Path, password: str,
                    keyfile: Optional[Path],
                    progress_callback: Optional[ProgressCallback]) -> Dict:
        """Decrypt V1 container."""
        with open(src_path, 'rb') as f:
            header = ContainerV1Reader.read_header(f)
            
            # Derive key
            key = self._derive_key(password, header.scrypt_params.salt, keyfile)
            
            # Setup AEAD for this algorithm
            aead = AEAD(header.algorithm)
            
            is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
            
            ensure_parent_exists(dst_path)
            
            if is_chunked:
                with atomic_write(dst_path) as out_f:
                    for info, ciphertext in ContainerV1Reader.read_chunks(f):
                        import struct
                        chunk_aad = header.aad + struct.pack('<I', info.index)
                        plaintext = aead.decrypt(key, info.nonce, ciphertext, chunk_aad)
                        out_f.write(plaintext)
                        
                        if progress_callback is not None:
                            progress_callback(info.index + 1, 0, f"Chunk {info.index + 1}")
            else:
                ciphertext = ContainerV1Reader.read_payload_simple(f)
                
                if progress_callback:
                    progress_callback(0, len(ciphertext), "Decrypting...")
                
                plaintext = aead.decrypt(key, header.nonce, ciphertext, header.aad)
                
                with atomic_write(dst_path) as out_f:
                    out_f.write(plaintext)
                
                if progress_callback:
                    progress_callback(len(ciphertext), len(ciphertext), "Complete")
        
        # Parse metadata
        metadata = None
        if header.aad:
            try:
                metadata = ContainerMetadata.from_json_bytes(header.aad)
            except:
                pass
        
        return {
            "original_filename": metadata.original_filename if metadata else None,
            "created_at": metadata.created_at if metadata else None,
            "algorithm": header.algorithm.name,
            "chunked": is_chunked,
            "dst_size": dst_path.stat().st_size,
        }
    
    def _decrypt_v2(self, src_path: Path, dst_path: Path, password: str,
                    keyfile: Optional[Path],
                    progress_callback: Optional[ProgressCallback]) -> Dict:
        """Decrypt V2 container."""
        with open(src_path, 'rb') as f:
            header, compression = ContainerV2Reader.read_header(f)
            
            # Derive key
            key = self._derive_key(password, header.scrypt_params.salt, keyfile)
            
            # Setup AEAD
            aead = AEAD(header.algorithm)
            
            is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
            
            ensure_parent_exists(dst_path)
            
            if is_chunked:
                base_nonce, chunk_table = ContainerV2Reader.read_chunk_table(f)
                
                with atomic_write(dst_path) as out_f:
                    # Read chunks manually
                    chunk_idx = 0
                    while True:
                        import struct
                        chunk_header = f.read(8)
                        if len(chunk_header) < 8:
                            break
                        
                        idx, ct_len = struct.unpack('<II', chunk_header)
                        ciphertext = f.read(ct_len)
                        
                        # Derive nonce
                        chunk_nonce = ContainerV2Reader.derive_chunk_nonce(base_nonce, idx)
                        
                        # AAD with chunk index
                        chunk_aad = header.aad + struct.pack('<I', idx)
                        
                        plaintext = aead.decrypt(key, chunk_nonce, ciphertext, chunk_aad)
                        
                        # Decompress if needed
                        if compression != CompressionType.NONE:
                            plaintext = Compression.decompress(plaintext, compression)
                        
                        out_f.write(plaintext)
                        
                        if progress_callback is not None:
                            progress_callback(idx + 1, chunk_table.total_chunks, f"Chunk {idx + 1}")
                        
                        chunk_idx += 1
            else:
                nonce, ciphertext = ContainerV2Reader.read_payload_simple(f)
                
                if progress_callback:
                    progress_callback(0, len(ciphertext), "Decrypting...")
                
                plaintext = aead.decrypt(key, nonce, ciphertext, header.aad)
                
                # Decompress if needed
                if compression != CompressionType.NONE:
                    plaintext = Compression.decompress(plaintext, compression)
                
                with atomic_write(dst_path) as out_f:
                    out_f.write(plaintext)
                
                if progress_callback:
                    progress_callback(len(ciphertext), len(ciphertext), "Complete")
        
        # Parse metadata
        metadata = None
        if header.aad:
            try:
                metadata = ContainerMetadata.from_json_bytes(header.aad)
            except:
                pass
        
        return {
            "original_filename": metadata.original_filename if metadata else None,
            "created_at": metadata.created_at if metadata else None,
            "algorithm": header.algorithm.name,
            "chunked": is_chunked,
            "compressed": compression != CompressionType.NONE,
            "dst_size": dst_path.stat().st_size,
        }
    
    def verify_file(self, path: Union[str, Path], password: str,
                    keyfile: Optional[Union[str, Path]] = None) -> Tuple[bool, Dict]:
        """
        Verify a .codi file integrity without full decryption.
        
        Args:
            path: Path to .codi file
            password: Password
            keyfile: Optional keyfile
        
        Returns:
            Tuple of (is_valid, info_dict)
        """
        path = normalize_path(path)
        
        if keyfile:
            keyfile = normalize_path(keyfile)
        else:
            keyfile = None
            
        try:
            # Get info first
            info = get_container_info(path)
            
            # Try to decrypt (will fail if wrong password)
            with open(path, 'rb') as f:
                version = detect_version(path)
                f.seek(0)
                
                if version == 1:
                    header = ContainerV1Reader.read_header(f)
                    key = self._derive_key(password, header.scrypt_params.salt, keyfile)
                    aead = AEAD(header.algorithm)
                    
                    is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
                    
                    if is_chunked:
                        # Verify first chunk
                        chunk_count = ContainerV1Reader.count_chunks(f)
                        f.seek(f.tell() - 4)
                        
                        for (chunk_info, ciphertext) in ContainerV1Reader.read_chunks(f):
                            import struct
                            chunk_aad = header.aad + struct.pack('<I', chunk_info.index)
                            aead.decrypt(key, chunk_info.nonce, ciphertext, chunk_aad)
                            break  # Just verify first chunk
                    else:
                        ciphertext = ContainerV1Reader.read_payload_simple(f)
                        aead.decrypt(key, header.nonce, ciphertext, header.aad)
                
                else:
                    header, compression = ContainerV2Reader.read_header(f)
                    key = self._derive_key(password, header.scrypt_params.salt, keyfile)
                    aead = AEAD(header.algorithm)
                    
                    is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
                    
                    if is_chunked:
                        base_nonce, _ = ContainerV2Reader.read_chunk_table(f)
                        # Verify first chunk
                        import struct
                        chunk_header = f.read(8)
                        idx, ct_len = struct.unpack('<II', chunk_header)
                        ciphertext = f.read(ct_len)
                        chunk_nonce = ContainerV2Reader.derive_chunk_nonce(base_nonce, idx)
                        chunk_aad = header.aad + struct.pack('<I', idx)
                        aead.decrypt(key, chunk_nonce, ciphertext, chunk_aad)
                    else:
                        nonce, ciphertext = ContainerV2Reader.read_payload_simple(f)
                        aead.decrypt(key, nonce, ciphertext, header.aad)
            
            info["valid"] = True
            return True, info
            
        except IntegrityError:
            return False, {"valid": False, "error": "Integrity check failed"}
        except Exception as e:
            return False, {"valid": False, "error": str(e)}
    
    def get_file_info(self, path: Union[str, Path]) -> Dict:
        """
        Get .codi file information without password.
        
        Args:
            path: Path to .codi file
        
        Returns:
            Dict with file information
        """
        path = normalize_path(path)
        return get_container_info(path)
