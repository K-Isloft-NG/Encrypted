"""
Container format V2 reader/writer.

V2 adds:
- Compression support (zlib)
- Improved chunk table
- Multi-file container support (optional)
- Better metadata handling

V2 Format Structure:
    Header (12 bytes):
        - Magic: "CDI2" (4 bytes)
        - Version: 2 (1 byte)
        - Algorithm ID: 1=AES-GCM, 2=ChaCha20 (1 byte)
        - KDF ID: 1=scrypt (1 byte)
        - Compression: 0=none, 1=zlib (1 byte)
        - Flags: bitfield (2 bytes)
        - Reserved: (2 bytes)
    
    KDF Params:
        - salt_len: 1 byte
        - salt: N bytes
        - n: 4 bytes (uint32 LE)
        - r: 4 bytes (uint32 LE)
        - p: 4 bytes (uint32 LE)
        - dklen: 2 bytes (uint16 LE)
    
    Metadata:
        - aad_len: 4 bytes (uint32 LE)
        - aad: N bytes (JSON)
    
    Payload (non-chunked):
        - nonce: 12 bytes
        - ciphertext_len: 8 bytes (uint64 LE)
        - ciphertext: N bytes (includes tag)
    
    Payload (chunked):
        - base_nonce: 12 bytes
        - chunk_count: 4 bytes (uint32 LE)
        - chunk_size: 4 bytes (uint32 LE)
        - For each chunk:
            - chunk_idx: 4 bytes (uint32 LE)
            - ct_len: 4 bytes (uint32 LE)
            - ciphertext: N bytes
        (Nonce per chunk = base_nonce XOR chunk_idx)
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import BinaryIO, Generator, List, Optional, Tuple

from . import (
    Algorithm, KDFType, CompressionType, ContainerVersion,
    ScryptParams, ContainerHeader, ContainerMetadata, ChunkInfo, ChunkTable,
    CODI_MAGIC_V2, DEFAULT_NONCE_SIZE, DEFAULT_CHUNK_SIZE
)
from .errors import ContainerFormatError, ContainerVersionError


class ContainerV2Reader:
    """Reader for .codi V2 format."""
    
    @staticmethod
    def read_header(f: BinaryIO) -> Tuple[ContainerHeader, CompressionType]:
        """
        Read V2 container header from file.
        
        Args:
            f: Binary file object positioned at start
        
        Returns:
            Tuple of (ContainerHeader, CompressionType)
        
        Raises:
            ContainerFormatError: If format is invalid
            ContainerVersionError: If version is not 2
        """
        # Read magic
        magic = f.read(4)
        if magic != CODI_MAGIC_V2:
            raise ContainerFormatError(
                f"Invalid magic bytes: expected {CODI_MAGIC_V2!r}, got {magic!r}"
            )
        
        # Read header fields (8 bytes)
        data = f.read(8)
        if len(data) < 8:
            raise ContainerFormatError("Truncated header")
        
        version, algo_id, kdf_id, comp_id, flags_lo, flags_hi, _, _ = struct.unpack(
            '<BBBBBBBB', data
        )
        flags = flags_lo | (flags_hi << 8)
        
        if version != 2:
            raise ContainerVersionError(version, [2])
        
        try:
            algorithm = Algorithm(algo_id)
        except ValueError:
            raise ContainerFormatError(f"Unknown algorithm ID: {algo_id}")
        
        try:
            kdf = KDFType(kdf_id)
        except ValueError:
            raise ContainerFormatError(f"Unknown KDF ID: {kdf_id}")
        
        try:
            compression = CompressionType(comp_id)
        except ValueError:
            compression = CompressionType.NONE
        
        # Read scrypt params
        salt_len = struct.unpack('<B', f.read(1))[0]
        salt = f.read(salt_len)
        if len(salt) != salt_len:
            raise ContainerFormatError("Truncated salt")
        
        n, r, p = struct.unpack('<III', f.read(12))
        dklen = struct.unpack('<H', f.read(2))[0]
        
        scrypt_params = ScryptParams(salt=salt, n=n, r=r, p=p, dklen=dklen)
        
        # Read AAD/metadata
        aad_len = struct.unpack('<I', f.read(4))[0]
        aad = f.read(aad_len) if aad_len > 0 else b''
        if len(aad) != aad_len:
            raise ContainerFormatError("Truncated AAD")
        
        header = ContainerHeader(
            version=ContainerVersion.V2,
            algorithm=algorithm,
            kdf=kdf,
            flags=flags,
            scrypt_params=scrypt_params,
            aad=aad
        )
        
        return header, compression
    
    @staticmethod
    def read_payload_simple(f: BinaryIO) -> Tuple[bytes, bytes]:
        """
        Read non-chunked payload.
        
        Returns:
            Tuple of (nonce, ciphertext)
        """
        nonce = f.read(DEFAULT_NONCE_SIZE)
        if len(nonce) != DEFAULT_NONCE_SIZE:
            raise ContainerFormatError("Truncated nonce")
        
        ct_len = struct.unpack('<Q', f.read(8))[0]
        ciphertext = f.read(ct_len)
        if len(ciphertext) != ct_len:
            raise ContainerFormatError("Truncated ciphertext")
        
        return nonce, ciphertext
    
    @staticmethod
    def read_chunk_table(f: BinaryIO) -> Tuple[bytes, ChunkTable]:
        """
        Read chunk table header.
        
        Returns:
            Tuple of (base_nonce, ChunkTable)
        """
        base_nonce = f.read(DEFAULT_NONCE_SIZE)
        if len(base_nonce) != DEFAULT_NONCE_SIZE:
            raise ContainerFormatError("Truncated base nonce")
        
        chunk_count, chunk_size = struct.unpack('<II', f.read(8))
        
        table = ChunkTable(
            chunk_size=chunk_size,
            total_chunks=chunk_count,
            chunks=[]
        )
        
        return base_nonce, table
    
    @staticmethod
    def read_chunks(f: BinaryIO, base_nonce: bytes) -> Generator[Tuple[ChunkInfo, bytes], None, None]:
        """
        Read chunks as generator.
        
        Args:
            f: File positioned after chunk table header
            base_nonce: Base nonce from chunk table
        
        Yields:
            Tuple of (ChunkInfo, ciphertext)
        """
        # First read chunk count (already read in read_chunk_table but we may not have it)
        # Re-read from current position
        while True:
            chunk_header = f.read(8)
            if len(chunk_header) < 8:
                break
            
            chunk_idx, ct_len = struct.unpack('<II', chunk_header)
            
            ciphertext = f.read(ct_len)
            if len(ciphertext) != ct_len:
                raise ContainerFormatError(f"Truncated chunk {chunk_idx}")
            
            # Derive chunk nonce: base_nonce XOR chunk_idx
            nonce = ContainerV2Reader.derive_chunk_nonce(base_nonce, chunk_idx)
            
            info = ChunkInfo(
                index=chunk_idx,
                nonce=nonce,
                ciphertext_length=ct_len
            )
            
            yield info, ciphertext
    
    @staticmethod
    def derive_chunk_nonce(base_nonce: bytes, chunk_idx: int) -> bytes:
        """
        Derive unique nonce for a chunk.
        
        Method: XOR last 4 bytes of base_nonce with chunk index
        """
        nonce = bytearray(base_nonce)
        # XOR chunk index into last 4 bytes
        idx_bytes = struct.pack('<I', chunk_idx)
        for i in range(4):
            nonce[8 + i] ^= idx_bytes[i]
        return bytes(nonce)


class ContainerV2Writer:
    """Writer for .codi V2 format."""
    
    @staticmethod
    def write_header(f: BinaryIO, header: ContainerHeader, 
                     compression: CompressionType = CompressionType.NONE) -> None:
        """
        Write V2 container header to file.
        
        Args:
            f: Binary file object
            header: Header to write
            compression: Compression type
        """
        # Magic
        f.write(CODI_MAGIC_V2)
        
        # Header fields
        flags_lo = header.flags & 0xFF
        flags_hi = (header.flags >> 8) & 0xFF
        f.write(struct.pack('<BBBBBBBB',
            2,  # Version 2
            header.algorithm.value,
            header.kdf.value,
            compression.value,
            flags_lo,
            flags_hi,
            0, 0  # Reserved
        ))
        
        # Scrypt params
        salt = header.scrypt_params.salt
        f.write(struct.pack('<B', len(salt)))
        f.write(salt)
        f.write(struct.pack('<III',
            header.scrypt_params.n,
            header.scrypt_params.r,
            header.scrypt_params.p
        ))
        f.write(struct.pack('<H', header.scrypt_params.dklen))
        
        # AAD/metadata
        f.write(struct.pack('<I', len(header.aad)))
        if header.aad:
            f.write(header.aad)
    
    @staticmethod
    def write_payload_simple(f: BinaryIO, nonce: bytes, ciphertext: bytes) -> None:
        """Write non-chunked payload."""
        f.write(nonce)
        f.write(struct.pack('<Q', len(ciphertext)))
        f.write(ciphertext)
    
    @staticmethod
    def write_chunk_table_header(f: BinaryIO, base_nonce: bytes, 
                                  chunk_count: int, chunk_size: int) -> None:
        """Write chunk table header."""
        f.write(base_nonce)
        f.write(struct.pack('<II', chunk_count, chunk_size))
    
    @staticmethod
    def write_chunk(f: BinaryIO, chunk_idx: int, ciphertext: bytes) -> None:
        """Write a single chunk."""
        f.write(struct.pack('<II', chunk_idx, len(ciphertext)))
        f.write(ciphertext)
    
    @staticmethod
    def derive_chunk_nonce(base_nonce: bytes, chunk_idx: int) -> bytes:
        """Derive unique nonce for a chunk (same as reader)."""
        return ContainerV2Reader.derive_chunk_nonce(base_nonce, chunk_idx)


# ══════════════════════════════════════════════════════════════════════════════
# COMPRESSION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

class Compression:
    """Compression utilities for V2 containers."""
    
    @staticmethod
    def compress(data: bytes, 
                 compression: CompressionType = CompressionType.ZLIB,
                 level: int = 6) -> bytes:
        """
        Compress data.
        
        Args:
            data: Data to compress
            compression: Compression type
            level: Compression level (1-9)
        
        Returns:
            Compressed data
        """
        if compression == CompressionType.NONE:
            return data
        elif compression == CompressionType.ZLIB:
            return zlib.compress(data, level)
        else:
            return data
    
    @staticmethod
    def decompress(data: bytes, compression: CompressionType) -> bytes:
        """
        Decompress data.
        
        Args:
            data: Compressed data
            compression: Compression type used
        
        Returns:
            Decompressed data
        """
        if compression == CompressionType.NONE:
            return data
        elif compression == CompressionType.ZLIB:
            return zlib.decompress(data)
        else:
            return data


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def detect_version(path: Path) -> int:
    """
    Detect container version from file.
    
    Args:
        path: Path to .codi file
    
    Returns:
        Version number (1 or 2)
    
    Raises:
        ContainerFormatError: If file is not a valid container
    """
    from . import CODI_MAGIC_V1
    
    with open(path, 'rb') as f:
        magic = f.read(4)
        
        if magic == CODI_MAGIC_V1:
            return 1
        elif magic == CODI_MAGIC_V2:
            return 2
        else:
            raise ContainerFormatError(f"Unknown container format: {magic!r}")


def get_v2_info(path: Path) -> dict:
    """
    Get information about a V2 container without reading payload.
    
    Args:
        path: Path to .codi file
    
    Returns:
        Dict with container information
    """
    with open(path, 'rb') as f:
        header, compression = ContainerV2Reader.read_header(f)
        
        metadata = None
        if header.aad:
            try:
                metadata = ContainerMetadata.from_json_bytes(header.aad)
            except:
                pass
        
        is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
        is_compressed = bool(header.flags & ContainerHeader.FLAG_COMPRESSED)
        
        info = {
            "version": 2,
            "algorithm": header.algorithm.name,
            "kdf": header.kdf.name,
            "chunked": is_chunked,
            "compressed": is_compressed,
            "compression_type": compression.name,
            "scrypt_n": header.scrypt_params.n,
            "scrypt_r": header.scrypt_params.r,
            "scrypt_p": header.scrypt_params.p,
        }
        
        if metadata:
            info["original_filename"] = metadata.original_filename
            info["created_at"] = metadata.created_at
            info["tool_version"] = metadata.tool_version
            info["original_size"] = metadata.original_size
            if metadata.chunked:
                info["chunk_size"] = metadata.chunk_size
                info["chunk_count"] = metadata.chunk_count
        
        return info


def get_container_info(path: Path) -> dict:
    """
    Get information about any container version.
    
    Args:
        path: Path to .codi file
    
    Returns:
        Dict with container information
    """
    version = detect_version(path)
    
    if version == 1:
        from .container_v1 import get_v1_info
        return get_v1_info(path)
    elif version == 2:
        return get_v2_info(path)
    else:
        raise ContainerFormatError(f"Unsupported version: {version}")
