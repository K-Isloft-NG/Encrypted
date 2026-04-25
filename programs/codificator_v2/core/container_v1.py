"""
Container format V1 reader/writer.

This module provides backward compatibility with .codi V1 format
created by Codificator V0.

V1 Format Structure:
    Header (8 bytes):
        - Magic: "CODI" (4 bytes)
        - Version: 1 (1 byte)
        - Algorithm ID: 1=AES-GCM, 2=ChaCha20 (1 byte)
        - KDF ID: 1=scrypt (1 byte)
        - Flags: bitfield (1 byte)
    
    KDF Params:
        - salt_len: 1 byte
        - salt: N bytes
        - n: 4 bytes (uint32 LE)
        - r: 4 bytes (uint32 LE)
        - p: 4 bytes (uint32 LE)
        - dklen: 2 bytes (uint16 LE)
    
    AEAD Params (non-chunked):
        - nonce_len: 1 byte
        - nonce: N bytes
        - aad_len: 4 bytes (uint32 LE)
        - aad: N bytes
    
    Payload (non-chunked):
        - ciphertext_len: 8 bytes (uint64 LE)
        - ciphertext: N bytes (includes tag)
    
    Payload (chunked):
        - chunk_count: 4 bytes (uint32 LE)
        - For each chunk:
            - nonce: 12 bytes
            - ct_len: 4 bytes (uint32 LE)
            - ciphertext: N bytes
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Generator, Optional, Tuple, Union, List

from . import (
    Algorithm, KDFType, ContainerVersion,
    ScryptParams, ContainerHeader, ContainerMetadata, ChunkInfo,
    CODI_MAGIC_V1, DEFAULT_NONCE_SIZE
)
from .errors import ContainerFormatError, ContainerVersionError


class ContainerV1Reader:
    """Reader for .codi V1 format."""
    
    @staticmethod
    def read_header(f: BinaryIO) -> ContainerHeader:
        """
        Read container header from file.
        
        Args:
            f: Binary file object positioned at start
        
        Returns:
            ContainerHeader with parsed values
        
        Raises:
            ContainerFormatError: If format is invalid
            ContainerVersionError: If version is not 1
        """
        # Read magic
        magic = f.read(4)
        if magic != CODI_MAGIC_V1:
            raise ContainerFormatError(
                f"Invalid magic bytes: expected {CODI_MAGIC_V1!r}, got {magic!r}"
            )
        
        # Read header fields
        data = f.read(4)
        if len(data) < 4:
            raise ContainerFormatError("Truncated header")
        
        version, algo_id, kdf_id, flags = struct.unpack('<BBBB', data)
        
        if version != 1:
            raise ContainerVersionError(version, [1])
        
        try:
            algorithm = Algorithm(algo_id)
        except ValueError:
            raise ContainerFormatError(f"Unknown algorithm ID: {algo_id}")
        
        try:
            kdf = KDFType(kdf_id)
        except ValueError:
            raise ContainerFormatError(f"Unknown KDF ID: {kdf_id}")
        
        # Read scrypt params
        salt_len = struct.unpack('<B', f.read(1))[0]
        salt = f.read(salt_len)
        if len(salt) != salt_len:
            raise ContainerFormatError("Truncated salt")
        
        n, r, p = struct.unpack('<III', f.read(12))
        dklen = struct.unpack('<H', f.read(2))[0]
        
        scrypt_params = ScryptParams(salt=salt, n=n, r=r, p=p, dklen=dklen)
        
        # Read nonce (only for non-chunked)
        is_chunked = bool(flags & ContainerHeader.FLAG_CHUNKED)
        if is_chunked:
            nonce = b''
        else:
            nonce_len = struct.unpack('<B', f.read(1))[0]
            nonce = f.read(nonce_len)
            if len(nonce) != nonce_len:
                raise ContainerFormatError("Truncated nonce")
        
        # Read AAD
        aad_len = struct.unpack('<I', f.read(4))[0]
        aad = f.read(aad_len) if aad_len > 0 else b''
        if len(aad) != aad_len:
            raise ContainerFormatError("Truncated AAD")
        
        return ContainerHeader(
            version=ContainerVersion.V1,
            algorithm=algorithm,
            kdf=kdf,
            flags=flags,
            scrypt_params=scrypt_params,
            nonce=nonce,
            aad=aad
        )
    
    @staticmethod
    def read_payload_simple(f: BinaryIO) -> bytes:
        """Read non-chunked payload."""
        ct_len = struct.unpack('<Q', f.read(8))[0]
        ciphertext = f.read(ct_len)
        if len(ciphertext) != ct_len:
            raise ContainerFormatError("Truncated ciphertext")
        return ciphertext
    
    @staticmethod
    def read_chunks(f: BinaryIO) -> Generator[Tuple[ChunkInfo, bytes], None, None]:
        """Read chunked payload as generator."""
        chunk_count = struct.unpack('<I', f.read(4))[0]
        
        for i in range(chunk_count):
            nonce = f.read(DEFAULT_NONCE_SIZE)
            if len(nonce) != DEFAULT_NONCE_SIZE:
                raise ContainerFormatError(f"Truncated chunk {i} nonce")
            
            ct_len = struct.unpack('<I', f.read(4))[0]
            ciphertext = f.read(ct_len)
            if len(ciphertext) != ct_len:
                raise ContainerFormatError(f"Truncated chunk {i} ciphertext")
            
            yield ChunkInfo(
                index=i,
                nonce=nonce,
                ciphertext_length=ct_len
            ), ciphertext
    
    @staticmethod
    def count_chunks(f: BinaryIO) -> int:
        """Read chunk count without reading chunks."""
        return struct.unpack('<I', f.read(4))[0]


class ContainerV1Writer:
    """Writer for .codi V1 format."""
    
    @staticmethod
    def write_header(f: BinaryIO, header: ContainerHeader) -> None:
        """
        Write container header to file.
        
        Args:
            f: Binary file object
            header: Header to write
        """
        # Magic + version + algo + kdf + flags
        f.write(CODI_MAGIC_V1)
        f.write(struct.pack('<BBBB',
            1,  # Version 1
            header.algorithm.value,
            header.kdf.value,
            header.flags
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
        
        # Nonce (only for non-chunked)
        is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
        if not is_chunked:
            f.write(struct.pack('<B', len(header.nonce)))
            f.write(header.nonce)
        
        # AAD
        f.write(struct.pack('<I', len(header.aad)))
        if header.aad:
            f.write(header.aad)
    
    @staticmethod
    def write_payload_simple(f: BinaryIO, ciphertext: bytes) -> None:
        """Write non-chunked payload."""
        f.write(struct.pack('<Q', len(ciphertext)))
        f.write(ciphertext)
    
    @staticmethod
    def write_chunk_header(f: BinaryIO, chunk_count: int) -> None:
        """Write chunk count header."""
        f.write(struct.pack('<I', chunk_count))
    
    @staticmethod
    def write_chunk(f: BinaryIO, nonce: bytes, ciphertext: bytes) -> None:
        """Write a single chunk."""
        f.write(nonce)
        f.write(struct.pack('<I', len(ciphertext)))
        f.write(ciphertext)


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def read_v1_container(path: Path) -> Tuple[ContainerHeader, Union[bytes, List[Tuple[ChunkInfo, bytes]]]]:
    """
    Read a V1 container file completely.
    
    Args:
        path: Path to .codi file
    
    Returns:
        Tuple of (header, ciphertext)
    
    Note: For chunked files, returns concatenated ciphertext.
          Use read_v1_chunks() for streaming.
    """
    with open(path, 'rb') as f:
        header = ContainerV1Reader.read_header(f)
        
        if header.flags & ContainerHeader.FLAG_CHUNKED:
            # Read all chunks
            chunks_data = []
            for info, ct in ContainerV1Reader.read_chunks(f):
                chunks_data.append((info, ct))
            return header, chunks_data
        else:
            ciphertext = ContainerV1Reader.read_payload_simple(f)
            return header, ciphertext


def get_v1_info(path: Path) -> dict:
    """
    Get information about a V1 container without reading payload.
    
    Args:
        path: Path to .codi file
    
    Returns:
        Dict with container information
    """
    with open(path, 'rb') as f:
        header = ContainerV1Reader.read_header(f)
        
        metadata = None
        if header.aad:
            try:
                metadata = ContainerMetadata.from_json_bytes(header.aad)
            except:
                pass
        
        is_chunked = bool(header.flags & ContainerHeader.FLAG_CHUNKED)
        
        info = {
            "version": 1,
            "algorithm": header.algorithm.name,
            "kdf": header.kdf.name,
            "chunked": is_chunked,
            "scrypt_n": header.scrypt_params.n,
            "scrypt_r": header.scrypt_params.r,
            "scrypt_p": header.scrypt_params.p,
        }
        
        if metadata:
            info["original_filename"] = metadata.original_filename
            info["created_at"] = metadata.created_at
            info["tool_version"] = metadata.tool_version
            if metadata.chunked:
                info["chunk_size"] = metadata.chunk_size
                info["chunk_count"] = metadata.chunk_count
        
        return info
