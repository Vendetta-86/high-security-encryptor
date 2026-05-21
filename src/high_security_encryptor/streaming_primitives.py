"""Shared primitives for the HSE1 streaming container."""

from __future__ import annotations

import struct

from .kdf_profiles import KEY_LEN, derive_argon2id_key, get_kdf_profile

HEADER_MAGIC = b"HSE1"
VERSION = 1
FLAGS = 0
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DIGEST_LEN = 32
DEFAULT_CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
_HSE1_KDF_PROFILE = get_kdf_profile("compatible")
ARGON_TIME_COST = _HSE1_KDF_PROFILE.time_cost
ARGON_MEMORY_COST = _HSE1_KDF_PROFILE.memory_cost_kib
ARGON_PARALLELISM = _HSE1_KDF_PROFILE.parallelism

HEADER_STRUCT = struct.Struct(">4sBBBBII")
CHUNK_HEADER_STRUCT = struct.Struct(">QI")
TRAILER_STRUCT = struct.Struct(">QQ32s16s")
TRAILER_NONCE_INDEX = (1 << 64) - 1


class StreamingFormatError(Exception):
    """Base class for streaming container errors."""


class LegacyFormatDetected(StreamingFormatError):
    """Raised when the legacy compatibility path should handle a file."""


class IntegrityError(StreamingFormatError):
    """Raised when authentication, structure, or consistency checks fail."""


class HeaderError(StreamingFormatError):
    """Raised when the container header is corrupted or unsupported."""


def build_header(chunk_size: int, salt: bytes, base_nonce: bytes) -> bytes:
    """Build the fixed header plus salt and base nonce."""

    if len(salt) != SALT_LEN:
        raise ValueError("invalid salt length")
    if len(base_nonce) != NONCE_LEN:
        raise ValueError("invalid nonce length")
    fixed = HEADER_STRUCT.pack(
        HEADER_MAGIC,
        VERSION,
        FLAGS,
        SALT_LEN,
        NONCE_LEN,
        chunk_size,
        0,
    )
    return fixed + salt + base_nonce


def parse_header(file_obj) -> tuple[bytes, bytes, int]:
    """Read and validate a streaming container header from an open binary file."""

    fixed = file_obj.read(HEADER_STRUCT.size)
    if len(fixed) != HEADER_STRUCT.size:
        raise HeaderError("truncated header")
    magic, version, _flags, salt_len, nonce_len, chunk_size, _reserved = HEADER_STRUCT.unpack(fixed)
    if magic != HEADER_MAGIC:
        raise LegacyFormatDetected("legacy or unknown format; legacy dispatch path must be implemented")
    if version != VERSION:
        raise HeaderError(f"unsupported version: {version}")
    if salt_len != SALT_LEN or nonce_len != NONCE_LEN:
        raise HeaderError("unexpected salt or nonce size")
    salt = file_obj.read(salt_len)
    base_nonce = file_obj.read(nonce_len)
    if len(salt) != salt_len or len(base_nonce) != nonce_len:
        raise HeaderError("truncated header payload")
    return fixed + salt + base_nonce, salt, chunk_size


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the HSE1 file encryption key with the compatibility Argon2id profile."""

    return derive_argon2id_key(password, salt, _HSE1_KDF_PROFILE)


def derive_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Derive the nonce for a chunk or trailer from the base nonce and index."""

    nonce_int = int.from_bytes(base_nonce, "big") ^ chunk_index
    return nonce_int.to_bytes(len(base_nonce), "big")
