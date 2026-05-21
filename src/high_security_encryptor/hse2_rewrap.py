"""Experimental HSE2 rewrap helpers.

Rewrapping replaces mutable HSE2 key-wrapper metadata while preserving encrypted
payload bytes. Payload AAD must remain unchanged across the operation.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil

from .atomic_io import atomic_output_path, flush_file
from .hse2_header import HEADER_LENGTH_STRUCT, HSE2_MAGIC, HSE2Header, build_header_frame, build_hse2_header
from .hse2_streaming import KDF_SALT_LEN, read_hse2_header_frame
from .kdf_profiles import KDF_PROFILE_HARDENED, derive_argon2id_key, get_kdf_profile
from .key_wrapping import unwrap_data_key, wrap_data_key
from .streaming_primitives import IntegrityError


class HSE2RewrapError(Exception):
    """Raised when an HSE2 rewrap operation cannot be completed safely."""


def rewrap_hse2_file(
    source: str | Path,
    target: str | Path,
    old_secret: str,
    new_secret: str,
    *,
    new_kdf_profile_name: str = KDF_PROFILE_HARDENED,
) -> Path:
    """Write a rewrapped HSE2 file with unchanged payload bytes."""

    source_path = Path(source)
    target_path = Path(target)
    old_header, data_key, payload_offset = read_hse2_rewrap_source(source_path, old_secret)
    new_header_frame = build_rewrapped_hse2_header_frame(
        old_header,
        data_key,
        new_secret,
        new_kdf_profile_name=new_kdf_profile_name,
    )
    with source_path.open("rb") as src:
        src.seek(payload_offset)
        with atomic_output_path(target_path) as temp_target:
            with temp_target.open("wb") as dst:
                dst.write(new_header_frame)
                shutil.copyfileobj(src, dst)
                flush_file(dst)
    return target_path


def read_hse2_rewrap_source(source: str | Path, secret: str) -> tuple[HSE2Header, bytes, int]:
    """Read an HSE2 header and return the unwrapped data key plus payload offset."""

    source_path = Path(source)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not secret:
        raise ValueError("secret is required")
    min_size = len(HSE2_MAGIC) + HEADER_LENGTH_STRUCT.size
    if source_path.stat().st_size < min_size:
        raise IntegrityError("ciphertext is too short")
    with source_path.open("rb") as src:
        _header_frame, header = read_hse2_header_frame(src)
        payload_offset = src.tell()
    wrapper_key = derive_argon2id_key(secret, header.kdf_salt, header.kdf)
    try:
        data_key = unwrap_data_key(header.wrapped_data_key, wrapper_key)
    except ValueError as exc:
        raise IntegrityError("wrapped data key authentication failed") from exc
    return header, data_key, payload_offset


def build_rewrapped_hse2_header(
    old_header: HSE2Header,
    data_key: bytes,
    new_secret: str,
    *,
    new_kdf_profile_name: str = KDF_PROFILE_HARDENED,
) -> HSE2Header:
    """Build a replacement header that preserves the payload AAD context."""

    if not new_secret:
        raise ValueError("new_secret is required")
    new_salt = os.urandom(KDF_SALT_LEN)
    profile = get_kdf_profile(new_kdf_profile_name)
    wrapper_key = derive_argon2id_key(new_secret, new_salt, profile)
    wrapped_data_key = wrap_data_key(data_key, wrapper_key)
    new_header = build_hse2_header(
        kdf_profile_name=new_kdf_profile_name,
        kdf_salt=new_salt,
        wrapped_data_key=wrapped_data_key,
        base_nonce=old_header.base_nonce,
        chunk_size=old_header.chunk_size,
    )
    if new_header.associated_data() != old_header.associated_data():
        raise HSE2RewrapError("replacement header changes payload authentication context")
    return new_header


def build_rewrapped_hse2_header_frame(
    old_header: HSE2Header,
    data_key: bytes,
    new_secret: str,
    *,
    new_kdf_profile_name: str = KDF_PROFILE_HARDENED,
) -> bytes:
    """Build a replacement header frame for an existing HSE2 payload."""

    return build_header_frame(
        build_rewrapped_hse2_header(
            old_header,
            data_key,
            new_secret,
            new_kdf_profile_name=new_kdf_profile_name,
        )
    )
