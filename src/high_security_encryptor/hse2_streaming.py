"""Experimental HSE2 streaming file helpers.

These helpers exercise the HSE2 design without changing the existing HSE1 CLI
path. They encrypt payload chunks with a random DEK and wrap that DEK with a KEK
derived from the user password and the self-describing HSE2 KDF metadata.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct

from Crypto.Cipher import AES

from .atomic_io import atomic_output_path, flush_file
from .hse2_header import (
    HEADER_LENGTH_STRUCT,
    HSE2_MAGIC,
    HSE2Header,
    MAX_HEADER_JSON_LEN,
    build_header_frame,
    build_hse2_header,
)
from .kdf_profiles import KDF_PROFILE_HARDENED, derive_argon2id_key
from .key_wrapping import generate_data_key, unwrap_data_key, wrap_data_key
from .streaming_primitives import (
    CHUNK_HEADER_STRUCT,
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    NONCE_LEN,
    TAG_LEN,
    TRAILER_NONCE_INDEX,
    TRAILER_STRUCT,
    HeaderError,
    IntegrityError,
    derive_nonce,
)

KDF_SALT_LEN = 32


def encrypt_streaming_hse2(
    source: str | Path,
    target: str | Path,
    password: str,
    *,
    kdf_profile_name: str = KDF_PROFILE_HARDENED,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Path:
    """Encrypt a file into an experimental HSE2 streaming container."""

    source_path = Path(source)
    target_path = Path(target)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not password:
        raise ValueError("password is required")
    _validate_chunk_size(chunk_size)

    kdf_salt = os.urandom(KDF_SALT_LEN)
    base_nonce = os.urandom(NONCE_LEN)
    data_key = generate_data_key()
    wrapping_key = derive_argon2id_key(password, kdf_salt, get_profile_for_name(kdf_profile_name))
    wrapped_data_key = wrap_data_key(data_key, wrapping_key)
    header = build_hse2_header(
        kdf_profile_name=kdf_profile_name,
        kdf_salt=kdf_salt,
        wrapped_data_key=wrapped_data_key,
        base_nonce=base_nonce,
        chunk_size=chunk_size,
    )
    header_frame = build_header_frame(header)
    payload_aad = header.associated_data()

    total_plaintext_size = 0
    chunk_count = 0
    plaintext_digest = hashlib.sha256()

    with atomic_output_path(target_path) as temp_target:
        with source_path.open("rb") as src, temp_target.open("wb") as dst:
            dst.write(header_frame)
            while True:
                plaintext = src.read(chunk_size)
                if not plaintext:
                    break
                meta = CHUNK_HEADER_STRUCT.pack(chunk_count, len(plaintext))
                cipher = AES.new(data_key, AES.MODE_GCM, nonce=derive_nonce(base_nonce, chunk_count))
                cipher.update(payload_aad + meta)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                dst.write(meta)
                dst.write(tag)
                dst.write(ciphertext)
                total_plaintext_size += len(plaintext)
                plaintext_digest.update(plaintext)
                chunk_count += 1

            digest_bytes = plaintext_digest.digest()
            trailer_meta = struct.pack(">QQ32s", chunk_count, total_plaintext_size, digest_bytes)
            trailer_cipher = AES.new(data_key, AES.MODE_GCM, nonce=derive_nonce(base_nonce, TRAILER_NONCE_INDEX))
            trailer_cipher.update(payload_aad + trailer_meta)
            trailer_tag = trailer_cipher.encrypt_and_digest(b"")[1]
            dst.write(TRAILER_STRUCT.pack(chunk_count, total_plaintext_size, digest_bytes, trailer_tag))
            flush_file(dst)
    return target_path


def decrypt_streaming_hse2(source: str | Path, target: str | Path, password: str) -> Path:
    """Decrypt an experimental HSE2 streaming container."""

    source_path = Path(source)
    target_path = Path(target)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not password:
        raise ValueError("password is required")

    file_size = source_path.stat().st_size
    min_size = len(HSE2_MAGIC) + HEADER_LENGTH_STRUCT.size + TRAILER_STRUCT.size
    if file_size < min_size:
        raise IntegrityError("ciphertext is too short")

    with source_path.open("rb") as src:
        _header_frame, header = read_hse2_header_frame(src)
        if header.chunk_size <= 0 or header.chunk_size > MAX_CHUNK_SIZE:
            raise HeaderError("unsupported chunk size")
        payload_aad = header.associated_data()
        wrapping_key = derive_argon2id_key(password, header.kdf_salt, header.kdf)
        try:
            data_key = unwrap_data_key(header.wrapped_data_key, wrapping_key)
        except ValueError as exc:
            raise IntegrityError("wrapped data key authentication failed") from exc

        payload_end = file_size - TRAILER_STRUCT.size
        chunk_index = 0
        total_plaintext_size = 0
        plaintext_digest = hashlib.sha256()
        with atomic_output_path(target_path) as temp_target:
            with temp_target.open("wb") as dst:
                while src.tell() < payload_end:
                    meta = src.read(CHUNK_HEADER_STRUCT.size)
                    if len(meta) != CHUNK_HEADER_STRUCT.size:
                        raise IntegrityError("truncated chunk metadata")
                    read_index, plaintext_length = CHUNK_HEADER_STRUCT.unpack(meta)
                    if read_index != chunk_index:
                        raise IntegrityError("unexpected chunk order")
                    if plaintext_length == 0 or plaintext_length > header.chunk_size:
                        raise IntegrityError("invalid chunk length")
                    remaining_payload = payload_end - src.tell() - TAG_LEN
                    if plaintext_length > remaining_payload:
                        raise IntegrityError("chunk length exceeds remaining payload")
                    tag = src.read(TAG_LEN)
                    if len(tag) != TAG_LEN:
                        raise IntegrityError("truncated chunk tag")
                    ciphertext = src.read(plaintext_length)
                    if len(ciphertext) != plaintext_length:
                        raise IntegrityError("truncated chunk ciphertext")
                    cipher = AES.new(data_key, AES.MODE_GCM, nonce=derive_nonce(header.base_nonce, chunk_index))
                    cipher.update(payload_aad + meta)
                    try:
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    except ValueError as exc:
                        raise IntegrityError("chunk authentication failed") from exc
                    dst.write(plaintext)
                    total_plaintext_size += len(plaintext)
                    plaintext_digest.update(plaintext)
                    chunk_index += 1

                trailer_blob = src.read(TRAILER_STRUCT.size)
                if len(trailer_blob) != TRAILER_STRUCT.size:
                    raise IntegrityError("truncated trailer")
                expected_chunk_count, expected_plaintext_size, expected_digest, trailer_tag = TRAILER_STRUCT.unpack(trailer_blob)
                trailer_meta = struct.pack(">QQ32s", expected_chunk_count, expected_plaintext_size, expected_digest)
                trailer_cipher = AES.new(data_key, AES.MODE_GCM, nonce=derive_nonce(header.base_nonce, TRAILER_NONCE_INDEX))
                trailer_cipher.update(payload_aad + trailer_meta)
                try:
                    trailer_cipher.decrypt_and_verify(b"", trailer_tag)
                except ValueError as exc:
                    raise IntegrityError("trailer authentication failed") from exc
                if expected_chunk_count != chunk_index:
                    raise IntegrityError("chunk count mismatch")
                if expected_plaintext_size != total_plaintext_size:
                    raise IntegrityError("plaintext size mismatch")
                if expected_digest != plaintext_digest.digest():
                    raise IntegrityError("plaintext digest mismatch")
                flush_file(dst)
    return target_path


def read_hse2_header_frame(file_obj) -> tuple[bytes, HSE2Header]:
    """Read an HSE2 header frame from an open binary file."""

    prefix = file_obj.read(len(HSE2_MAGIC) + HEADER_LENGTH_STRUCT.size)
    if len(prefix) != len(HSE2_MAGIC) + HEADER_LENGTH_STRUCT.size:
        raise HeaderError("truncated HSE2 header frame")
    if prefix[: len(HSE2_MAGIC)] != HSE2_MAGIC:
        raise HeaderError("invalid HSE2 magic")
    (json_len,) = HEADER_LENGTH_STRUCT.unpack(prefix[len(HSE2_MAGIC) :])
    if json_len <= 0 or json_len > MAX_HEADER_JSON_LEN:
        raise HeaderError("invalid HSE2 header JSON length")
    json_bytes = file_obj.read(json_len)
    if len(json_bytes) != json_len:
        raise HeaderError("truncated HSE2 header JSON")
    header_frame = prefix + json_bytes
    try:
        header = HSE2Header.from_json_bytes(json_bytes)
    except ValueError as exc:
        raise HeaderError("invalid HSE2 header") from exc
    return header_frame, header


def get_profile_for_name(name: str):
    """Import helper kept local to avoid widening public API surface for this draft."""

    from .kdf_profiles import get_kdf_profile

    return get_kdf_profile(name)


def _validate_chunk_size(chunk_size: int) -> None:
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_SIZE}")
