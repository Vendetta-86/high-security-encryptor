"""Variable-length authenticated data records for HSE2 v5."""

from __future__ import annotations

import secrets
import struct

from .container_v5_crypto import (
    V5_GCM_NONCE_SIZE, V5_GCM_TAG_SIZE, V5_HKDF_SALT_SIZE, V5_MAX_CHUNK_SIZE,
    V5Sealed, derive_v5_key, open_v5, seal_v5,
)
from .models import HSE2ModelError

V5_RECORD_OVERHEAD = V5_HKDF_SALT_SIZE + V5_GCM_NONCE_SIZE + V5_GCM_TAG_SIZE
_RECORD_AAD_PREFIX = b"HSE2:v5:record:v1"
_RECORD_AAD = struct.Struct(">16sBQQI")


def _validate_location(archive_id: bytes, slot: int, sequence: int, offset: int, length: int) -> None:
    if not isinstance(archive_id, bytes) or len(archive_id) != 16:
        raise HSE2ModelError("invalid v5 record archive id")
    if type(slot) is not int or slot not in (0, 1):
        raise HSE2ModelError("invalid v5 record slot")
    if type(sequence) is not int or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 record sequence")
    if type(offset) is not int or not 0 <= offset <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 record offset")
    if type(length) is not int or not 1 <= length <= V5_MAX_CHUNK_SIZE:
        raise HSE2ModelError("invalid v5 record plaintext length")


def _record_aad(archive_id: bytes, slot: int, sequence: int, offset: int, length: int) -> bytes:
    _validate_location(archive_id, slot, sequence, offset, length)
    return _RECORD_AAD_PREFIX + _RECORD_AAD.pack(archive_id, slot, sequence, offset, length)


def seal_v5_record(*, root_key: bytes, archive_id: bytes, slot: int, sequence: int,
                   offset: int, plaintext: bytes) -> bytes:
    if not isinstance(plaintext, bytes):
        raise HSE2ModelError("v5 record plaintext must be bytes")
    _validate_location(archive_id, slot, sequence, offset, len(plaintext))
    salt = secrets.token_bytes(V5_HKDF_SALT_SIZE)
    nonce = secrets.token_bytes(V5_GCM_NONCE_SIZE)
    info = f"HSE2:v5:view:{slot}:record:{sequence}:v1".encode("ascii")
    key = derive_v5_key(root_key=root_key, salt=salt, info=info)
    sealed = seal_v5(key=key, nonce=nonce, plaintext=plaintext,
                     aad=_record_aad(archive_id, slot, sequence, offset, len(plaintext)))
    return salt + nonce + sealed.ciphertext + sealed.tag


def open_v5_record(*, root_key: bytes, archive_id: bytes, slot: int, sequence: int,
                   offset: int, plaintext_length: int, blob: bytes) -> bytes:
    _validate_location(archive_id, slot, sequence, offset, plaintext_length)
    if not isinstance(blob, bytes) or len(blob) != V5_RECORD_OVERHEAD + plaintext_length:
        raise HSE2ModelError("invalid v5 record blob length")
    salt = blob[:V5_HKDF_SALT_SIZE]
    nonce_start = V5_HKDF_SALT_SIZE
    nonce = blob[nonce_start:nonce_start + V5_GCM_NONCE_SIZE]
    ciphertext = blob[V5_HKDF_SALT_SIZE + V5_GCM_NONCE_SIZE:-V5_GCM_TAG_SIZE]
    tag = blob[-V5_GCM_TAG_SIZE:]
    info = f"HSE2:v5:view:{slot}:record:{sequence}:v1".encode("ascii")
    key = derive_v5_key(root_key=root_key, salt=salt, info=info)
    return open_v5(key=key, sealed=V5Sealed(nonce, ciphertext, tag),
                   aad=_record_aad(archive_id, slot, sequence, offset, plaintext_length))
