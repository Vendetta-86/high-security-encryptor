"""Fixed-size record codec for the experimental HSE2 v4 candidate.

This module is isolated from the v2/v3 workflows. Record lengths supplied by
callers are authenticated descriptor data and must be checked before use.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .container_v4_crypto import (
    V4_HKDF_SALT_SIZE,
    V4_KEY_SIZE,
    V4_MAX_RECORDS,
    V4_RECORD_SIZE,
    V4_ZERO_NONCE,
    V4Sealed,
    derive_v4_key,
    open_v4,
    seal_v4,
)
from .models import HSE2ModelError

V4_RECORD_KEY_SIZE = 32
V4_RECORD_TAG_SIZE = 16
V4_RECORD_NONCE_SIZE = 12
V4_RECORD_PREFIX_SIZE = V4_HKDF_SALT_SIZE + V4_RECORD_KEY_SIZE + V4_RECORD_TAG_SIZE
V4_RECORD_PAYLOAD_SIZE = V4_RECORD_SIZE - V4_RECORD_PREFIX_SIZE - V4_RECORD_NONCE_SIZE - V4_RECORD_TAG_SIZE


@dataclass(frozen=True)
class V4Record:
    """One exact-size encoded v4 data record."""

    hkdf_salt: bytes
    wrapped_key: bytes
    wrap_tag: bytes
    payload_nonce: bytes
    payload_ciphertext: bytes
    payload_tag: bytes

    def __post_init__(self) -> None:
        expected = (
            (self.hkdf_salt, V4_HKDF_SALT_SIZE, "record HKDF salt"),
            (self.wrapped_key, V4_RECORD_KEY_SIZE, "wrapped record key"),
            (self.wrap_tag, V4_RECORD_TAG_SIZE, "record-key tag"),
            (self.payload_nonce, V4_RECORD_NONCE_SIZE, "payload nonce"),
            (self.payload_ciphertext, V4_RECORD_PAYLOAD_SIZE, "payload ciphertext"),
            (self.payload_tag, V4_RECORD_TAG_SIZE, "payload tag"),
        )
        for value, size, name in expected:
            if not isinstance(value, bytes) or len(value) != size:
                raise HSE2ModelError(f"invalid v4 {name} length")

    def to_bytes(self) -> bytes:
        return b"".join(
            (self.hkdf_salt, self.wrapped_key, self.wrap_tag,
             self.payload_nonce, self.payload_ciphertext, self.payload_tag)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "V4Record":
        if not isinstance(data, bytes) or len(data) != V4_RECORD_SIZE:
            raise HSE2ModelError("invalid v4 record length")
        p = 0
        salt = data[p:p + V4_HKDF_SALT_SIZE]
        p += V4_HKDF_SALT_SIZE
        wrapped = data[p:p + V4_RECORD_KEY_SIZE]
        p += V4_RECORD_KEY_SIZE
        wrap_tag = data[p:p + V4_RECORD_TAG_SIZE]
        p += V4_RECORD_TAG_SIZE
        nonce = data[p:p + V4_RECORD_NONCE_SIZE]
        p += V4_RECORD_NONCE_SIZE
        ciphertext = data[p:p + V4_RECORD_PAYLOAD_SIZE]
        p += V4_RECORD_PAYLOAD_SIZE
        return cls(salt, wrapped, wrap_tag, nonce, ciphertext, data[p:])


def _validate_location(*, slot: int, index: int) -> None:
    if type(slot) is not int or slot not in (0, 1):
        raise HSE2ModelError("invalid v4 view slot")
    if type(index) is not int or not 0 <= index < V4_MAX_RECORDS:
        raise HSE2ModelError("invalid v4 record index")
    if index % 2 != slot:
        raise HSE2ModelError("invalid v4 record index for slot")


def _record_wrap_aad(slot: int, index: int) -> bytes:
    return f"HSE2:v4:record-key:{slot}:{index}:{V4_RECORD_SIZE}:v1".encode("ascii")


def _record_payload_aad(slot: int, index: int) -> bytes:
    return f"HSE2:v4:record-payload:{slot}:{index}:{V4_RECORD_SIZE}:v1".encode("ascii")


def seal_v4_record(*, view_root_key: bytes, slot: int, index: int, plaintext: bytes) -> V4Record:
    """Seal one short payload into one padded, fixed-size record."""

    _validate_location(slot=slot, index=index)
    if not isinstance(plaintext, bytes) or len(plaintext) > V4_RECORD_PAYLOAD_SIZE:
        raise HSE2ModelError("v4 record plaintext exceeds fixed payload capacity")
    salt = secrets.token_bytes(V4_HKDF_SALT_SIZE)
    wrap_key = derive_v4_key(
        root_key=view_root_key,
        salt=salt,
        info=f"HSE2:v4:view:{slot}:record-wrap:{index}:v1".encode("ascii"),
    )
    record_key = secrets.token_bytes(V4_RECORD_KEY_SIZE)
    wrapped = seal_v4(key=wrap_key, nonce=V4_ZERO_NONCE, plaintext=record_key,
                      aad=_record_wrap_aad(slot, index))
    padded = plaintext + secrets.token_bytes(V4_RECORD_PAYLOAD_SIZE - len(plaintext))
    payload_nonce = secrets.token_bytes(V4_RECORD_NONCE_SIZE)
    payload = seal_v4(key=record_key, nonce=payload_nonce, plaintext=padded,
                      aad=_record_payload_aad(slot, index))
    return V4Record(salt, wrapped.ciphertext, wrapped.tag, payload_nonce,
                    payload.ciphertext, payload.tag)


def open_v4_record(*, view_root_key: bytes, slot: int, index: int,
                   record: V4Record | bytes, plaintext_length: int) -> bytes:
    """Authenticate a record fully, then return its descriptor-sized payload."""

    _validate_location(slot=slot, index=index)
    if type(plaintext_length) is not int or not 0 <= plaintext_length <= V4_RECORD_PAYLOAD_SIZE:
        raise HSE2ModelError("v4 record authentication failed")
    try:
        parsed = V4Record.from_bytes(record) if isinstance(record, bytes) else record
    except HSE2ModelError as exc:
        raise HSE2ModelError("v4 record authentication failed") from exc
    if not isinstance(parsed, V4Record):
        raise HSE2ModelError("invalid v4 record")
    try:
        wrap_key = derive_v4_key(
            root_key=view_root_key,
            salt=parsed.hkdf_salt,
            info=f"HSE2:v4:view:{slot}:record-wrap:{index}:v1".encode("ascii"),
        )
        record_key = open_v4(
            key=wrap_key,
            sealed=V4Sealed(V4_ZERO_NONCE, parsed.wrapped_key, parsed.wrap_tag),
            aad=_record_wrap_aad(slot, index),
        )
        if len(record_key) != V4_RECORD_KEY_SIZE:
            raise HSE2ModelError("v4 authentication failed")
        padded = open_v4(
            key=record_key,
            sealed=V4Sealed(parsed.payload_nonce, parsed.payload_ciphertext, parsed.payload_tag),
            aad=_record_payload_aad(slot, index),
        )
        return padded[:plaintext_length]
    except HSE2ModelError as exc:
        raise HSE2ModelError("v4 record authentication failed") from exc
