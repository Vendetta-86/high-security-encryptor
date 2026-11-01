"""Cryptographic building blocks for the experimental HSE2 v4 prototype.

This module is not wired into normal HSE2 create/open workflows. It implements
only the versioned HKDF and AES-GCM operations from the local v4 design draft.
"""

from __future__ import annotations

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from .models import HSE2ModelError


V4_VERSION = 4
V4_KEY_SIZE = 32
V4_GCM_NONCE_SIZE = 12
V4_GCM_TAG_SIZE = 16
V4_HKDF_SALT_SIZE = 32
V4_MAX_RECORDS = 65_536
V4_RECORD_SIZE = 1_048_576
V4_DESCRIPTOR_SIZE = 67_108_864
V4_MANIFEST_LIMIT = 67_108_864
V4_DESCRIPTOR_REWRITE_LIMIT = 1 << 20
V4_ZERO_NONCE = bytes(V4_GCM_NONCE_SIZE)


@dataclass(frozen=True)
class V4Sealed:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if len(self.nonce) != V4_GCM_NONCE_SIZE:
            raise HSE2ModelError("v4 GCM nonce must be 12 bytes")
        if len(self.tag) != V4_GCM_TAG_SIZE:
            raise HSE2ModelError("v4 GCM tag must be 16 bytes")


def derive_v4_key(*, root_key: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive one 256-bit v4 key with RFC 5869 HKDF-SHA-256."""

    if not isinstance(root_key, bytes) or len(root_key) != V4_KEY_SIZE:
        raise HSE2ModelError("v4 HKDF input key must be 32 bytes")
    if not isinstance(salt, bytes) or len(salt) != V4_HKDF_SALT_SIZE:
        raise HSE2ModelError("v4 HKDF salt must be 32 bytes")
    if not isinstance(info, bytes) or not info or len(info) > 255:
        raise HSE2ModelError("v4 HKDF info must contain 1 to 255 bytes")
    return HKDF(root_key, V4_KEY_SIZE, salt, SHA256, context=info)


def seal_v4(*, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> V4Sealed:
    """Encrypt and authenticate one value with AES-256-GCM."""

    if not isinstance(key, bytes) or len(key) != V4_KEY_SIZE:
        raise HSE2ModelError("v4 AES-GCM key must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != V4_GCM_NONCE_SIZE:
        raise HSE2ModelError("v4 AES-GCM nonce must be 12 bytes")
    if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
        raise HSE2ModelError("v4 plaintext and AAD must be bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=V4_GCM_TAG_SIZE)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return V4Sealed(nonce=nonce, ciphertext=ciphertext, tag=tag)


def open_v4(*, key: bytes, sealed: V4Sealed, aad: bytes) -> bytes:
    """Authenticate before returning any plaintext."""

    if not isinstance(key, bytes) or len(key) != V4_KEY_SIZE:
        raise HSE2ModelError("v4 AES-GCM key must be 32 bytes")
    if not isinstance(aad, bytes):
        raise HSE2ModelError("v4 AAD must be bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=sealed.nonce, mac_len=V4_GCM_TAG_SIZE)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(sealed.ciphertext, sealed.tag)
    except ValueError as exc:
        raise HSE2ModelError("v4 authentication failed") from exc
