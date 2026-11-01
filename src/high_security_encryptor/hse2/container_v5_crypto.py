"""Versioned cryptographic primitives for the compact HSE2 v5 format."""

from __future__ import annotations

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from .models import HSE2ModelError

V5_VERSION = 5
V5_KEY_SIZE = 32
V5_GCM_NONCE_SIZE = 12
V5_GCM_TAG_SIZE = 16
V5_HKDF_SALT_SIZE = 32
V5_MAX_CHUNK_SIZE = 1_048_576
V5_MAX_LIVE_CHUNKS_PER_VIEW = 32_768
V5_MAX_DESCRIPTOR_SIZE = 16 * 1024 * 1024
V5_MAX_CONTAINER_SIZE = 64 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class V5Sealed:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, bytes) or len(self.nonce) != V5_GCM_NONCE_SIZE:
            raise HSE2ModelError("v5 GCM nonce must be 12 bytes")
        if not isinstance(self.ciphertext, bytes):
            raise HSE2ModelError("v5 ciphertext must be bytes")
        if not isinstance(self.tag, bytes) or len(self.tag) != V5_GCM_TAG_SIZE:
            raise HSE2ModelError("v5 GCM tag must be 16 bytes")


def derive_v5_key(*, root_key: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive one AES-256 key with HKDF-SHA-256 and caller-defined domain separation."""

    if not isinstance(root_key, bytes) or len(root_key) != V5_KEY_SIZE:
        raise HSE2ModelError("v5 HKDF input key must be 32 bytes")
    if not isinstance(salt, bytes) or len(salt) != V5_HKDF_SALT_SIZE:
        raise HSE2ModelError("v5 HKDF salt must be 32 bytes")
    if not isinstance(info, bytes) or not info or len(info) > 255:
        raise HSE2ModelError("v5 HKDF info must contain 1 to 255 bytes")
    return HKDF(root_key, V5_KEY_SIZE, salt, SHA256, context=info)


def seal_v5(*, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> V5Sealed:
    if not isinstance(key, bytes) or len(key) != V5_KEY_SIZE:
        raise HSE2ModelError("v5 AES-GCM key must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != V5_GCM_NONCE_SIZE:
        raise HSE2ModelError("v5 GCM nonce must be 12 bytes")
    if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
        raise HSE2ModelError("v5 plaintext and AAD must be bytes")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=V5_GCM_TAG_SIZE)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return V5Sealed(nonce=nonce, ciphertext=ciphertext, tag=tag)


def open_v5(*, key: bytes, sealed: V5Sealed, aad: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != V5_KEY_SIZE:
        raise HSE2ModelError("v5 AES-GCM key must be 32 bytes")
    if not isinstance(sealed, V5Sealed) or not isinstance(aad, bytes):
        raise HSE2ModelError("invalid v5 sealed value")
    cipher = AES.new(key, AES.MODE_GCM, nonce=sealed.nonce, mac_len=V5_GCM_TAG_SIZE)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(sealed.ciphertext, sealed.tag)
    except ValueError as exc:
        raise HSE2ModelError("v5 authentication failed") from exc
