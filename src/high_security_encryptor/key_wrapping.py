"""Key-wrapping primitives for future HSE2 containers.

HSE2 should encrypt file payloads with random data-encryption keys (DEKs), then
wrap those DEKs with key-encryption keys (KEKs) derived from user-provided
material. This module provides the payload shape and AES-GCM wrapping helpers but
does not yet change the HSE1 file format or CLI behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import os

from Crypto.Cipher import AES

from .kdf_profiles import KEY_LEN
from .streaming_primitives import NONCE_LEN, TAG_LEN

KEY_WRAP_ALGORITHM = "AES-256-GCM"
DEK_LEN = KEY_LEN
WRAPPED_KEY_VERSION = 1


@dataclass(frozen=True)
class WrappedDataKey:
    """Serialized encrypted data key material for a self-describing container."""

    algorithm: str
    version: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "version": self.version,
            "nonce_hex": self.nonce.hex(),
            "ciphertext_hex": self.ciphertext.hex(),
            "tag_hex": self.tag.hex(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "WrappedDataKey":
        try:
            algorithm = str(payload["algorithm"])
            version = int(payload["version"])
            nonce = bytes.fromhex(str(payload["nonce_hex"]))
            ciphertext = bytes.fromhex(str(payload["ciphertext_hex"]))
            tag = bytes.fromhex(str(payload["tag_hex"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid wrapped data key payload") from exc
        wrapped = cls(
            algorithm=algorithm,
            version=version,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )
        wrapped.validate()
        return wrapped

    def validate(self) -> None:
        if self.algorithm != KEY_WRAP_ALGORITHM:
            raise ValueError(f"unsupported key wrap algorithm: {self.algorithm}")
        if self.version != WRAPPED_KEY_VERSION:
            raise ValueError(f"unsupported key wrap version: {self.version}")
        if len(self.nonce) != NONCE_LEN:
            raise ValueError("invalid wrapped data key nonce length")
        if len(self.ciphertext) != DEK_LEN:
            raise ValueError("invalid wrapped data key ciphertext length")
        if len(self.tag) != TAG_LEN:
            raise ValueError("invalid wrapped data key tag length")


def generate_data_key() -> bytes:
    """Return a random HSE2 data-encryption key."""

    return os.urandom(DEK_LEN)


def wrap_data_key(data_key: bytes, wrapping_key: bytes, associated_data: bytes = b"") -> WrappedDataKey:
    """Encrypt a data-encryption key with a key-encryption key."""

    _validate_key_material(data_key, "data_key")
    _validate_key_material(wrapping_key, "wrapping_key")
    nonce = os.urandom(NONCE_LEN)
    cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=nonce)
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(data_key)
    wrapped = WrappedDataKey(
        algorithm=KEY_WRAP_ALGORITHM,
        version=WRAPPED_KEY_VERSION,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )
    wrapped.validate()
    return wrapped


def unwrap_data_key(wrapped: WrappedDataKey, wrapping_key: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt and authenticate a wrapped data-encryption key."""

    wrapped.validate()
    _validate_key_material(wrapping_key, "wrapping_key")
    cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=wrapped.nonce)
    if associated_data:
        cipher.update(associated_data)
    try:
        data_key = cipher.decrypt_and_verify(wrapped.ciphertext, wrapped.tag)
    except ValueError as exc:
        raise ValueError("wrapped data key authentication failed") from exc
    _validate_key_material(data_key, "data_key")
    return data_key


def _validate_key_material(key: bytes, name: str) -> None:
    if not isinstance(key, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(key) != KEY_LEN:
        raise ValueError(f"{name} must be {KEY_LEN} bytes")
