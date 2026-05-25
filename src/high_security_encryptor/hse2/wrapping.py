"""AES-GCM key wrapping primitives for HSE2.

This module wraps fixed-size HSE2 DEK/MEK values with a KEK. It deliberately
stays below provider, CLI, GUI, and container I/O layers.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

from .keys import HSE2KeyMaterial
from .models import HSE2ModelError


HSE2_WRAP_NONCE_SIZE = 12
HSE2_WRAP_AUTH_TAG_SIZE = 16


@dataclass(frozen=True)
class WrappedKeyBlob:
    """AES-GCM wrapped key bytes plus nonce and authentication tag."""

    nonce: bytes
    ciphertext: bytes
    auth_tag: bytes

    def __post_init__(self) -> None:
        if len(self.nonce) != HSE2_WRAP_NONCE_SIZE:
            raise HSE2ModelError(f"wrap nonce must be {HSE2_WRAP_NONCE_SIZE} bytes")
        if not self.ciphertext:
            raise HSE2ModelError("wrapped key ciphertext must not be empty")
        if len(self.auth_tag) != HSE2_WRAP_AUTH_TAG_SIZE:
            raise HSE2ModelError(f"wrap auth tag must be {HSE2_WRAP_AUTH_TAG_SIZE} bytes")


def _aad_for_key(purpose: str) -> bytes:
    """Return domain-separated associated data for a wrapped HSE2 key."""

    return f"HSE2:key-wrap:{purpose}".encode("ascii")


def wrap_key_material(key: HSE2KeyMaterial, *, kek: HSE2KeyMaterial) -> WrappedKeyBlob:
    """Wrap one HSE2 key material value with an AES-256-GCM KEK."""

    if kek.purpose != "KEK":
        raise HSE2ModelError("wrapping requires a KEK")
    nonce = secrets.token_bytes(HSE2_WRAP_NONCE_SIZE)
    cipher = AES.new(kek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_aad_for_key(key.purpose))
    ciphertext, auth_tag = cipher.encrypt_and_digest(key.as_bytes())
    return WrappedKeyBlob(nonce=nonce, ciphertext=ciphertext, auth_tag=auth_tag)


def unwrap_key_material(blob: WrappedKeyBlob, *, kek: HSE2KeyMaterial, purpose: str) -> HSE2KeyMaterial:
    """Unwrap one HSE2 key material value with an AES-256-GCM KEK."""

    if kek.purpose != "KEK":
        raise HSE2ModelError("unwrapping requires a KEK")
    cipher = AES.new(kek.as_bytes(), AES.MODE_GCM, nonce=blob.nonce)
    cipher.update(_aad_for_key(purpose))
    try:
        plaintext = cipher.decrypt_and_verify(blob.ciphertext, blob.auth_tag)
    except ValueError as exc:
        raise HSE2ModelError("wrapped key authentication failed") from exc
    return HSE2KeyMaterial(purpose=purpose, value=plaintext)


def key_confirmation_tag(*, kek: HSE2KeyMaterial, context: bytes) -> bytes:
    """Return a non-secret confirmation tag for wrapper tests and metadata binding.

    This is not a password hash and must not be used to validate user guesses by
    itself. Future wrapper records may use it only as authenticated metadata when
    the surrounding design requires a stable key-confirmation value.
    """

    if kek.purpose != "KEK":
        raise HSE2ModelError("key confirmation requires a KEK")
    if not context:
        raise HSE2ModelError("key confirmation context must not be empty")
    hmac = HMAC.new(kek.as_bytes(), digestmod=SHA256)
    hmac.update(b"HSE2:key-confirmation:")
    hmac.update(context)
    return hmac.digest()
