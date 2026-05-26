"""Manifest encryption primitives for HSE2.

The manifest is encrypted as canonical JSON with MEK-backed AES-GCM. This module
performs no file I/O, payload encryption, CLI handling, or GUI work.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Any

from Crypto.Cipher import AES

from .encoding import b64decode_bytes, b64encode_bytes
from .keys import HSE2KeyMaterial
from .models import HSE2ModelError, canonical_json_bytes
from .wrapping import HSE2_WRAP_AUTH_TAG_SIZE, HSE2_WRAP_NONCE_SIZE


@dataclass(frozen=True)
class EncryptedManifest:
    """JSON-safe encrypted manifest metadata."""

    nonce: str
    ciphertext: str
    auth_tag: str

    def __post_init__(self) -> None:
        if len(b64decode_bytes(self.nonce, field_name="manifest nonce")) != HSE2_WRAP_NONCE_SIZE:
            raise HSE2ModelError(f"manifest nonce must be {HSE2_WRAP_NONCE_SIZE} bytes")
        if not b64decode_bytes(self.ciphertext, field_name="manifest ciphertext"):
            raise HSE2ModelError("manifest ciphertext must not be empty")
        if len(b64decode_bytes(self.auth_tag, field_name="manifest auth_tag")) != HSE2_WRAP_AUTH_TAG_SIZE:
            raise HSE2ModelError(f"manifest auth tag must be {HSE2_WRAP_AUTH_TAG_SIZE} bytes")

    def to_dict(self) -> dict[str, str]:
        return {
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "auth_tag": self.auth_tag,
        }


def _manifest_aad(context: bytes | None) -> bytes:
    base = b"HSE2:manifest:v1"
    return base if context is None else base + b":" + context


def encrypt_manifest(manifest: dict[str, Any], *, mek: HSE2KeyMaterial, context: bytes | None = None) -> EncryptedManifest:
    """Encrypt a manifest dictionary with a MEK."""

    if mek.purpose != "MEK":
        raise HSE2ModelError("manifest encryption requires a MEK")
    if not isinstance(manifest, dict):
        raise HSE2ModelError("manifest must be a dictionary")
    plaintext = canonical_json_bytes(manifest)
    if not plaintext:
        raise HSE2ModelError("manifest plaintext must not be empty")

    nonce = secrets.token_bytes(HSE2_WRAP_NONCE_SIZE)
    cipher = AES.new(mek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_manifest_aad(context))
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return EncryptedManifest(
        nonce=b64encode_bytes(nonce),
        ciphertext=b64encode_bytes(ciphertext),
        auth_tag=b64encode_bytes(auth_tag),
    )


def decrypt_manifest(encrypted: EncryptedManifest, *, mek: HSE2KeyMaterial, context: bytes | None = None) -> dict[str, Any]:
    """Decrypt an encrypted manifest with a MEK."""

    if mek.purpose != "MEK":
        raise HSE2ModelError("manifest decryption requires a MEK")
    nonce = b64decode_bytes(encrypted.nonce, field_name="manifest nonce")
    ciphertext = b64decode_bytes(encrypted.ciphertext, field_name="manifest ciphertext")
    auth_tag = b64decode_bytes(encrypted.auth_tag, field_name="manifest auth_tag")

    cipher = AES.new(mek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_manifest_aad(context))
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as exc:
        raise HSE2ModelError("manifest authentication failed") from exc

    import json

    try:
        value = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HSE2ModelError("manifest plaintext is not valid canonical JSON") from exc
    if not isinstance(value, dict):
        raise HSE2ModelError("manifest plaintext must decode to a dictionary")
    return value


def encrypted_manifest_from_dict(data: dict[str, str]) -> EncryptedManifest:
    """Create EncryptedManifest from JSON-safe metadata."""

    if not isinstance(data, dict):
        raise HSE2ModelError("encrypted manifest metadata must be a dictionary")
    return EncryptedManifest(
        nonce=data.get("nonce", ""),
        ciphertext=data.get("ciphertext", ""),
        auth_tag=data.get("auth_tag", ""),
    )
