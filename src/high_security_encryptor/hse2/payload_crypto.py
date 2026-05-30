"""Payload chunk encryption primitives for HSE2.

Payload chunks are encrypted with DEK-backed AES-GCM. This module works on
caller-supplied bytes only; it performs no file I/O, chunk scheduling, CLI
handling, or GUI work.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from Crypto.Cipher import AES

from .encoding import b64decode_bytes, b64encode_bytes
from .keys import HSE2KeyMaterial
from .models import HSE2ModelError
from .wrapping import HSE2_WRAP_AUTH_TAG_SIZE, HSE2_WRAP_NONCE_SIZE


@dataclass(frozen=True)
class EncryptedPayloadChunk:
    """JSON-safe encrypted payload chunk metadata plus ciphertext."""

    index: int
    nonce: str
    ciphertext: str
    auth_tag: str

    def __post_init__(self) -> None:
        if not isinstance(self.index, int):
            raise HSE2ModelError("payload chunk index must be an integer")
        if self.index < 0:
            raise HSE2ModelError("payload chunk index must be non-negative")
        if len(b64decode_bytes(self.nonce, field_name="payload chunk nonce")) != HSE2_WRAP_NONCE_SIZE:
            raise HSE2ModelError(f"payload chunk nonce must be {HSE2_WRAP_NONCE_SIZE} bytes")
        if not b64decode_bytes(self.ciphertext, field_name="payload chunk ciphertext"):
            raise HSE2ModelError("payload chunk ciphertext must not be empty")
        if len(b64decode_bytes(self.auth_tag, field_name="payload chunk auth_tag")) != HSE2_WRAP_AUTH_TAG_SIZE:
            raise HSE2ModelError(f"payload chunk auth tag must be {HSE2_WRAP_AUTH_TAG_SIZE} bytes")

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "auth_tag": self.auth_tag,
        }


def _payload_aad(index: int, context: bytes | None) -> bytes:
    if not isinstance(index, int):
        raise HSE2ModelError("payload chunk index must be an integer")
    if index < 0:
        raise HSE2ModelError("payload chunk index must be non-negative")
    base = f"HSE2:payload-chunk:v1:{index}".encode("ascii")
    return base if context is None else base + b":" + context


def encrypt_payload_chunk(plaintext: bytes, *, dek: HSE2KeyMaterial, index: int, context: bytes | None = None) -> EncryptedPayloadChunk:
    """Encrypt one payload chunk with a DEK."""

    if dek.purpose != "DEK":
        raise HSE2ModelError("payload encryption requires a DEK")
    if not isinstance(plaintext, bytes):
        raise HSE2ModelError("payload chunk plaintext must be bytes")
    if not plaintext:
        raise HSE2ModelError("payload chunk plaintext must not be empty")

    nonce = secrets.token_bytes(HSE2_WRAP_NONCE_SIZE)
    cipher = AES.new(dek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_payload_aad(index, context))
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return EncryptedPayloadChunk(
        index=index,
        nonce=b64encode_bytes(nonce),
        ciphertext=b64encode_bytes(ciphertext),
        auth_tag=b64encode_bytes(auth_tag),
    )


def decrypt_payload_chunk(chunk: EncryptedPayloadChunk, *, dek: HSE2KeyMaterial, context: bytes | None = None) -> bytes:
    """Decrypt one payload chunk with a DEK."""

    if dek.purpose != "DEK":
        raise HSE2ModelError("payload decryption requires a DEK")
    nonce = b64decode_bytes(chunk.nonce, field_name="payload chunk nonce")
    ciphertext = b64decode_bytes(chunk.ciphertext, field_name="payload chunk ciphertext")
    auth_tag = b64decode_bytes(chunk.auth_tag, field_name="payload chunk auth_tag")

    cipher = AES.new(dek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_payload_aad(chunk.index, context))
    try:
        return cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as exc:
        raise HSE2ModelError("payload chunk authentication failed") from exc


def encrypted_payload_chunk_from_dict(data: dict[str, object]) -> EncryptedPayloadChunk:
    """Create EncryptedPayloadChunk from JSON-safe metadata."""

    if not isinstance(data, dict):
        raise HSE2ModelError("encrypted payload chunk metadata must be a dictionary")
    index = data.get("index")
    nonce = data.get("nonce")
    ciphertext = data.get("ciphertext")
    auth_tag = data.get("auth_tag")
    if not isinstance(index, int):
        raise HSE2ModelError("payload chunk index is missing or invalid")
    if not isinstance(nonce, str):
        raise HSE2ModelError("payload chunk nonce is missing or invalid")
    if not isinstance(ciphertext, str):
        raise HSE2ModelError("payload chunk ciphertext is missing or invalid")
    if not isinstance(auth_tag, str):
        raise HSE2ModelError("payload chunk auth_tag is missing or invalid")
    return EncryptedPayloadChunk(index=index, nonce=nonce, ciphertext=ciphertext, auth_tag=auth_tag)
