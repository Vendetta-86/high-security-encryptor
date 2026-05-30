"""Helpers for building JSON-safe HSE2 wrapper records."""

from __future__ import annotations

from dataclasses import dataclass

from .encoding import b64decode_bytes, b64encode_bytes
from .models import HSE2ModelError, WrappedKeys, WrapperRecord
from .wrapping import WrappedKeyBlob


@dataclass(frozen=True)
class WrappedKeyPairBlobs:
    """Wrapped DEK and MEK blobs that share one wrapper record."""

    dek: WrappedKeyBlob
    mek: WrappedKeyBlob

    def __post_init__(self) -> None:
        if self.dek.nonce != self.mek.nonce:
            raise HSE2ModelError("wrapped DEK and MEK blobs must use the same wrapper nonce")
        if self.dek.auth_tag == self.mek.auth_tag and self.dek.ciphertext == self.mek.ciphertext:
            raise HSE2ModelError("wrapped DEK and MEK blobs must be distinct")


def wrapped_blob_to_metadata(blob: WrappedKeyBlob) -> dict[str, str]:
    """Convert one wrapped blob to JSON-safe metadata."""

    return {
        "nonce": b64encode_bytes(blob.nonce),
        "ciphertext": b64encode_bytes(blob.ciphertext),
        "auth_tag": b64encode_bytes(blob.auth_tag),
    }


def wrapped_blob_from_metadata(data: dict[str, str]) -> WrappedKeyBlob:
    """Convert JSON-safe metadata back to a wrapped blob."""

    return WrappedKeyBlob(
        nonce=b64decode_bytes(data.get("nonce", ""), field_name="nonce"),
        ciphertext=b64decode_bytes(data.get("ciphertext", ""), field_name="ciphertext"),
        auth_tag=b64decode_bytes(data.get("auth_tag", ""), field_name="auth_tag"),
    )


def build_wrapper_record(
    *,
    wrapper_id: str,
    wrapper_type: str,
    created_utc: str,
    wrapped_blobs: WrappedKeyPairBlobs,
    auth_tag: bytes,
    label: str | None = None,
    kdf: dict[str, object] | None = None,
) -> WrapperRecord:
    """Build a JSON-safe WrapperRecord from wrapped DEK/MEK blobs."""

    return WrapperRecord(
        id=wrapper_id,
        type=wrapper_type,
        label=label,
        created_utc=created_utc,
        nonce=b64encode_bytes(wrapped_blobs.dek.nonce),
        wrapped_keys=WrappedKeys(
            dek=b64encode_bytes(wrapped_blobs.dek.ciphertext),
            mek=b64encode_bytes(wrapped_blobs.mek.ciphertext),
        ),
        auth_tag=b64encode_bytes(auth_tag),
        kdf=dict(kdf) if kdf is not None else None,
    )
