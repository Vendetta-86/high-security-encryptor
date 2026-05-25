"""Keyfile-derived KEK primitives for HSE2 wrappers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .keys import HSE2_KEY_SIZE, HSE2KeyMaterial
from .models import HSE2ModelError


HSE2_KEYFILE_MIN_SIZE = 32
HSE2_KEYFILE_CONTEXT = b"HSE2:keyfile-kek:v1"


@dataclass(frozen=True)
class KeyfileKDFResult:
    """A keyfile-derived KEK plus non-secret metadata about the source bytes."""

    kek: HSE2KeyMaterial
    keyfile_size: int
    keyfile_sha256: str

    def __post_init__(self) -> None:
        if self.kek.purpose != "KEK":
            raise HSE2ModelError("keyfile KDF result must contain a KEK")
        if self.keyfile_size < HSE2_KEYFILE_MIN_SIZE:
            raise HSE2ModelError("keyfile size is below the minimum")
        if len(self.keyfile_sha256) != 64:
            raise HSE2ModelError("keyfile sha256 metadata must be hex-encoded")

    def metadata(self) -> dict[str, object]:
        """Return non-secret keyfile metadata for diagnostics or wrapper records."""

        return {
            "algorithm": "sha256-domain-separated",
            "keyfile_size": self.keyfile_size,
            "keyfile_sha256": self.keyfile_sha256,
        }


def validate_keyfile_bytes(keyfile_bytes: bytes) -> bytes:
    """Validate raw keyfile bytes before derivation."""

    if not isinstance(keyfile_bytes, bytes):
        raise HSE2ModelError("keyfile material must be bytes")
    if len(keyfile_bytes) < HSE2_KEYFILE_MIN_SIZE:
        raise HSE2ModelError(f"keyfile material must be at least {HSE2_KEYFILE_MIN_SIZE} bytes")
    return keyfile_bytes


def derive_kek_from_keyfile(keyfile_bytes: bytes) -> KeyfileKDFResult:
    """Derive a 32-byte KEK from validated keyfile bytes.

    This helper intentionally accepts bytes rather than a path. File loading,
    permissions, prompts, and GUI selection belong to later provider layers.
    """

    material = validate_keyfile_bytes(keyfile_bytes)
    digest = hashlib.sha256(HSE2_KEYFILE_CONTEXT + b":" + material).digest()
    metadata_digest = hashlib.sha256(material).hexdigest()
    return KeyfileKDFResult(
        kek=HSE2KeyMaterial(purpose="KEK", value=digest[:HSE2_KEY_SIZE]),
        keyfile_size=len(material),
        keyfile_sha256=metadata_digest,
    )
