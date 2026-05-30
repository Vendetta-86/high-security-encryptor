"""HSE2 key material primitives.

This module only handles in-memory key value creation and validation. It does
not perform payload encryption, key wrapping, provider loading, or persistence.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import ClassVar

from .models import HSE2ModelError


HSE2_KEY_SIZE = 32


@dataclass(frozen=True)
class HSE2KeyMaterial:
    """A fixed-size secret key used by the HSE2 key model."""

    purpose: str
    value: bytes

    VALID_PURPOSES: ClassVar[frozenset[str]] = frozenset({"DEK", "MEK", "KEK"})

    def __post_init__(self) -> None:
        if self.purpose not in self.VALID_PURPOSES:
            raise HSE2ModelError(f"unsupported key purpose: {self.purpose}")
        if not isinstance(self.value, bytes):
            raise HSE2ModelError("key value must be bytes")
        if len(self.value) != HSE2_KEY_SIZE:
            raise HSE2ModelError(f"{self.purpose} must be {HSE2_KEY_SIZE} bytes")

    def as_bytes(self) -> bytes:
        """Return the raw key bytes for cryptographic operations."""

        return self.value


def generate_key_material(purpose: str) -> HSE2KeyMaterial:
    """Generate a random 32-byte HSE2 key for the requested purpose."""

    return HSE2KeyMaterial(purpose=purpose, value=secrets.token_bytes(HSE2_KEY_SIZE))


def generate_dek() -> HSE2KeyMaterial:
    """Generate a random data-encryption key."""

    return generate_key_material("DEK")


def generate_mek() -> HSE2KeyMaterial:
    """Generate a random manifest-encryption key."""

    return generate_key_material("MEK")


def generate_kek() -> HSE2KeyMaterial:
    """Generate a random key-encryption key.

    Provider-derived KEKs will be added later. This helper is useful for tests,
    recovery-wrapper design, and future non-password key material.
    """

    return generate_key_material("KEK")


def validate_key_bytes(value: bytes, *, purpose: str) -> bytes:
    """Validate and return raw fixed-size key bytes."""

    return HSE2KeyMaterial(purpose=purpose, value=value).as_bytes()
