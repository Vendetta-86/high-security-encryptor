"""Wrapper metadata records for HSE2.

A wrapper record describes one independent way to unwrap the random HSE2
container keys. This module only models authenticated metadata; cryptographic
wrapping and unwrapping will be implemented in a later step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
import base64
import secrets

from .constants import DEFAULT_WRAP_CIPHER, GCM_NONCE_BYTES
from .errors import HSE2FormatError
from .kdf import KdfProfile, get_kdf_profile

WRAPPER_PASSWORD = "password"
WRAPPER_KEYFILE = "keyfile"
WRAPPER_PASSWORD_KEYFILE = "password_keyfile"
WRAPPER_DPAPI = "dpapi"

SUPPORTED_WRAPPER_TYPES = frozenset(
    {
        WRAPPER_PASSWORD,
        WRAPPER_KEYFILE,
        WRAPPER_PASSWORD_KEYFILE,
        WRAPPER_DPAPI,
    }
)


def b64encode_bytes(value: bytes) -> str:
    """Return standard base64 text for binary metadata fields."""

    return base64.b64encode(value).decode("ascii")


def b64decode_text(value: str, *, field_name: str) -> bytes:
    """Decode a base64 metadata field and normalize errors."""

    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise HSE2FormatError(f"Invalid base64 value for {field_name}") from exc


def utc_now_iso() -> str:
    """Return a stable UTC timestamp for newly created wrapper metadata."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class WrappedKeys:
    """Base64-serializable wrapped DEK and MEK fields."""

    dek: bytes
    mek: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "dek": b64encode_bytes(self.dek),
            "mek": b64encode_bytes(self.mek),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WrappedKeys":
        try:
            dek_text = data["dek"]
            mek_text = data["mek"]
        except KeyError as exc:
            raise HSE2FormatError("Wrapped keys must contain dek and mek") from exc
        if not isinstance(dek_text, str) or not isinstance(mek_text, str):
            raise HSE2FormatError("Wrapped key fields must be base64 strings")
        return cls(
            dek=b64decode_text(dek_text, field_name="wrapped_keys.dek"),
            mek=b64decode_text(mek_text, field_name="wrapped_keys.mek"),
        )


@dataclass(frozen=True, slots=True)
class WrapperRecord:
    """Authenticated metadata for one HSE2 unlock wrapper."""

    id: str
    type: str
    kdf: KdfProfile | None
    nonce: bytes
    wrapped_keys: WrappedKeys
    wrap_cipher: str = DEFAULT_WRAP_CIPHER
    created_utc: str = field(default_factory=utc_now_iso)
    label: str | None = None
    provider: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Validate structural wrapper metadata before serialization."""

        if not self.id:
            raise HSE2FormatError("Wrapper id is required")
        if self.type not in SUPPORTED_WRAPPER_TYPES:
            raise HSE2FormatError(f"Unsupported HSE2 wrapper type: {self.type}")
        if self.type != WRAPPER_DPAPI and self.kdf is None:
            raise HSE2FormatError(f"Wrapper type {self.type} requires KDF metadata")
        if len(self.nonce) != GCM_NONCE_BYTES:
            raise HSE2FormatError("Wrapper nonce must be 12 bytes for AES-GCM")
        if not self.wrap_cipher:
            raise HSE2FormatError("Wrapper cipher is required")

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-serializable wrapper representation."""

        self.validate()
        result: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "wrap_cipher": self.wrap_cipher,
            "nonce": b64encode_bytes(self.nonce),
            "wrapped_keys": self.wrapped_keys.to_dict(),
            "created_utc": self.created_utc,
        }
        if self.kdf is not None:
            result["kdf"] = self.kdf.to_dict()
        if self.label is not None:
            result["label"] = self.label
        if self.provider:
            result["provider"] = dict(self.provider)
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WrapperRecord":
        """Parse wrapper metadata from a decoded HSE2 header."""

        try:
            wrapper_id = data["id"]
            wrapper_type = data["type"]
            nonce_text = data["nonce"]
            wrapped_keys_data = data["wrapped_keys"]
        except KeyError as exc:
            raise HSE2FormatError(f"Missing wrapper field: {exc.args[0]}") from exc

        if not isinstance(wrapper_id, str):
            raise HSE2FormatError("Wrapper id must be a string")
        if not isinstance(wrapper_type, str):
            raise HSE2FormatError("Wrapper type must be a string")
        if not isinstance(nonce_text, str):
            raise HSE2FormatError("Wrapper nonce must be a base64 string")
        if not isinstance(wrapped_keys_data, dict):
            raise HSE2FormatError("wrapped_keys must be an object")

        kdf: KdfProfile | None = None
        kdf_data = data.get("kdf")
        if kdf_data is not None:
            if not isinstance(kdf_data, dict):
                raise HSE2FormatError("kdf must be an object")
            profile_name = kdf_data.get("name") or kdf_data.get("profile")
            if not isinstance(profile_name, str):
                raise HSE2FormatError("kdf.name or kdf.profile must be a string")
            kdf = get_kdf_profile(profile_name)

        label = data.get("label")
        if label is not None and not isinstance(label, str):
            raise HSE2FormatError("Wrapper label must be a string")

        provider = data.get("provider", {})
        if not isinstance(provider, dict):
            raise HSE2FormatError("Wrapper provider must be an object")

        record = cls(
            id=wrapper_id,
            type=wrapper_type,
            kdf=kdf,
            nonce=b64decode_text(nonce_text, field_name="nonce"),
            wrapped_keys=WrappedKeys.from_dict(wrapped_keys_data),
            wrap_cipher=str(data.get("wrap_cipher", DEFAULT_WRAP_CIPHER)),
            created_utc=str(data.get("created_utc", "")),
            label=label,
            provider=provider,
        )
        record.validate()
        return record


def make_placeholder_wrapper(
    *,
    wrapper_id: str,
    wrapper_type: str,
    profile_name: str = "hardened",
    label: str | None = None,
) -> WrapperRecord:
    """Create structurally valid placeholder metadata for early format tests.

    The wrapped values are random bytes until the real password/keyfile wrapping
    implementation is added. This function must not be used as the final
    encryption implementation.
    """

    return WrapperRecord(
        id=wrapper_id,
        type=wrapper_type,
        kdf=None if wrapper_type == WRAPPER_DPAPI else get_kdf_profile(profile_name),
        nonce=secrets.token_bytes(GCM_NONCE_BYTES),
        wrapped_keys=WrappedKeys(
            dek=secrets.token_bytes(32),
            mek=secrets.token_bytes(32),
        ),
        label=label,
    )
