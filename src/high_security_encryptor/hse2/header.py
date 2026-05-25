"""Canonical HSE2 header metadata serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
import json

from .constants import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MANIFEST_CIPHER,
    DEFAULT_PAYLOAD_CIPHER,
    HSE2_VERSION,
)
from .errors import HSE2FormatError
from .wrappers import WrapperRecord


@dataclass(frozen=True, slots=True)
class CipherSuite:
    """Payload and manifest cipher metadata stored in the HSE2 header."""

    payload_cipher: str = DEFAULT_PAYLOAD_CIPHER
    manifest_cipher: str = DEFAULT_MANIFEST_CIPHER
    chunk_size: int = DEFAULT_CHUNK_SIZE

    def validate(self) -> None:
        if not self.payload_cipher:
            raise HSE2FormatError("payload_cipher is required")
        if not self.manifest_cipher:
            raise HSE2FormatError("manifest_cipher is required")
        if self.chunk_size <= 0:
            raise HSE2FormatError("chunk_size must be positive")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "payload_cipher": self.payload_cipher,
            "manifest_cipher": self.manifest_cipher,
            "chunk_size": self.chunk_size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CipherSuite":
        return cls(
            payload_cipher=str(data.get("payload_cipher", DEFAULT_PAYLOAD_CIPHER)),
            manifest_cipher=str(data.get("manifest_cipher", DEFAULT_MANIFEST_CIPHER)),
            chunk_size=int(data.get("chunk_size", DEFAULT_CHUNK_SIZE)),
        )


@dataclass(frozen=True, slots=True)
class ManifestPolicy:
    """Manifest metadata handling policy."""

    encrypted: bool = True
    filename_policy: str = "randomized"
    store_original_paths: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "encrypted": self.encrypted,
            "filename_policy": self.filename_policy,
            "store_original_paths": self.store_original_paths,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManifestPolicy":
        return cls(
            encrypted=bool(data.get("encrypted", True)),
            filename_policy=str(data.get("filename_policy", "randomized")),
            store_original_paths=bool(data.get("store_original_paths", False)),
        )


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class HSE2Header:
    """Authenticated metadata for an HSE2 container."""

    format_version: int = HSE2_VERSION
    created_utc: str = field(default_factory=_utc_now_iso)
    cipher_suite: CipherSuite = field(default_factory=CipherSuite)
    manifest: ManifestPolicy = field(default_factory=ManifestPolicy)
    wrappers: tuple[WrapperRecord, ...] = field(default_factory=tuple)
    header_auth_algorithm: str = "HMAC-SHA256"

    def validate(self) -> None:
        if self.format_version != HSE2_VERSION:
            raise HSE2FormatError(
                f"Unsupported HSE2 format version: {self.format_version}"
            )
        self.cipher_suite.validate()
        for wrapper in self.wrappers:
            wrapper.validate()
        wrapper_ids = [wrapper.id for wrapper in self.wrappers]
        if len(wrapper_ids) != len(set(wrapper_ids)):
            raise HSE2FormatError("Wrapper ids must be unique")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "format": "HSE2",
            "format_version": self.format_version,
            "created_utc": self.created_utc,
            "cipher_suite": self.cipher_suite.to_dict(),
            "manifest": self.manifest.to_dict(),
            "wrappers": [wrapper.to_dict() for wrapper in self.wrappers],
            "header_auth": {
                "algorithm": self.header_auth_algorithm,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HSE2Header":
        if data.get("format") != "HSE2":
            raise HSE2FormatError("Header format must be HSE2")
        version = int(data.get("format_version", -1))
        if version != HSE2_VERSION:
            raise HSE2FormatError(f"Unsupported HSE2 format version: {version}")

        cipher_suite_data = data.get("cipher_suite", {})
        if not isinstance(cipher_suite_data, dict):
            raise HSE2FormatError("cipher_suite must be an object")

        manifest_data = data.get("manifest", {})
        if not isinstance(manifest_data, dict):
            raise HSE2FormatError("manifest must be an object")

        wrappers_data = data.get("wrappers", [])
        if not isinstance(wrappers_data, list):
            raise HSE2FormatError("wrappers must be a list")

        header_auth_data = data.get("header_auth", {})
        if not isinstance(header_auth_data, dict):
            raise HSE2FormatError("header_auth must be an object")

        header = cls(
            format_version=version,
            created_utc=str(data.get("created_utc", "")),
            cipher_suite=CipherSuite.from_dict(cipher_suite_data),
            manifest=ManifestPolicy.from_dict(manifest_data),
            wrappers=tuple(WrapperRecord.from_dict(item) for item in wrappers_data),
            header_auth_algorithm=str(header_auth_data.get("algorithm", "HMAC-SHA256")),
        )
        header.validate()
        return header


def dumps_canonical_header(header: HSE2Header) -> bytes:
    """Serialize a header using deterministic JSON bytes."""

    return json.dumps(
        header.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def loads_canonical_header(data: bytes) -> HSE2Header:
    """Deserialize deterministic HSE2 header JSON bytes."""

    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HSE2FormatError("Invalid HSE2 header JSON") from exc
    if not isinstance(decoded, dict):
        raise HSE2FormatError("HSE2 header must decode to an object")
    return HSE2Header.from_dict(decoded)
