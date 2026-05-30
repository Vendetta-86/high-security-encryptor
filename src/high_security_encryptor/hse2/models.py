"""Pure HSE2 container data models.

These models intentionally contain no encryption workflow code. They provide a
stable, deterministic representation for the HSE2 format before the key wrapping
and payload implementations are wired in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, ClassVar


class HSE2ModelError(ValueError):
    """Raised when an HSE2 model contains invalid format data."""


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """Serialize a JSON-compatible mapping deterministically.

    HSE2 header authentication depends on stable serialization. This helper uses
    sorted keys and compact separators and rejects non-JSON values early.
    """

    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HSE2ModelError(f"value is not canonical-json serializable: {exc}") from exc


@dataclass(frozen=True)
class KDFProfile:
    """Named Argon2id KDF parameters serialized into HSE2 wrappers."""

    name: str
    memory_cost_kib: int
    time_cost: int
    parallelism: int
    hash_len: int = 32
    algorithm: str = "argon2id"

    VALID_NAMES: ClassVar[frozenset[str]] = frozenset({"compatible", "hardened", "paranoid"})

    def __post_init__(self) -> None:
        if self.name not in self.VALID_NAMES:
            raise HSE2ModelError(f"unsupported KDF profile: {self.name}")
        if self.algorithm != "argon2id":
            raise HSE2ModelError(f"unsupported KDF algorithm: {self.algorithm}")
        for field_name in ("memory_cost_kib", "time_cost", "parallelism", "hash_len"):
            if getattr(self, field_name) <= 0:
                raise HSE2ModelError(f"{field_name} must be positive")

    def to_dict(self, *, salt: str | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "algorithm": self.algorithm,
            "profile": self.name,
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }
        if salt is not None:
            data["salt"] = salt
        return data


KDF_PROFILES: dict[str, KDFProfile] = {
    "compatible": KDFProfile("compatible", memory_cost_kib=65536, time_cost=3, parallelism=4),
    "hardened": KDFProfile("hardened", memory_cost_kib=262144, time_cost=3, parallelism=4),
    "paranoid": KDFProfile("paranoid", memory_cost_kib=1048576, time_cost=4, parallelism=4),
}


def get_kdf_profile(name: str) -> KDFProfile:
    """Return a named HSE2 KDF profile."""

    try:
        return KDF_PROFILES[name]
    except KeyError as exc:
        raise HSE2ModelError(f"unsupported KDF profile: {name}") from exc


@dataclass(frozen=True)
class CipherSuite:
    """Cipher selections for HSE2 payload, manifest, and key wrapping."""

    payload_cipher: str = "AES-256-GCM"
    manifest_cipher: str = "AES-256-GCM"
    wrap_cipher: str = "AES-256-GCM"
    chunk_size: int = 1048576

    def __post_init__(self) -> None:
        allowed = {"AES-256-GCM"}
        if self.payload_cipher not in allowed:
            raise HSE2ModelError(f"unsupported payload cipher: {self.payload_cipher}")
        if self.manifest_cipher not in allowed:
            raise HSE2ModelError(f"unsupported manifest cipher: {self.manifest_cipher}")
        if self.wrap_cipher not in allowed:
            raise HSE2ModelError(f"unsupported wrap cipher: {self.wrap_cipher}")
        if self.chunk_size <= 0:
            raise HSE2ModelError("chunk_size must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_cipher": self.payload_cipher,
            "manifest_cipher": self.manifest_cipher,
            "wrap_cipher": self.wrap_cipher,
            "chunk_size": self.chunk_size,
        }


@dataclass(frozen=True)
class ManifestPolicy:
    """Controls what metadata HSE2 may expose outside encrypted manifest data."""

    encrypted: bool = True
    store_original_paths: bool = False
    filename_policy: str = "encrypted"

    def __post_init__(self) -> None:
        if self.filename_policy not in {"encrypted", "randomized", "preserved"}:
            raise HSE2ModelError(f"unsupported filename policy: {self.filename_policy}")
        if not self.encrypted and self.filename_policy == "encrypted":
            raise HSE2ModelError("filename_policy cannot be encrypted when manifest encryption is disabled")

    def to_dict(self) -> dict[str, Any]:
        return {
            "encrypted": self.encrypted,
            "store_original_paths": self.store_original_paths,
            "filename_policy": self.filename_policy,
        }


@dataclass(frozen=True)
class PayloadLayout:
    """Streaming payload offsets and chunk count."""

    chunk_count: int = 0
    payload_offset: int = 0
    footer_offset: int = 0

    def __post_init__(self) -> None:
        for field_name in ("chunk_count", "payload_offset", "footer_offset"):
            if getattr(self, field_name) < 0:
                raise HSE2ModelError(f"{field_name} must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_count": self.chunk_count,
            "payload_offset": self.payload_offset,
            "footer_offset": self.footer_offset,
        }


@dataclass(frozen=True)
class WrappedKeys:
    """Base64-encoded wrapped DEK and MEK blobs."""

    dek: str
    mek: str

    def __post_init__(self) -> None:
        if not self.dek:
            raise HSE2ModelError("wrapped DEK must not be empty")
        if not self.mek:
            raise HSE2ModelError("wrapped MEK must not be empty")

    def to_dict(self) -> dict[str, str]:
        return {"dek": self.dek, "mek": self.mek}


@dataclass(frozen=True)
class WrapperRecord:
    """One HSE2 unlock method and its authenticated metadata."""

    id: str
    type: str
    created_utc: str
    nonce: str
    wrapped_keys: WrappedKeys
    auth_tag: str
    label: str | None = None
    kdf: dict[str, Any] | None = None
    wrap_cipher: str = "AES-256-GCM"

    VALID_TYPES: ClassVar[frozenset[str]] = frozenset({"password", "keyfile", "password_keyfile", "dpapi"})

    def __post_init__(self) -> None:
        if not self.id:
            raise HSE2ModelError("wrapper id must not be empty")
        if self.type not in self.VALID_TYPES:
            raise HSE2ModelError(f"unsupported wrapper type: {self.type}")
        if self.wrap_cipher != "AES-256-GCM":
            raise HSE2ModelError(f"unsupported wrap cipher: {self.wrap_cipher}")
        if not self.created_utc:
            raise HSE2ModelError("created_utc must not be empty")
        if not self.nonce:
            raise HSE2ModelError("wrapper nonce must not be empty")
        if not self.auth_tag:
            raise HSE2ModelError("wrapper auth_tag must not be empty")
        if self.type in {"password", "password_keyfile"} and not self.kdf:
            raise HSE2ModelError(f"{self.type} wrapper requires kdf metadata")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "created_utc": self.created_utc,
            "wrap_cipher": self.wrap_cipher,
            "nonce": self.nonce,
            "wrapped_keys": self.wrapped_keys.to_dict(),
            "auth_tag": self.auth_tag,
        }
        if self.label is not None:
            data["label"] = self.label
        if self.kdf is not None:
            data["kdf"] = dict(self.kdf)
        return data


@dataclass(frozen=True)
class HSE2Header:
    """Authenticated HSE2 header data before the final header tag is computed."""

    created_utc: str
    cipher_suite: CipherSuite = field(default_factory=CipherSuite)
    manifest_policy: ManifestPolicy = field(default_factory=ManifestPolicy)
    payload_layout: PayloadLayout = field(default_factory=PayloadLayout)
    wrappers: tuple[WrapperRecord, ...] = field(default_factory=tuple)
    format: str = "HSE2"
    format_version: int = 2
    header_auth_algorithm: str = "HMAC-SHA256"
    header_auth_tag: str | None = None

    def __post_init__(self) -> None:
        if self.format != "HSE2":
            raise HSE2ModelError(f"unsupported format: {self.format}")
        if self.format_version != 2:
            raise HSE2ModelError(f"unsupported HSE2 format version: {self.format_version}")
        if not self.created_utc:
            raise HSE2ModelError("created_utc must not be empty")
        if self.header_auth_algorithm != "HMAC-SHA256":
            raise HSE2ModelError(f"unsupported header auth algorithm: {self.header_auth_algorithm}")

    def to_dict(self, *, include_auth_tag: bool = True) -> dict[str, Any]:
        header_auth: dict[str, Any] = {"algorithm": self.header_auth_algorithm}
        if include_auth_tag and self.header_auth_tag is not None:
            header_auth["tag"] = self.header_auth_tag
        return {
            "format": self.format,
            "format_version": self.format_version,
            "created_utc": self.created_utc,
            "cipher_suite": self.cipher_suite.to_dict(),
            "manifest_policy": self.manifest_policy.to_dict(),
            "payload_layout": self.payload_layout.to_dict(),
            "wrappers": [wrapper.to_dict() for wrapper in self.wrappers],
            "header_auth": header_auth,
        }

    def canonical_bytes(self, *, include_auth_tag: bool = True) -> bytes:
        """Return deterministic bytes for header authentication or storage."""

        return canonical_json_bytes(self.to_dict(include_auth_tag=include_auth_tag))
