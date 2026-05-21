"""Self-describing header model for future HSE2 containers.

The HSE2 header is intentionally modeled before the streaming format is wired to
CLI commands. It provides a canonical metadata representation for future HSE2
encryption/decryption, rewrapping, and keyfile/device-bound modes.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import struct
from typing import Any

from .kdf_profiles import ARGON2ID_ALGORITHM, Argon2idProfile, get_kdf_profile
from .key_wrapping import KEY_WRAP_ALGORITHM, WrappedDataKey
from .streaming_primitives import DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, NONCE_LEN

HSE2_MAGIC = b"HSE2"
HSE2_VERSION = 2
CONTENT_ALGORITHM = "AES-256-GCM-STREAM"
PAYLOAD_AAD_CONTEXT = "HSE2-PAYLOAD-AAD-v1"
HEADER_LENGTH_STRUCT = struct.Struct(">I")
MAX_HEADER_JSON_LEN = 1024 * 1024


@dataclass(frozen=True)
class HSE2Header:
    """Canonical HSE2 header payload."""

    version: int
    content_algorithm: str
    chunk_size: int
    base_nonce: bytes
    kdf: Argon2idProfile
    kdf_salt: bytes
    wrapped_data_key: WrappedDataKey

    def validate(self) -> None:
        if self.version != HSE2_VERSION:
            raise ValueError(f"unsupported HSE2 version: {self.version}")
        if self.content_algorithm != CONTENT_ALGORITHM:
            raise ValueError(f"unsupported HSE2 content algorithm: {self.content_algorithm}")
        if self.chunk_size <= 0 or self.chunk_size > MAX_CHUNK_SIZE:
            raise ValueError("invalid HSE2 chunk size")
        if len(self.base_nonce) != NONCE_LEN:
            raise ValueError("invalid HSE2 base nonce length")
        if len(self.kdf_salt) < 16:
            raise ValueError("HSE2 KDF salt must be at least 16 bytes")
        self.kdf.validate()
        self.wrapped_data_key.validate()

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "version": self.version,
            "content_algorithm": self.content_algorithm,
            "chunk_size": self.chunk_size,
            "base_nonce_hex": self.base_nonce.hex(),
            "kdf": self.kdf.as_dict() | {"salt_hex": self.kdf_salt.hex()},
            "wrapped_data_key": self.wrapped_data_key.as_dict(),
        }

    def immutable_payload_dict(self) -> dict[str, Any]:
        """Return metadata that must remain stable for existing payload bytes.

        KDF metadata and wrapped DEK fields are deliberately excluded so future
        rewrap operations can replace the password/KDF wrapper without rewriting
        or invalidating encrypted payload chunks.
        """

        self.validate()
        return {
            "context": PAYLOAD_AAD_CONTEXT,
            "version": self.version,
            "content_algorithm": self.content_algorithm,
            "chunk_size": self.chunk_size,
            "base_nonce_hex": self.base_nonce.hex(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "HSE2Header":
        try:
            kdf_payload = payload["kdf"]
            if not isinstance(kdf_payload, dict):
                raise ValueError("invalid HSE2 KDF payload")
            if kdf_payload.get("algorithm") != ARGON2ID_ALGORITHM:
                raise ValueError("unsupported HSE2 KDF algorithm")
            profile = get_kdf_profile(str(kdf_payload["profile"]))
            expected = profile.as_dict()
            for field in ("time_cost", "memory_cost_kib", "parallelism", "hash_len"):
                if int(kdf_payload[field]) != int(expected[field]):
                    raise ValueError(f"KDF field does not match named profile: {field}")
            header = cls(
                version=int(payload["version"]),
                content_algorithm=str(payload["content_algorithm"]),
                chunk_size=int(payload["chunk_size"]),
                base_nonce=bytes.fromhex(str(payload["base_nonce_hex"])),
                kdf=profile,
                kdf_salt=bytes.fromhex(str(kdf_payload["salt_hex"])),
                wrapped_data_key=WrappedDataKey.from_dict(payload["wrapped_data_key"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid HSE2 header payload") from exc
        header.validate()
        return header

    def to_json_bytes(self) -> bytes:
        """Serialize the full header as canonical UTF-8 JSON bytes."""

        return canonical_json_bytes(self.as_dict())

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "HSE2Header":
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid HSE2 header JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("invalid HSE2 header JSON payload")
        return cls.from_dict(payload)

    def associated_data(self) -> bytes:
        """Return stable AEAD AAD bytes for payload chunks and trailers."""

        return build_payload_associated_data(self)


def build_header_frame(header: HSE2Header) -> bytes:
    """Serialize an HSE2 header with magic and a length-prefixed JSON payload."""

    json_bytes = header.to_json_bytes()
    if len(json_bytes) > MAX_HEADER_JSON_LEN:
        raise ValueError("HSE2 header JSON is too large")
    return HSE2_MAGIC + HEADER_LENGTH_STRUCT.pack(len(json_bytes)) + json_bytes


def build_payload_associated_data(header: HSE2Header) -> bytes:
    """Return AEAD AAD for payload bytes using only immutable payload metadata."""

    payload = canonical_json_bytes(header.immutable_payload_dict())
    return HSE2_MAGIC + b"AAD" + HEADER_LENGTH_STRUCT.pack(len(payload)) + payload


def parse_header_frame(data: bytes) -> HSE2Header:
    """Parse a complete HSE2 header frame."""

    json_bytes, consumed = split_header_frame(data)
    if consumed != len(data):
        raise ValueError("unexpected trailing bytes after HSE2 header frame")
    return HSE2Header.from_json_bytes(json_bytes)


def split_header_frame(data: bytes) -> tuple[bytes, int]:
    """Return the header JSON bytes and number of frame bytes consumed."""

    prefix_len = len(HSE2_MAGIC) + HEADER_LENGTH_STRUCT.size
    if len(data) < prefix_len:
        raise ValueError("truncated HSE2 header frame")
    if data[: len(HSE2_MAGIC)] != HSE2_MAGIC:
        raise ValueError("invalid HSE2 magic")
    (json_len,) = HEADER_LENGTH_STRUCT.unpack(data[len(HSE2_MAGIC) : prefix_len])
    if json_len <= 0 or json_len > MAX_HEADER_JSON_LEN:
        raise ValueError("invalid HSE2 header JSON length")
    end = prefix_len + json_len
    if len(data) < end:
        raise ValueError("truncated HSE2 header JSON")
    return data[prefix_len:end], end


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Return stable compact JSON bytes for authenticated metadata."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_hse2_header(
    *,
    kdf_profile_name: str,
    kdf_salt: bytes,
    wrapped_data_key: WrappedDataKey,
    base_nonce: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> HSE2Header:
    """Construct and validate a standard HSE2 header."""

    header = HSE2Header(
        version=HSE2_VERSION,
        content_algorithm=CONTENT_ALGORITHM,
        chunk_size=chunk_size,
        base_nonce=base_nonce,
        kdf=get_kdf_profile(kdf_profile_name),
        kdf_salt=kdf_salt,
        wrapped_data_key=wrapped_data_key,
    )
    header.validate()
    return header
