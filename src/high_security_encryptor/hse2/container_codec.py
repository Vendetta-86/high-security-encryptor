"""HSE2 container preamble and authenticated-header byte codec.

This module defines the initial fixed preamble and header framing. It works on
caller-supplied bytes only; it does not read or write filesystem paths and does
not process manifests or payload chunks.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import struct
from typing import Any

from .models import (
    CipherSuite,
    HSE2Header,
    HSE2ModelError,
    ManifestPolicy,
    PayloadLayout,
    WrappedKeys,
    WrapperRecord,
)


HSE2_MAGIC = b"HSE2"
HSE2_PREAMBLE_VERSION = 2
HSE2_HEADER_ENCODING_CANONICAL_JSON = 1
HSE2_PREAMBLE_STRUCT = struct.Struct(">4sBBH Q")
HSE2_PREAMBLE_SIZE = HSE2_PREAMBLE_STRUCT.size


@dataclass(frozen=True)
class HSE2Preamble:
    """Fixed-size unencrypted HSE2 preamble."""

    magic: bytes = HSE2_MAGIC
    format_version: int = HSE2_PREAMBLE_VERSION
    header_encoding: int = HSE2_HEADER_ENCODING_CANONICAL_JSON
    header_length: int = 0

    def __post_init__(self) -> None:
        if self.magic != HSE2_MAGIC:
            raise HSE2ModelError("invalid HSE2 magic")
        if self.format_version != HSE2_PREAMBLE_VERSION:
            raise HSE2ModelError(f"unsupported HSE2 preamble version: {self.format_version}")
        if self.header_encoding != HSE2_HEADER_ENCODING_CANONICAL_JSON:
            raise HSE2ModelError(f"unsupported HSE2 header encoding: {self.header_encoding}")
        if self.header_length < 0:
            raise HSE2ModelError("header_length must be non-negative")

    def to_bytes(self) -> bytes:
        return HSE2_PREAMBLE_STRUCT.pack(
            self.magic,
            self.format_version,
            self.header_encoding,
            0,
            self.header_length,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HSE2Preamble":
        if len(data) != HSE2_PREAMBLE_SIZE:
            raise HSE2ModelError(f"HSE2 preamble must be {HSE2_PREAMBLE_SIZE} bytes")
        magic, format_version, header_encoding, reserved, header_length = HSE2_PREAMBLE_STRUCT.unpack(data)
        if reserved != 0:
            raise HSE2ModelError("HSE2 preamble reserved field must be zero")
        return cls(
            magic=magic,
            format_version=format_version,
            header_encoding=header_encoding,
            header_length=header_length,
        )


def encode_header_frame(header: HSE2Header) -> bytes:
    """Return preamble + canonical header bytes."""

    header_bytes = header.canonical_bytes(include_auth_tag=True)
    preamble = HSE2Preamble(header_length=len(header_bytes))
    return preamble.to_bytes() + header_bytes


def decode_header_frame(data: bytes) -> tuple[HSE2Preamble, HSE2Header, bytes]:
    """Decode preamble + header bytes and return trailing bytes separately."""

    if len(data) < HSE2_PREAMBLE_SIZE:
        raise HSE2ModelError("data is too short to contain an HSE2 preamble")
    preamble = HSE2Preamble.from_bytes(data[:HSE2_PREAMBLE_SIZE])
    header_start = HSE2_PREAMBLE_SIZE
    header_end = header_start + preamble.header_length
    if len(data) < header_end:
        raise HSE2ModelError("data is too short to contain the declared HSE2 header")
    header = hse2_header_from_dict(_json_dict_from_bytes(data[header_start:header_end]))
    return preamble, header, data[header_end:]


def _json_dict_from_bytes(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HSE2ModelError("HSE2 header is not valid JSON") from exc
    if not isinstance(value, dict):
        raise HSE2ModelError("HSE2 header JSON must be a dictionary")
    return value


def hse2_header_from_dict(data: dict[str, Any]) -> HSE2Header:
    """Build an HSE2Header model from parsed JSON data."""

    if not isinstance(data, dict):
        raise HSE2ModelError("HSE2 header data must be a dictionary")
    header_auth = data.get("header_auth")
    if not isinstance(header_auth, dict):
        raise HSE2ModelError("HSE2 header_auth must be a dictionary")

    return HSE2Header(
        created_utc=_required_str(data, "created_utc"),
        cipher_suite=_cipher_suite_from_dict(_required_dict(data, "cipher_suite")),
        manifest_policy=_manifest_policy_from_dict(_required_dict(data, "manifest_policy")),
        payload_layout=_payload_layout_from_dict(_required_dict(data, "payload_layout")),
        wrappers=tuple(_wrapper_record_from_dict(item) for item in _required_list(data, "wrappers")),
        format=_required_str(data, "format"),
        format_version=_required_int(data, "format_version"),
        header_auth_algorithm=_required_str(header_auth, "algorithm"),
        header_auth_tag=header_auth.get("tag") if isinstance(header_auth.get("tag"), str) else None,
    )


def _cipher_suite_from_dict(data: dict[str, Any]) -> CipherSuite:
    return CipherSuite(
        payload_cipher=_required_str(data, "payload_cipher"),
        manifest_cipher=_required_str(data, "manifest_cipher"),
        wrap_cipher=_required_str(data, "wrap_cipher"),
        chunk_size=_required_int(data, "chunk_size"),
    )


def _manifest_policy_from_dict(data: dict[str, Any]) -> ManifestPolicy:
    encrypted = data.get("encrypted")
    store_original_paths = data.get("store_original_paths")
    if not isinstance(encrypted, bool):
        raise HSE2ModelError("manifest_policy.encrypted must be boolean")
    if not isinstance(store_original_paths, bool):
        raise HSE2ModelError("manifest_policy.store_original_paths must be boolean")
    return ManifestPolicy(
        encrypted=encrypted,
        store_original_paths=store_original_paths,
        filename_policy=_required_str(data, "filename_policy"),
    )


def _payload_layout_from_dict(data: dict[str, Any]) -> PayloadLayout:
    return PayloadLayout(
        chunk_count=_required_int(data, "chunk_count"),
        payload_offset=_required_int(data, "payload_offset"),
        footer_offset=_required_int(data, "footer_offset"),
    )


def _wrapper_record_from_dict(data: Any) -> WrapperRecord:
    if not isinstance(data, dict):
        raise HSE2ModelError("wrapper record must be a dictionary")
    return WrapperRecord(
        id=_required_str(data, "id"),
        type=_required_str(data, "type"),
        created_utc=_required_str(data, "created_utc"),
        nonce=_required_str(data, "nonce"),
        wrapped_keys=_wrapped_keys_from_dict(_required_dict(data, "wrapped_keys")),
        auth_tag=_required_str(data, "auth_tag"),
        label=data.get("label") if isinstance(data.get("label"), str) else None,
        kdf=dict(data["kdf"]) if isinstance(data.get("kdf"), dict) else None,
        wrap_cipher=_required_str(data, "wrap_cipher"),
    )


def _wrapped_keys_from_dict(data: dict[str, Any]) -> WrappedKeys:
    return WrappedKeys(dek=_required_str(data, "dek"), mek=_required_str(data, "mek"))


def _required_dict(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise HSE2ModelError(f"{key} must be a dictionary")
    return value


def _required_list(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    if not isinstance(value, list):
        raise HSE2ModelError(f"{key} must be a list")
    return value


def _required_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise HSE2ModelError(f"{key} must be a string")
    return value


def _required_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int):
        raise HSE2ModelError(f"{key} must be an integer")
    return value
