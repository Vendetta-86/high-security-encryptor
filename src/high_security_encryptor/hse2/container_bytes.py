"""In-memory HSE2 container byte orchestration.

This module composes the existing header frame, encrypted manifest metadata, and
encrypted payload chunk records into a single bytes object. It deliberately does
not read from or write to filesystem paths and does not perform CLI or GUI work.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .container_codec import decode_header_frame, encode_header_frame
from .manifest_crypto import EncryptedManifest, encrypted_manifest_from_dict
from .models import HSE2Header, HSE2ModelError, canonical_json_bytes
from .payload_crypto import EncryptedPayloadChunk, encrypted_payload_chunk_from_dict


HSE2_SECTION_MAGIC = b"HSE2BODY\n"


@dataclass(frozen=True)
class HSE2ContainerBytes:
    """Parsed in-memory HSE2 container components."""

    header: HSE2Header
    manifest: EncryptedManifest
    payload_chunks: tuple[EncryptedPayloadChunk, ...]

    def to_body_dict(self) -> dict[str, Any]:
        return {
            "section_magic": HSE2_SECTION_MAGIC.decode("ascii"),
            "manifest": self.manifest.to_dict(),
            "payload_chunks": [chunk.to_dict() for chunk in self.payload_chunks],
        }


def encode_container_bytes(header: HSE2Header, *, manifest: EncryptedManifest, payload_chunks: tuple[EncryptedPayloadChunk, ...]) -> bytes:
    """Encode header frame plus encrypted manifest/chunk metadata into bytes."""

    container = HSE2ContainerBytes(header=header, manifest=manifest, payload_chunks=tuple(payload_chunks))
    return encode_header_frame(header) + canonical_json_bytes(container.to_body_dict())


def decode_container_bytes(data: bytes) -> HSE2ContainerBytes:
    """Decode an in-memory HSE2 container bytes object."""

    _, header, body_bytes = decode_header_frame(data)
    body = _body_dict_from_bytes(body_bytes)
    section_magic = body.get("section_magic")
    if section_magic != HSE2_SECTION_MAGIC.decode("ascii"):
        raise HSE2ModelError("HSE2 body section magic is missing or invalid")
    manifest = encrypted_manifest_from_dict(_required_dict(body, "manifest"))
    payload_chunks = tuple(encrypted_payload_chunk_from_dict(item) for item in _required_list(body, "payload_chunks"))
    return HSE2ContainerBytes(header=header, manifest=manifest, payload_chunks=payload_chunks)


def _body_dict_from_bytes(data: bytes) -> dict[str, Any]:
    if not data:
        raise HSE2ModelError("HSE2 body section is missing")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HSE2ModelError("HSE2 body section is not valid JSON") from exc
    if not isinstance(value, dict):
        raise HSE2ModelError("HSE2 body section must be a dictionary")
    return value


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
