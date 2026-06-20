"""Safe read-only HSE2 container inspection helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from .container_bytes import decode_container_bytes
from .container_codec import decode_header_frame
from .file_io import read_container_bytes
from .models import WrapperRecord


@dataclass(frozen=True)
class HSE2InspectWrapperSummary:
    """Safe-to-print metadata for one HSE2 wrapper."""

    id: str
    type: str
    created_utc: str
    label: str | None
    wrap_cipher: str
    has_kdf: bool
    kdf_algorithm: str | None
    kdf_profile: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "created_utc": self.created_utc,
            "label": self.label,
            "wrap_cipher": self.wrap_cipher,
            "has_kdf": self.has_kdf,
            "kdf_algorithm": self.kdf_algorithm,
            "kdf_profile": self.kdf_profile,
        }


@dataclass(frozen=True)
class HSE2InspectResult:
    """Safe-to-print HSE2 container metadata."""

    input_path: str
    container_size: int
    preamble_magic: str
    preamble_format_version: int
    preamble_header_encoding: int
    preamble_header_length: int
    body_size: int
    format: str
    format_version: int
    created_utc: str
    header_auth_algorithm: str
    header_auth_present: bool
    access_destroyed: bool
    cipher_suite: dict[str, Any]
    manifest_policy: dict[str, Any]
    payload_layout: dict[str, Any]
    payload_chunk_count: int
    payload_chunk_count_matches_header: bool
    manifest_encrypted: bool
    wrapper_count: int
    wrapper_types: tuple[str, ...]
    wrappers: tuple[HSE2InspectWrapperSummary, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-inspect",
            "experimental": True,
            "input_path": self.input_path,
            "container_size": self.container_size,
            "preamble": {
                "magic": self.preamble_magic,
                "format_version": self.preamble_format_version,
                "header_encoding": self.preamble_header_encoding,
                "header_length": self.preamble_header_length,
            },
            "body_size": self.body_size,
            "format": self.format,
            "format_version": self.format_version,
            "created_utc": self.created_utc,
            "header_auth": {
                "algorithm": self.header_auth_algorithm,
                "tag_present": self.header_auth_present,
            },
            "access_destroyed": self.access_destroyed,
            "cipher_suite": dict(self.cipher_suite),
            "manifest_policy": dict(self.manifest_policy),
            "payload_layout": dict(self.payload_layout),
            "payload_chunk_count": self.payload_chunk_count,
            "payload_chunk_count_matches_header": self.payload_chunk_count_matches_header,
            "manifest_encrypted": self.manifest_encrypted,
            "wrapper_count": self.wrapper_count,
            "wrapper_types": list(self.wrapper_types),
            "wrappers": [wrapper.to_dict() for wrapper in self.wrappers],
        }


def inspect_hse2_container(input_path: str | os.PathLike[str]) -> HSE2InspectResult:
    """Inspect safe metadata from an HSE2 container without unlocking payload data."""

    path = Path(input_path)
    data = read_container_bytes(path)
    preamble, header, body_bytes = decode_header_frame(data)
    container = decode_container_bytes(data)
    wrappers = tuple(_summarize_wrapper(wrapper) for wrapper in header.wrappers)
    wrapper_types = tuple(sorted({wrapper.type for wrapper in header.wrappers}))
    payload_chunk_count = len(container.payload_chunks)
    return HSE2InspectResult(
        input_path=str(path),
        container_size=len(data),
        preamble_magic=preamble.magic.decode("ascii"),
        preamble_format_version=preamble.format_version,
        preamble_header_encoding=preamble.header_encoding,
        preamble_header_length=preamble.header_length,
        body_size=len(body_bytes),
        format=header.format,
        format_version=header.format_version,
        created_utc=header.created_utc,
        header_auth_algorithm=header.header_auth_algorithm,
        header_auth_present=header.header_auth_tag is not None,
        access_destroyed=header.access_destroyed,
        cipher_suite=header.cipher_suite.to_dict(),
        manifest_policy=header.manifest_policy.to_dict(),
        payload_layout=header.payload_layout.to_dict(),
        payload_chunk_count=payload_chunk_count,
        payload_chunk_count_matches_header=header.payload_layout.chunk_count == payload_chunk_count,
        manifest_encrypted=header.manifest_policy.encrypted,
        wrapper_count=len(header.wrappers),
        wrapper_types=wrapper_types,
        wrappers=wrappers,
    )


def _summarize_wrapper(wrapper: WrapperRecord) -> HSE2InspectWrapperSummary:
    kdf_algorithm = None
    kdf_profile = None
    if isinstance(wrapper.kdf, dict):
        if isinstance(wrapper.kdf.get("algorithm"), str):
            kdf_algorithm = wrapper.kdf["algorithm"]
        if isinstance(wrapper.kdf.get("profile"), str):
            kdf_profile = wrapper.kdf["profile"]
    return HSE2InspectWrapperSummary(
        id=wrapper.id,
        type=wrapper.type,
        created_utc=wrapper.created_utc,
        label=wrapper.label,
        wrap_cipher=wrapper.wrap_cipher,
        has_kdf=wrapper.kdf is not None,
        kdf_algorithm=kdf_algorithm,
        kdf_profile=kdf_profile,
    )
