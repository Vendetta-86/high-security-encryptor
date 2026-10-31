"""Safe read-only HSE2 container inspection helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import struct
from typing import Any

from .container_bytes import decode_container_bytes
from .container_codec import HSE2_PREAMBLE_STRUCT, decode_header_frame
from .container_stream import V3_CHUNK_MAGIC, V3_MANIFEST_MAGIC, V3_MAX_CHUNK_SIZE, V3_MAX_MANIFEST_SIZE, read_v3_header_frame
from .file_io import read_container_bytes
from .models import HSE2Header, HSE2ModelError, WrapperRecord


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
    with path.open("rb") as stream:
        preamble_bytes = _read_exact(stream, HSE2_PREAMBLE_STRUCT.size, "preamble")
        _magic, preamble_version, _encoding, _reserved, header_length = HSE2_PREAMBLE_STRUCT.unpack(preamble_bytes)
        if preamble_version == 3:
            stream.seek(0)
            header_frame, header = read_v3_header_frame(stream)
            payload_chunk_count = _scan_v3_body(stream, header)
            container_size = path.stat().st_size
            return _build_inspect_result(
                path=path,
                container_size=container_size,
                preamble_bytes=preamble_bytes,
                header_length=header_length,
                header_frame_size=len(header_frame),
                header=header,
                payload_chunk_count=payload_chunk_count,
            )

    data = read_container_bytes(path)
    preamble, header, body_bytes = decode_header_frame(data)
    container = decode_container_bytes(data)
    return _build_inspect_result(
        path=path,
        container_size=len(data),
        preamble_bytes=data[:HSE2_PREAMBLE_STRUCT.size],
        header_length=preamble.header_length,
        header_frame_size=HSE2_PREAMBLE_STRUCT.size + preamble.header_length,
        header=header,
        payload_chunk_count=len(container.payload_chunks),
    )


def _build_inspect_result(
    *,
    path: Path,
    container_size: int,
    preamble_bytes: bytes,
    header_length: int,
    header_frame_size: int,
    header: HSE2Header,
    payload_chunk_count: int,
) -> HSE2InspectResult:
    magic, preamble_version, header_encoding, _reserved, _declared_header_length = HSE2_PREAMBLE_STRUCT.unpack(preamble_bytes)
    wrappers = tuple(_summarize_wrapper(wrapper) for wrapper in header.wrappers)
    wrapper_types = tuple(sorted({wrapper.type for wrapper in header.wrappers}))
    return HSE2InspectResult(
        input_path=str(path),
        container_size=container_size,
        preamble_magic=magic.decode("ascii"),
        preamble_format_version=preamble_version,
        preamble_header_encoding=header_encoding,
        preamble_header_length=header_length,
        body_size=container_size - header_frame_size,
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


def _scan_v3_body(stream: Any, header: Any) -> int:
    manifest_magic, manifest_length = struct.unpack(">4sQ", _read_exact(stream, 12, "manifest prefix"))
    if manifest_magic != V3_MANIFEST_MAGIC:
        raise HSE2ModelError("invalid v3 manifest record magic")
    if manifest_length == 0 or manifest_length > V3_MAX_MANIFEST_SIZE:
        raise HSE2ModelError("v3 manifest ciphertext length is outside the supported range")
    _skip_exact(stream, 12, "manifest nonce")
    _skip_exact(stream, manifest_length, "manifest ciphertext")
    _skip_exact(stream, 16, "manifest authentication tag")

    chunk_count = 0
    chunk_size = header.cipher_suite.chunk_size
    for expected_index in range(header.payload_layout.chunk_count):
        magic, index, ciphertext_length = struct.unpack(">4sQI", _read_exact(stream, 16, "chunk prefix"))
        if magic != V3_CHUNK_MAGIC:
            raise HSE2ModelError("invalid v3 payload chunk record magic")
        if index != expected_index:
            raise HSE2ModelError("unexpected v3 payload chunk index")
        if ciphertext_length == 0 or ciphertext_length > min(chunk_size, V3_MAX_CHUNK_SIZE):
            raise HSE2ModelError("v3 chunk ciphertext length is outside the supported range")
        _skip_exact(stream, 12, "chunk nonce")
        _skip_exact(stream, ciphertext_length, "chunk ciphertext")
        _skip_exact(stream, 16, "chunk authentication tag")
        chunk_count += 1
    if stream.read(1) != b"":
        raise HSE2ModelError("unexpected trailing bytes after v3 payload records")
    return chunk_count


def _read_exact(stream: Any, size: int, field_name: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        part = stream.read(remaining)
        if not part:
            raise HSE2ModelError(f"truncated v3 {field_name}")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def _skip_exact(stream: Any, size: int, field_name: str) -> None:
    remaining = size
    while remaining:
        block = stream.read(min(remaining, 128 * 1024))
        if not block:
            raise HSE2ModelError(f"truncated v3 {field_name}")
        remaining -= len(block)


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
