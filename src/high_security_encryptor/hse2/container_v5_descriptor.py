"""Bounded, variable-length encrypted manifests for HSE2 v5 views."""

from __future__ import annotations

import json
import secrets
import struct
from dataclasses import dataclass
from pathlib import PurePosixPath
import unicodedata

from .archive_manifest import validate_archive_path
from .container_v5_crypto import (
    V5_GCM_NONCE_SIZE, V5_GCM_TAG_SIZE, V5_HKDF_SALT_SIZE, V5_MAX_CHUNK_SIZE,
    V5_MAX_DESCRIPTOR_SIZE, V5_MAX_LIVE_CHUNKS_PER_VIEW, V5Sealed, derive_v5_key,
    open_v5, seal_v5,
)
from .container_v5_header import V5_HEADER_SIZE
from .models import HSE2ModelError, canonical_json_bytes

V5_MAX_FILES_PER_VIEW = 100_000
V5_MAX_PATH_BYTES = 4_096
V5_MAX_JSON_DEPTH = 32
V5_DESCRIPTOR_OVERHEAD = V5_HKDF_SALT_SIZE + V5_GCM_NONCE_SIZE + V5_GCM_TAG_SIZE
_DESCRIPTOR_AAD_PREFIX = b"HSE2:v5:descriptor:v1"
_DESCRIPTOR_AAD = struct.Struct(">16sBQQI")


@dataclass(frozen=True)
class V5ChunkReference:
    sequence: int
    offset: int
    length: int


@dataclass(frozen=True)
class V5FileEntry:
    path: str
    size: int
    chunks: tuple[V5ChunkReference, ...]


@dataclass(frozen=True)
class V5ViewDescriptor:
    slot: int
    generation: int
    next_sequence: int
    files: tuple[V5FileEntry, ...]


def _descriptor_aad(archive_id: bytes, slot: int, generation: int, offset: int, blob_length: int) -> bytes:
    if not isinstance(archive_id, bytes) or len(archive_id) != 16:
        raise HSE2ModelError("invalid v5 descriptor archive id")
    if type(slot) is not int or slot not in (0, 1):
        raise HSE2ModelError("invalid v5 descriptor slot")
    if type(generation) is not int or not 1 <= generation <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 descriptor generation")
    if type(offset) is not int or not V5_HEADER_SIZE <= offset <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 descriptor offset")
    if type(blob_length) is not int or not V5_DESCRIPTOR_OVERHEAD <= blob_length <= V5_MAX_DESCRIPTOR_SIZE:
        raise HSE2ModelError("invalid v5 descriptor length")
    return _DESCRIPTOR_AAD_PREFIX + _DESCRIPTOR_AAD.pack(
        archive_id, slot, generation, offset, blob_length
    )


def _validate_descriptor(view: V5ViewDescriptor, *, offset: int) -> None:
    if type(offset) is not int or not V5_HEADER_SIZE <= offset <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 descriptor offset")
    if not isinstance(view, V5ViewDescriptor):
        raise HSE2ModelError("invalid v5 descriptor")
    if type(view.slot) is not int or view.slot not in (0, 1):
        raise HSE2ModelError("invalid v5 descriptor slot")
    if type(view.generation) is not int or not 1 <= view.generation <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 descriptor generation")
    if type(view.next_sequence) is not int or not 0 <= view.next_sequence <= 0xFFFFFFFFFFFFFFFF:
        raise HSE2ModelError("invalid v5 descriptor sequence")
    if not isinstance(view.files, tuple) or len(view.files) > V5_MAX_FILES_PER_VIEW:
        raise HSE2ModelError("invalid v5 descriptor file list")

    paths: set[str] = set()
    portable_paths: set[str] = set()
    spans: list[tuple[int, int]] = []
    sequences: set[int] = set()
    chunk_count = 0
    previous_path: bytes | None = None
    for item in view.files:
        if not isinstance(item, V5FileEntry) or type(item.size) is not int or not 0 <= item.size <= 0xFFFFFFFFFFFFFFFF:
            raise HSE2ModelError("invalid v5 descriptor file entry")
        validate_archive_path(item.path)
        if "\x00" in item.path:
            raise HSE2ModelError("v5 archive path contains a NUL character")
        if unicodedata.normalize("NFC", item.path) != item.path:
            raise HSE2ModelError("v5 archive path must use NFC Unicode")
        path_bytes = item.path.encode("utf-8")
        portable_path = unicodedata.normalize("NFC", item.path.casefold())
        if len(path_bytes) > V5_MAX_PATH_BYTES or item.path in paths or portable_path in portable_paths:
            raise HSE2ModelError("invalid or duplicate v5 archive path")
        if previous_path is not None and path_bytes <= previous_path:
            raise HSE2ModelError("v5 descriptor paths are not in canonical order")
        previous_path = path_bytes
        paths.add(item.path)
        portable_paths.add(portable_path)
        if not isinstance(item.chunks, tuple):
            raise HSE2ModelError("invalid v5 file chunk list")
        file_size = 0
        previous_sequence = -1
        for chunk in item.chunks:
            if not isinstance(chunk, V5ChunkReference):
                raise HSE2ModelError("invalid v5 chunk reference")
            if (type(chunk.sequence) is not int or not 0 <= chunk.sequence < view.next_sequence
                    or chunk.sequence <= previous_sequence):
                raise HSE2ModelError("invalid v5 chunk sequence")
            if (type(chunk.offset) is not int or chunk.offset < V5_HEADER_SIZE
                    or type(chunk.length) is not int or not 1 <= chunk.length <= V5_MAX_CHUNK_SIZE):
                raise HSE2ModelError("invalid v5 chunk bounds")
            end = chunk.offset + 60 + chunk.length
            if end > offset:
                raise HSE2ModelError("v5 chunk overlaps its descriptor")
            spans.append((chunk.offset, end))
            if chunk.sequence in sequences:
                raise HSE2ModelError("duplicate v5 chunk sequence")
            sequences.add(chunk.sequence)
            previous_sequence = chunk.sequence
            file_size += chunk.length
            chunk_count += 1
        if file_size != item.size:
            raise HSE2ModelError("v5 file size does not match its chunks")
    if chunk_count > V5_MAX_LIVE_CHUNKS_PER_VIEW:
        raise HSE2ModelError("v5 live chunk limit exceeded")
    for path_key in portable_paths:
        parts = PurePosixPath(path_key).parts
        if any("/".join(parts[:depth]) in portable_paths for depth in range(1, len(parts))):
            raise HSE2ModelError("v5 file path conflicts with a parent file")
    spans.sort()
    if any(current[0] < previous[1] for previous, current in zip(spans, spans[1:])):
        raise HSE2ModelError("overlapping v5 chunk records")


def _to_manifest(view: V5ViewDescriptor) -> dict[str, object]:
    return {
        "files": [
            {"chunks": [{"length": chunk.length, "offset": chunk.offset, "sequence": chunk.sequence}
                        for chunk in item.chunks],
             "path": item.path, "size": item.size}
            for item in view.files
        ],
        "generation": view.generation,
        "next_sequence": view.next_sequence,
        "schema": 1,
        "slot": view.slot,
    }


def seal_v5_descriptor(*, root_key: bytes, archive_id: bytes, view: V5ViewDescriptor,
                       offset: int) -> bytes:
    _validate_descriptor(view, offset=offset)
    plaintext = canonical_json_bytes(_to_manifest(view))
    blob_length = V5_DESCRIPTOR_OVERHEAD + len(plaintext)
    if blob_length > V5_MAX_DESCRIPTOR_SIZE:
        raise HSE2ModelError("v5 descriptor exceeds size limit")
    salt = secrets.token_bytes(V5_HKDF_SALT_SIZE)
    nonce = secrets.token_bytes(V5_GCM_NONCE_SIZE)
    info = f"HSE2:v5:view:{view.slot}:descriptor:{view.generation}:v1".encode("ascii")
    key = derive_v5_key(root_key=root_key, salt=salt, info=info)
    sealed = seal_v5(key=key, nonce=nonce, plaintext=plaintext,
                     aad=_descriptor_aad(archive_id, view.slot, view.generation, offset, blob_length))
    return salt + nonce + sealed.ciphertext + sealed.tag


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HSE2ModelError("duplicate v5 manifest key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise HSE2ModelError(f"invalid v5 JSON constant: {value}")


def _check_json_depth(data: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > V5_MAX_JSON_DEPTH:
                raise HSE2ModelError("v5 manifest nesting limit exceeded")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise HSE2ModelError("invalid v5 manifest JSON")
    if in_string or depth != 0:
        raise HSE2ModelError("invalid v5 manifest JSON")


def _from_manifest(value: object, *, slot: int, generation: int, offset: int) -> V5ViewDescriptor:
    if not isinstance(value, dict) or set(value) != {"files", "generation", "next_sequence", "schema", "slot"}:
        raise HSE2ModelError("invalid v5 descriptor manifest")
    if (type(value["schema"]) is not int or value["schema"] != 1
            or type(value["slot"]) is not int or value["slot"] != slot
            or type(value["generation"]) is not int or value["generation"] != generation
            or type(value["next_sequence"]) is not int
            or not isinstance(value["files"], list)
            or len(value["files"]) > V5_MAX_FILES_PER_VIEW):
        raise HSE2ModelError("invalid v5 descriptor manifest")
    files = []
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"chunks", "path", "size"}:
            raise HSE2ModelError("invalid v5 descriptor file entry")
        if not isinstance(item["chunks"], list):
            raise HSE2ModelError("invalid v5 descriptor chunk list")
        chunks = []
        for chunk in item["chunks"]:
            if not isinstance(chunk, dict) or set(chunk) != {"length", "offset", "sequence"}:
                raise HSE2ModelError("invalid v5 descriptor chunk reference")
            chunks.append(V5ChunkReference(chunk["sequence"], chunk["offset"], chunk["length"]))
        files.append(V5FileEntry(item["path"], item["size"], tuple(chunks)))
    descriptor = V5ViewDescriptor(slot, generation, value["next_sequence"], tuple(files))
    _validate_descriptor(descriptor, offset=offset)
    return descriptor


def open_v5_descriptor(*, root_key: bytes, archive_id: bytes, slot: int, generation: int,
                       offset: int, blob: bytes) -> V5ViewDescriptor:
    if not isinstance(blob, bytes) or not V5_DESCRIPTOR_OVERHEAD <= len(blob) <= V5_MAX_DESCRIPTOR_SIZE:
        raise HSE2ModelError("v5 descriptor authentication failed")
    salt = blob[:V5_HKDF_SALT_SIZE]
    nonce_start = V5_HKDF_SALT_SIZE
    nonce = blob[nonce_start:nonce_start + V5_GCM_NONCE_SIZE]
    ciphertext = blob[V5_HKDF_SALT_SIZE + V5_GCM_NONCE_SIZE:-V5_GCM_TAG_SIZE]
    tag = blob[-V5_GCM_TAG_SIZE:]
    try:
        info = f"HSE2:v5:view:{slot}:descriptor:{generation}:v1".encode("ascii")
        key = derive_v5_key(root_key=root_key, salt=salt, info=info)
        plaintext = open_v5(
            key=key,
            sealed=V5Sealed(nonce, ciphertext, tag),
            aad=_descriptor_aad(archive_id, slot, generation, offset, len(blob)),
        )
        _check_json_depth(plaintext)
        value = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
                           parse_constant=_reject_json_constant)
        if canonical_json_bytes(value) != plaintext:
            raise HSE2ModelError("non-canonical v5 descriptor JSON")
        return _from_manifest(value, slot=slot, generation=generation, offset=offset)
    except (HSE2ModelError, ValueError, UnicodeError, RecursionError, json.JSONDecodeError, struct.error) as exc:
        raise HSE2ModelError("v5 descriptor authentication failed") from exc
