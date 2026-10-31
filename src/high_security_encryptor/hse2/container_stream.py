"""Bounded binary record I/O for the HSE2 archive v3 body."""

from __future__ import annotations

import json
import struct
from typing import BinaryIO, Iterator

from .container_codec import HSE2_HEADER_ENCODING_CANONICAL_JSON, HSE2_MAGIC, HSE2_PREAMBLE_STRUCT
from .encoding import b64decode_bytes, b64encode_bytes
from .manifest_crypto import EncryptedManifest
from .models import HSE2Header, HSE2ModelError
from .payload_crypto import EncryptedPayloadChunk
from .container_codec import hse2_header_from_dict


V3_MANIFEST_MAGIC = b"MNF3"
V3_CHUNK_MAGIC = b"CHK3"
V3_PREAMBLE_VERSION = 3
V3_NONCE_SIZE = 12
V3_TAG_SIZE = 16
V3_MAX_HEADER_SIZE = 1024 * 1024
V3_MAX_MANIFEST_SIZE = 64 * 1024 * 1024
V3_MAX_CHUNK_SIZE = 16 * 1024 * 1024
_U64_MAX = (1 << 64) - 1
_MANIFEST_PREFIX = struct.Struct(">4sQ")
_CHUNK_PREFIX = struct.Struct(">4sQI")


def write_v3_header_frame(stream: BinaryIO, header: HSE2Header) -> None:
    """Write a bounded canonical-JSON v3 preamble and authenticated header."""

    if header.format_version != V3_PREAMBLE_VERSION:
        raise HSE2ModelError("v3 header frame requires format_version 3")
    if header.header_auth_tag is None:
        raise HSE2ModelError("v3 header frame requires a header authentication tag")
    _validate_v3_header_layout(header)
    header_bytes = header.canonical_bytes(include_auth_tag=True)
    if not header_bytes or len(header_bytes) > V3_MAX_HEADER_SIZE:
        raise HSE2ModelError("v3 header length is outside the supported range")
    preamble = HSE2_PREAMBLE_STRUCT.pack(
        HSE2_MAGIC,
        V3_PREAMBLE_VERSION,
        HSE2_HEADER_ENCODING_CANONICAL_JSON,
        0,
        len(header_bytes),
    )
    _write_all(stream, preamble)
    _write_all(stream, header_bytes)


def read_v3_header_frame(stream: BinaryIO) -> tuple[bytes, HSE2Header]:
    """Read and validate one bounded v3 preamble/header frame."""

    preamble_bytes = _read_exact(stream, HSE2_PREAMBLE_STRUCT.size, "preamble")
    magic, version, header_encoding, reserved, header_length = HSE2_PREAMBLE_STRUCT.unpack(preamble_bytes)
    if magic != HSE2_MAGIC:
        raise HSE2ModelError("invalid HSE2 magic")
    if version != V3_PREAMBLE_VERSION:
        raise HSE2ModelError(f"unsupported HSE2 preamble version: {version}")
    if header_encoding != HSE2_HEADER_ENCODING_CANONICAL_JSON:
        raise HSE2ModelError(f"unsupported HSE2 header encoding: {header_encoding}")
    if reserved != 0:
        raise HSE2ModelError("HSE2 preamble reserved field must be zero")
    if header_length == 0 or header_length > V3_MAX_HEADER_SIZE:
        raise HSE2ModelError("v3 header length is outside the supported range")

    header_bytes = _read_exact(stream, header_length, "header")
    try:
        header_value = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HSE2ModelError("HSE2 header is not valid JSON") from exc
    header = hse2_header_from_dict(header_value)
    if header.format_version != version:
        raise HSE2ModelError("HSE2 preamble and header versions do not match")
    if header.header_auth_tag is None:
        raise HSE2ModelError("v3 header authentication tag is missing")
    _validate_v3_header_layout(header)
    if header.canonical_bytes(include_auth_tag=True) != header_bytes:
        raise HSE2ModelError("HSE2 v3 header JSON is not canonical")
    return preamble_bytes + header_bytes, header


def write_v3_manifest_record(stream: BinaryIO, manifest: EncryptedManifest) -> None:
    """Write one raw-byte manifest record, without JSON/Base64 expansion."""

    nonce = b64decode_bytes(manifest.nonce, field_name="manifest nonce")
    ciphertext = b64decode_bytes(manifest.ciphertext, field_name="manifest ciphertext")
    tag = b64decode_bytes(manifest.auth_tag, field_name="manifest auth_tag")
    if len(nonce) != V3_NONCE_SIZE or len(tag) != V3_TAG_SIZE:
        raise HSE2ModelError("invalid v3 manifest nonce or tag length")
    if not ciphertext or len(ciphertext) > V3_MAX_MANIFEST_SIZE:
        raise HSE2ModelError("v3 manifest ciphertext length is outside the supported range")
    _write_all(stream, _MANIFEST_PREFIX.pack(V3_MANIFEST_MAGIC, len(ciphertext)))
    _write_all(stream, nonce)
    _write_all(stream, ciphertext)
    _write_all(stream, tag)


def read_v3_manifest_record(stream: BinaryIO) -> EncryptedManifest:
    """Read one bounded manifest record from a binary stream."""

    magic, ciphertext_length = _MANIFEST_PREFIX.unpack(_read_exact(stream, _MANIFEST_PREFIX.size, "manifest prefix"))
    if magic != V3_MANIFEST_MAGIC:
        raise HSE2ModelError("invalid v3 manifest record magic")
    if ciphertext_length == 0 or ciphertext_length > V3_MAX_MANIFEST_SIZE:
        raise HSE2ModelError("v3 manifest ciphertext length is outside the supported range")
    nonce = _read_exact(stream, V3_NONCE_SIZE, "manifest nonce")
    ciphertext = _read_exact(stream, ciphertext_length, "manifest ciphertext")
    tag = _read_exact(stream, V3_TAG_SIZE, "manifest authentication tag")
    return EncryptedManifest(
        nonce=b64encode_bytes(nonce),
        ciphertext=b64encode_bytes(ciphertext),
        auth_tag=b64encode_bytes(tag),
    )


def write_v3_payload_chunk_record(stream: BinaryIO, chunk: EncryptedPayloadChunk) -> None:
    """Write one raw-byte chunk record."""

    if chunk.index > _U64_MAX:
        raise HSE2ModelError("v3 chunk index exceeds the unsigned 64-bit range")
    nonce = b64decode_bytes(chunk.nonce, field_name="payload chunk nonce")
    ciphertext = b64decode_bytes(chunk.ciphertext, field_name="payload chunk ciphertext")
    tag = b64decode_bytes(chunk.auth_tag, field_name="payload chunk auth_tag")
    if len(nonce) != V3_NONCE_SIZE or len(tag) != V3_TAG_SIZE:
        raise HSE2ModelError("invalid v3 chunk nonce or tag length")
    if not ciphertext or len(ciphertext) > V3_MAX_CHUNK_SIZE:
        raise HSE2ModelError("v3 chunk ciphertext length is outside the supported range")
    _write_all(stream, _CHUNK_PREFIX.pack(V3_CHUNK_MAGIC, chunk.index, len(ciphertext)))
    _write_all(stream, nonce)
    _write_all(stream, ciphertext)
    _write_all(stream, tag)


def read_v3_payload_chunk_record(
    stream: BinaryIO,
    *,
    expected_index: int,
    chunk_size: int,
) -> EncryptedPayloadChunk:
    """Read and validate one chunk record before reading its declared payload."""

    if expected_index < 0 or expected_index > _U64_MAX:
        raise HSE2ModelError("expected v3 chunk index is outside the unsigned 64-bit range")
    if chunk_size <= 0 or chunk_size > V3_MAX_CHUNK_SIZE:
        raise HSE2ModelError("v3 chunk_size is outside the supported range")
    magic, index, ciphertext_length = _CHUNK_PREFIX.unpack(
        _read_exact(stream, _CHUNK_PREFIX.size, "chunk prefix")
    )
    if magic != V3_CHUNK_MAGIC:
        raise HSE2ModelError("invalid v3 payload chunk record magic")
    if index != expected_index:
        raise HSE2ModelError("unexpected v3 payload chunk index")
    if ciphertext_length == 0 or ciphertext_length > chunk_size:
        raise HSE2ModelError("v3 chunk ciphertext length is outside the supported range")
    nonce = _read_exact(stream, V3_NONCE_SIZE, "chunk nonce")
    ciphertext = _read_exact(stream, ciphertext_length, "chunk ciphertext")
    tag = _read_exact(stream, V3_TAG_SIZE, "chunk authentication tag")
    return EncryptedPayloadChunk(
        index=index,
        nonce=b64encode_bytes(nonce),
        ciphertext=b64encode_bytes(ciphertext),
        auth_tag=b64encode_bytes(tag),
    )


def require_v3_eof(stream: BinaryIO) -> None:
    """Reject any bytes after the declared manifest and chunk records."""

    if stream.read(1) != b"":
        raise HSE2ModelError("unexpected trailing bytes after v3 payload records")


def iter_v3_payload_chunk_records(
    stream: BinaryIO,
    *,
    chunk_count: int,
    chunk_size: int,
) -> Iterator[EncryptedPayloadChunk]:
    """Yield the authenticated header's exact chunk count, then require EOF.

    The caller must authenticate the header before passing its chunk_count.
    EOF validation occurs when the iterator is exhausted.
    """

    if chunk_count < 0 or chunk_count > _U64_MAX:
        raise HSE2ModelError("v3 chunk_count is outside the unsigned 64-bit range")
    for expected_index in range(chunk_count):
        yield read_v3_payload_chunk_record(
            stream,
            expected_index=expected_index,
            chunk_size=chunk_size,
        )
    require_v3_eof(stream)


def _read_exact(stream: BinaryIO, size: int, field_name: str) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining:
        block = stream.read(remaining)
        if not block:
            raise HSE2ModelError(f"truncated v3 {field_name}")
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


def _write_all(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = stream.write(view[written:])
        if count is None or count <= 0:
            raise HSE2ModelError("short write while writing v3 record")
        written += count


def _validate_v3_header_layout(header: HSE2Header) -> None:
    if not header.manifest_policy.encrypted:
        raise HSE2ModelError("v3 requires an encrypted manifest")
    if header.cipher_suite.chunk_size <= 0 or header.cipher_suite.chunk_size > V3_MAX_CHUNK_SIZE:
        raise HSE2ModelError("v3 chunk_size is outside the supported range")
    if header.payload_layout.chunk_count > _U64_MAX:
        raise HSE2ModelError("v3 chunk_count exceeds the unsigned 64-bit range")
    if header.payload_layout.payload_offset != 0 or header.payload_layout.footer_offset != 0:
        raise HSE2ModelError("v3 payload offsets must be zero reserved fields")
