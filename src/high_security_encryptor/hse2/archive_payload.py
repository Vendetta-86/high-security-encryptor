"""Archive payload chunk building helpers for HSE2.

This module reads regular file bytes from caller-supplied paths and converts
them into encrypted payload chunks. It does not traverse user-selected roots,
build wrappers, prompt users, write containers, or provide CLI/GUI behavior.
"""

from __future__ import annotations

from pathlib import Path

from .keys import HSE2KeyMaterial
from .models import HSE2ModelError
from .payload_crypto import EncryptedPayloadChunk, encrypt_payload_chunk


DEFAULT_ARCHIVE_CHUNK_SIZE = 1024 * 1024


def build_payload_chunks_from_file(
    path: str | Path,
    *,
    dek: HSE2KeyMaterial,
    start_index: int = 0,
    chunk_size: int = DEFAULT_ARCHIVE_CHUNK_SIZE,
    context: bytes | None = None,
) -> tuple[EncryptedPayloadChunk, ...]:
    """Encrypt one regular file into one or more payload chunks."""

    if start_index < 0:
        raise HSE2ModelError("start_index must not be negative")
    if chunk_size <= 0:
        raise HSE2ModelError("chunk_size must be positive")
    file_path = Path(path)
    if not file_path.is_file():
        raise HSE2ModelError(f"archive payload source must be a regular file: {file_path}")

    chunks: list[EncryptedPayloadChunk] = []
    index = start_index
    try:
        with file_path.open("rb") as handle:
            while True:
                data = handle.read(chunk_size)
                if not data:
                    break
                chunks.append(encrypt_payload_chunk(data, dek=dek, index=index, context=context))
                index += 1
    except OSError as exc:
        raise HSE2ModelError(f"cannot read archive payload source: {file_path}") from exc
    return tuple(chunks)


def build_payload_chunks_from_files(
    paths: tuple[str | Path, ...],
    *,
    dek: HSE2KeyMaterial,
    chunk_size: int = DEFAULT_ARCHIVE_CHUNK_SIZE,
    context: bytes | None = None,
) -> tuple[EncryptedPayloadChunk, ...]:
    """Encrypt multiple regular files into a contiguous payload chunk sequence."""

    if not paths:
        raise HSE2ModelError("at least one archive payload source is required")
    chunks: list[EncryptedPayloadChunk] = []
    next_index = 0
    for path in paths:
        file_chunks = build_payload_chunks_from_file(
            path,
            dek=dek,
            start_index=next_index,
            chunk_size=chunk_size,
            context=context,
        )
        chunks.extend(file_chunks)
        next_index += len(file_chunks)
    return tuple(chunks)
