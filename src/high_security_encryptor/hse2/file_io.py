"""Filesystem path helpers for HSE2 container bytes.

This module is intentionally thin: it writes and reads already assembled HSE2
container bytes through filesystem paths. It does not prompt users, unlock
wrappers, traverse directories, or provide CLI/GUI behavior.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .container_bytes import HSE2ContainerBytes, decode_container_bytes, encode_container_bytes
from .manifest_crypto import EncryptedManifest
from .models import HSE2Header, HSE2ModelError
from .payload_crypto import EncryptedPayloadChunk


def write_container_bytes(path: str | os.PathLike[str], data: bytes, *, overwrite: bool = False) -> None:
    """Atomically write raw HSE2 container bytes to a filesystem path."""

    target = Path(path)
    if not data:
        raise HSE2ModelError("container data must not be empty")
    if target.exists() and not overwrite:
        raise HSE2ModelError(f"target already exists: {target}")
    parent = target.parent if target.parent != Path("") else Path(".")
    parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


def read_container_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read raw HSE2 container bytes from a filesystem path."""

    data = Path(path).read_bytes()
    if not data:
        raise HSE2ModelError("container file is empty")
    return data


def write_hse2_container(
    path: str | os.PathLike[str],
    *,
    header: HSE2Header,
    manifest: EncryptedManifest,
    payload_chunks: tuple[EncryptedPayloadChunk, ...],
    overwrite: bool = False,
) -> None:
    """Encode and atomically write an HSE2 container to a filesystem path."""

    write_container_bytes(
        path,
        encode_container_bytes(header, manifest=manifest, payload_chunks=payload_chunks),
        overwrite=overwrite,
    )


def read_hse2_container(path: str | os.PathLike[str]) -> HSE2ContainerBytes:
    """Read and decode an HSE2 container from a filesystem path."""

    return decode_container_bytes(read_container_bytes(path))
