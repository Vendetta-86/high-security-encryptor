"""Path-based streaming I/O for HSE2 archive version 3."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator

from ..atomic_io import atomic_output_path
from .container_stream import (
    iter_v3_payload_chunk_records,
    read_v3_header_frame,
    read_v3_manifest_record,
    write_v3_header_frame,
    write_v3_manifest_record,
    write_v3_payload_chunk_record,
)
from .manifest_crypto import EncryptedManifest
from .models import HSE2Header, HSE2ModelError
from .payload_crypto import EncryptedPayloadChunk


class HSE2V3ContainerReader:
    """Read a v3 container sequentially after the header is authenticated."""

    def __init__(self, stream: BinaryIO, *, header_frame: bytes, header: HSE2Header) -> None:
        self.header_frame = header_frame
        self.header = header
        self._stream = stream
        self._manifest_read = False
        self._payload_iteration_started = False

    def read_manifest(self) -> EncryptedManifest:
        """Read the single encrypted manifest record after header verification."""

        if self._manifest_read:
            raise HSE2ModelError("v3 manifest record has already been read")
        manifest = read_v3_manifest_record(self._stream)
        self._manifest_read = True
        return manifest

    def iter_payload_chunks(self) -> Iterator[EncryptedPayloadChunk]:
        """Stream payload chunks in authenticated index order and require EOF."""

        if not self._manifest_read:
            raise HSE2ModelError("v3 manifest must be read before payload chunks")
        if self._payload_iteration_started:
            raise HSE2ModelError("v3 payload chunks can only be read once")
        self._payload_iteration_started = True
        return iter_v3_payload_chunk_records(
            self._stream,
            chunk_count=self.header.payload_layout.chunk_count,
            chunk_size=self.header.cipher_suite.chunk_size,
        )


@contextmanager
def open_v3_container(
    path: str | os.PathLike[str],
    *,
    authenticate_header: Callable[[HSE2Header], None],
) -> Iterator[HSE2V3ContainerReader]:
    """Open a v3 archive and authenticate its header before exposing the body.

    The callback must unlock a wrapper and validate the header HMAC. It is
    invoked before the manifest or payload body is read.
    """

    target = Path(path)
    with target.open("rb") as stream:
        header_frame, header = read_v3_header_frame(stream)
        authenticate_header(header)
        yield HSE2V3ContainerReader(stream, header_frame=header_frame, header=header)


def write_v3_container(
    path: str | os.PathLike[str],
    *,
    header: HSE2Header,
    manifest: EncryptedManifest,
    payload_chunks: Iterable[EncryptedPayloadChunk],
    overwrite: bool = False,
) -> Path:
    """Write a v3 archive incrementally and atomically replace the target."""

    target = Path(path)
    if target.exists() and not overwrite:
        raise HSE2ModelError(f"target already exists: {target}")
    parent = target.parent if target.parent != Path("") else Path(".")
    parent.mkdir(parents=True, exist_ok=True)

    with atomic_output_path(target) as temp_path:
        with temp_path.open("wb") as stream:
            write_v3_header_frame(stream, header)
            write_v3_manifest_record(stream, manifest)
            _write_declared_payload_chunks(stream, payload_chunks, header)
            stream.flush()
            os.fsync(stream.fileno())
    return target


def _write_declared_payload_chunks(
    stream: BinaryIO,
    payload_chunks: Iterable[EncryptedPayloadChunk],
    header: HSE2Header,
) -> None:
    chunks = iter(payload_chunks)
    for expected_index in range(header.payload_layout.chunk_count):
        try:
            chunk = next(chunks)
        except StopIteration as exc:
            raise HSE2ModelError("payload chunk iterable ended before the declared chunk_count") from exc
        if chunk.index != expected_index:
            raise HSE2ModelError("payload chunk iterable is not in contiguous index order")
        write_v3_payload_chunk_record(stream, chunk)

    try:
        next(chunks)
    except StopIteration:
        return
    raise HSE2ModelError("payload chunk iterable contains more than the declared chunk_count")
