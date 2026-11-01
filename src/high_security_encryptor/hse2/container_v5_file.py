"""Bounded random-access reader for HSE2 v5 container files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

from .container_v5_crypto import V5_MAX_CONTAINER_SIZE
from .container_v5_descriptor import V5_DESCRIPTOR_OVERHEAD
from .container_v5_header import V5_FOOTER_SIZE, V5_HEADER_SIZE, V5Footer, V5PublicHeader
from .models import HSE2ModelError


def _read_exact(file_obj: BinaryIO, size: int, error: str) -> bytes:
    data = file_obj.read(size)
    if len(data) != size:
        raise HSE2ModelError(error)
    return data


class V5ContainerReader:
    """Read the fixed framing and seek directly to authenticated objects."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._file: BinaryIO | None = None
        self.file_size = 0
        self._initial_stat: tuple[int, int, int, int, int] | None = None
        self.header: V5PublicHeader
        self.footer: V5Footer

    def __enter__(self) -> "V5ContainerReader":
        file_obj = self.path.open("rb")
        try:
            stat = os.fstat(file_obj.fileno())
            size = stat.st_size
            if type(size) is not int or not V5_HEADER_SIZE + V5_FOOTER_SIZE <= size <= V5_MAX_CONTAINER_SIZE:
                raise HSE2ModelError("invalid v5 container size")
            file_obj.seek(0)
            header = V5PublicHeader.from_bytes(_read_exact(file_obj, V5_HEADER_SIZE, "invalid v5 header"))
            file_obj.seek(size - V5_FOOTER_SIZE)
            footer_bytes = _read_exact(file_obj, V5_FOOTER_SIZE, "invalid v5 footer")
            footer = V5Footer.from_bytes(footer_bytes, file_size=size)
        except Exception:
            file_obj.close()
            raise
        self._file = file_obj
        self.file_size = size
        self._initial_stat = (stat.st_dev, stat.st_ino, size, stat.st_mtime_ns, stat.st_ctime_ns)
        self.header = header
        self.footer = footer
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def _require_open(self) -> BinaryIO:
        if self._file is None:
            raise HSE2ModelError("v5 container reader is not open")
        return self._file

    def read_descriptor(self, slot: int) -> tuple[int, bytes]:
        file_obj = self._require_open()
        if type(slot) is not int or slot not in (0, 1):
            raise HSE2ModelError("invalid v5 descriptor slot")
        entry = self.footer.views[slot]
        if not V5_DESCRIPTOR_OVERHEAD <= entry.length:
            raise HSE2ModelError("invalid v5 descriptor length")
        file_obj.seek(entry.offset)
        return entry.generation, _read_exact(file_obj, entry.length, "truncated v5 descriptor")

    def read_record(self, *, offset: int, plaintext_length: int) -> bytes:
        file_obj = self._require_open()
        if (type(offset) is not int or type(plaintext_length) is not int
                or not 1 <= plaintext_length <= 1_048_576):
            raise HSE2ModelError("invalid v5 record location")
        length = 60 + plaintext_length
        if not V5_HEADER_SIZE <= offset or offset + length > self.file_size - V5_FOOTER_SIZE:
            raise HSE2ModelError("v5 record is out of bounds")
        file_obj.seek(offset)
        return _read_exact(file_obj, length, "truncated v5 record")

    def copy_prefix_to(self, output: BinaryIO, length: int) -> None:
        """Copy a bounded prefix from this already-validated source handle."""

        file_obj = self._require_open()
        if type(length) is not int or not 0 <= length <= self.file_size - V5_FOOTER_SIZE:
            raise HSE2ModelError("invalid v5 copy length")
        self.ensure_unchanged()
        file_obj.seek(0)
        remaining = length
        while remaining:
            block = file_obj.read(min(1024 * 1024, remaining))
            if not block:
                raise HSE2ModelError("v5 source changed during copy")
            output.write(block)
            remaining -= len(block)
        self.ensure_unchanged()

    def ensure_unchanged(self) -> None:
        file_obj = self._require_open()
        current = os.fstat(file_obj.fileno())
        actual = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
        if actual != self._initial_stat:
            raise HSE2ModelError("v5 source changed during operation")
