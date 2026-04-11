"""Atomic file write helpers used by encryption and sidecar writers."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, Iterator


@contextmanager
def atomic_output_path(target: str | Path) -> Iterator[Path]:
    """Yield a unique temp path and replace the target only after success."""

    target_path = Path(target)
    file_descriptor, raw_temp_path = tempfile.mkstemp(
        prefix=f".{target_path.name}.",
        suffix=".tmp",
        dir=target_path.parent,
    )
    os.close(file_descriptor)
    temp_path = Path(raw_temp_path)
    committed = False
    try:
        yield temp_path
        os.replace(temp_path, target_path)
        committed = True
    finally:
        if not committed and temp_path.exists():
            temp_path.unlink()


def flush_file(file_obj: BinaryIO) -> None:
    """Flush a binary file object before the atomic replacement."""

    file_obj.flush()
    if os.environ.get("HSE_FSYNC") == "1":
        os.fsync(file_obj.fileno())


def write_bytes_atomically(target: str | Path, data: bytes) -> Path:
    """Write bytes through a unique temp file and atomically replace target."""

    target_path = Path(target)
    with atomic_output_path(target_path) as temp_path:
        with temp_path.open("wb") as file_obj:
            file_obj.write(data)
            flush_file(file_obj)
    return target_path
