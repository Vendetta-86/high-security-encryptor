"""Bounded inspection of HSE2 keyfile suitability and fingerprint."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Any

from .keyfile_kdf import HSE2_KEYFILE_MIN_SIZE
from .models import HSE2ModelError


KEYFILE_INSPECT_BUFFER_SIZE = 128 * 1024


@dataclass(frozen=True)
class HSE2KeyfileInspection:
    """Non-secret diagnostics for one keyfile."""

    input_path: str
    size_bytes: int
    minimum_size_bytes: int
    hse2_compatible: bool
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-keyfile-inspect",
            "input": self.input_path,
            "size_bytes": self.size_bytes,
            "minimum_size_bytes": self.minimum_size_bytes,
            "hse2_compatible": self.hse2_compatible,
            "sha256": self.sha256,
        }


def inspect_hse2_keyfile(path: str | os.PathLike[str]) -> HSE2KeyfileInspection:
    """Hash a regular file with bounded reads and report wrapper suitability.

    The fingerprint identifies the file but is not key material. This function
    never returns or logs keyfile bytes.
    """

    input_path = Path(path)
    digest = hashlib.sha256()
    with input_path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise HSE2ModelError("keyfile input must be a regular file")
        while block := stream.read(KEYFILE_INSPECT_BUFFER_SIZE):
            digest.update(block)
        after = os.fstat(stream.fileno())

    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise HSE2ModelError("keyfile changed while it was being inspected")
    return HSE2KeyfileInspection(
        input_path=str(input_path),
        size_bytes=after.st_size,
        minimum_size_bytes=HSE2_KEYFILE_MIN_SIZE,
        hse2_compatible=after.st_size >= HSE2_KEYFILE_MIN_SIZE,
        sha256=digest.hexdigest(),
    )
