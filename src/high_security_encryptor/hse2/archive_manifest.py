"""Archive manifest planning helpers for HSE2.

This module builds deterministic manifest dictionaries from caller-supplied path
metadata. It does not read file contents, encrypt payload bytes, prompt users,
write containers, or provide CLI/GUI behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .models import HSE2ModelError, canonical_json_bytes


@dataclass(frozen=True)
class HSE2ArchiveEntry:
    """A normalized archive entry for manifest construction."""

    path: str
    kind: str
    size: int = 0
    modified_utc: str | None = None

    def __post_init__(self) -> None:
        _validate_archive_path(self.path)
        if self.kind not in {"file", "directory"}:
            raise HSE2ModelError("archive entry kind must be file or directory")
        if self.size < 0:
            raise HSE2ModelError("archive entry size must not be negative")
        if self.kind == "directory" and self.size != 0:
            raise HSE2ModelError("directory archive entry size must be zero")
        if self.modified_utc is not None and not self.modified_utc:
            raise HSE2ModelError("modified_utc must be omitted or non-empty")

    def to_manifest_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
        }
        if self.modified_utc is not None:
            data["modified_utc"] = self.modified_utc
        return data


def build_archive_manifest(entries: tuple[HSE2ArchiveEntry, ...]) -> dict[str, Any]:
    """Build a deterministic encrypted-manifest plaintext dictionary."""

    if not entries:
        raise HSE2ModelError("archive manifest requires at least one entry")
    sorted_entries = tuple(sorted(entries, key=lambda entry: entry.path))
    _reject_duplicate_paths(sorted_entries)
    return {
        "format": "HSE2-archive-manifest-v1",
        "entries": [entry.to_manifest_dict() for entry in sorted_entries],
    }


def archive_manifest_digest(entries: tuple[HSE2ArchiveEntry, ...]) -> bytes:
    """Return canonical manifest bytes for deterministic tests and callers."""

    return canonical_json_bytes(build_archive_manifest(entries))


def _validate_archive_path(path: str) -> None:
    if not path:
        raise HSE2ModelError("archive path must not be empty")
    if "\\" in path:
        raise HSE2ModelError("archive path must use POSIX separators")
    if path.startswith("/"):
        raise HSE2ModelError("archive path must be relative")
    posix = PurePosixPath(path)
    if any(part in {"", ".", ".."} for part in posix.parts):
        raise HSE2ModelError("archive path must not contain empty, current, or parent segments")


def _reject_duplicate_paths(entries: tuple[HSE2ArchiveEntry, ...]) -> None:
    seen: set[str] = set()
    for entry in entries:
        if entry.path in seen:
            raise HSE2ModelError(f"duplicate archive path: {entry.path}")
        seen.add(entry.path)
