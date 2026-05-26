"""Filesystem traversal helpers for HSE2 archive manifest entries.

This module converts caller-selected filesystem roots into normalized archive
manifest entries. It reads filesystem metadata only; it does not read file
contents, encrypt payloads, write containers, or provide CLI/GUI behavior.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from .archive_manifest import HSE2ArchiveEntry
from .models import HSE2ModelError


def build_archive_entries_from_root(root: str | Path) -> tuple[HSE2ArchiveEntry, ...]:
    """Build archive manifest entries from one filesystem root."""

    root_path = Path(root)
    if not root_path.exists():
        raise HSE2ModelError(f"archive root does not exist: {root_path}")
    if root_path.is_file():
        return (_entry_for_path(root_path, root_path.parent),)
    if root_path.is_dir():
        return _entries_for_directory(root_path)
    raise HSE2ModelError(f"archive root is not a regular file or directory: {root_path}")


def build_archive_entries_from_roots(roots: tuple[str | Path, ...]) -> tuple[HSE2ArchiveEntry, ...]:
    """Build archive manifest entries from multiple filesystem roots."""

    if not roots:
        raise HSE2ModelError("at least one archive root is required")
    entries: list[HSE2ArchiveEntry] = []
    for root in roots:
        entries.extend(build_archive_entries_from_root(root))
    return tuple(sorted(entries, key=lambda entry: entry.path))


def _entries_for_directory(root: Path) -> tuple[HSE2ArchiveEntry, ...]:
    entries: list[HSE2ArchiveEntry] = [_entry_for_path(root, root.parent)]
    for path in sorted(root.rglob("*"), key=lambda item: _relative_posix_path(item, root.parent)):
        if path.is_file() or path.is_dir():
            entries.append(_entry_for_path(path, root.parent))
    return tuple(entries)


def _entry_for_path(path: Path, base: Path) -> HSE2ArchiveEntry:
    try:
        stat = path.stat()
    except OSError as exc:
        raise HSE2ModelError(f"cannot stat archive path: {path}") from exc
    kind = "directory" if path.is_dir() else "file"
    size = 0 if kind == "directory" else stat.st_size
    return HSE2ArchiveEntry(
        path=_relative_posix_path(path, base),
        kind=kind,
        size=size,
        modified_utc=_utc_from_timestamp(stat.st_mtime),
    )


def _relative_posix_path(path: Path, base: Path) -> str:
    try:
        relative = path.relative_to(base)
    except ValueError as exc:
        raise HSE2ModelError(f"archive path is not under base: {path}") from exc
    value = relative.as_posix()
    if value in {"", "."}:
        raise HSE2ModelError("archive relative path must not be empty")
    return value


def _utc_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
