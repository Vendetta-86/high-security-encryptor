"""Archive planning summary helpers for HSE2.

This module summarizes caller-selected filesystem roots as deterministic archive
manifest metadata. It does not read file contents, encrypt payload bytes, write
containers, prompt users, or provide GUI behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .archive_manifest import build_archive_manifest
from .archive_traversal import build_archive_entries_from_roots


def build_archive_plan_summary(roots: tuple[str | Path, ...]) -> dict[str, Any]:
    """Build a JSON-safe metadata summary for archive planning."""

    entries = build_archive_entries_from_roots(roots)
    manifest = build_archive_manifest(entries)
    file_count = sum(1 for entry in entries if entry.kind == "file")
    directory_count = sum(1 for entry in entries if entry.kind == "directory")
    total_file_size = sum(entry.size for entry in entries if entry.kind == "file")
    return {
        "format": manifest["format"],
        "root_count": len(roots),
        "entry_count": len(entries),
        "file_count": file_count,
        "directory_count": directory_count,
        "total_file_size": total_file_size,
        "entries": manifest["entries"],
    }
