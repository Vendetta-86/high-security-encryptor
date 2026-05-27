"""Archive assembly planning helpers for HSE2.

This module maps normalized archive entries to deterministic payload chunk index
ranges. It does not read file contents, encrypt payload bytes, write containers,
prompt users, or provide CLI/GUI behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .archive_manifest import HSE2ArchiveEntry, build_archive_manifest
from .models import HSE2ModelError


@dataclass(frozen=True)
class HSE2ArchivePayloadRange:
    """Payload chunk range assigned to one archive file entry."""

    path: str
    size: int
    start_chunk: int
    chunk_count: int

    def __post_init__(self) -> None:
        if not self.path:
            raise HSE2ModelError("payload range path must not be empty")
        if self.size < 0:
            raise HSE2ModelError("payload range size must not be negative")
        if self.start_chunk < 0:
            raise HSE2ModelError("payload range start_chunk must not be negative")
        if self.chunk_count < 0:
            raise HSE2ModelError("payload range chunk_count must not be negative")
        if self.size > 0 and self.chunk_count == 0:
            raise HSE2ModelError("non-empty payload range must contain chunks")
        if self.size == 0 and self.chunk_count != 0:
            raise HSE2ModelError("empty payload range must not contain chunks")

    def to_dict(self) -> dict[str, int | str]:
        return {
            "path": self.path,
            "size": self.size,
            "start_chunk": self.start_chunk,
            "chunk_count": self.chunk_count,
        }


def build_archive_payload_plan(
    entries: tuple[HSE2ArchiveEntry, ...],
    *,
    chunk_size: int,
) -> tuple[HSE2ArchivePayloadRange, ...]:
    """Assign deterministic payload chunk ranges to archive file entries."""

    if chunk_size <= 0:
        raise HSE2ModelError("chunk_size must be positive")
    manifest = build_archive_manifest(entries)
    next_chunk = 0
    ranges: list[HSE2ArchivePayloadRange] = []
    for item in manifest["entries"]:
        if item["kind"] != "file":
            continue
        size = int(item["size"])
        chunk_count = _chunk_count_for_size(size, chunk_size)
        ranges.append(
            HSE2ArchivePayloadRange(
                path=str(item["path"]),
                size=size,
                start_chunk=next_chunk,
                chunk_count=chunk_count,
            )
        )
        next_chunk += chunk_count
    return tuple(ranges)


def build_archive_assembly_plan(
    entries: tuple[HSE2ArchiveEntry, ...],
    *,
    chunk_size: int,
) -> dict[str, Any]:
    """Build a JSON-safe archive assembly plan without reading file contents."""

    manifest = build_archive_manifest(entries)
    payload_ranges = build_archive_payload_plan(entries, chunk_size=chunk_size)
    return {
        "format": "HSE2-archive-assembly-plan-v1",
        "chunk_size": chunk_size,
        "entry_count": len(manifest["entries"]),
        "file_count": len(payload_ranges),
        "payload_chunk_count": sum(item.chunk_count for item in payload_ranges),
        "entries": manifest["entries"],
        "payload_ranges": [item.to_dict() for item in payload_ranges],
    }


def _chunk_count_for_size(size: int, chunk_size: int) -> int:
    if size == 0:
        return 0
    return (size + chunk_size - 1) // chunk_size
