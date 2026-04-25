"""Utilities used while building encrypted folder packages."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable
import zipfile


def normalize_safe_relative_member_path(raw_relative_path: str, context: str = "folder entry") -> str:
    """Normalize a package-internal relative path and reject traversal primitives."""

    candidate = PurePosixPath(str(raw_relative_path).replace("\\", "/"))
    if candidate.is_absolute():
        raise ValueError(f"{context} must be relative: {raw_relative_path}")
    if not candidate.parts or candidate.as_posix() == ".":
        raise ValueError(f"{context} must not be empty: {raw_relative_path}")
    if any(part in ("", ".", "..") or ":" in part for part in candidate.parts):
        raise ValueError(f"{context} contains unsafe path segments: {raw_relative_path}")
    return candidate.as_posix()


def normalize_relative_path_list(source_folder: Path, relative_paths: list[str]) -> list[str]:
    """Validate and normalize folder-relative file paths."""

    normalized: list[str] = []
    seen: set[str] = set()
    for raw_relative_path in relative_paths:
        posix_relative_path = normalize_relative_path(source_folder, raw_relative_path)
        if posix_relative_path not in seen:
            seen.add(posix_relative_path)
            normalized.append(posix_relative_path)
    return sorted(normalized)


def normalize_inner_password_mapping(passwords_by_relative_path: dict[str, str]) -> dict[str, str]:
    """Normalize password keys for independently encrypted folder entries."""

    normalized: dict[str, str] = {}
    for raw_relative_path, password in passwords_by_relative_path.items():
        posix_relative_path = normalize_safe_relative_member_path(
            str(raw_relative_path),
            "folder inner password path",
        )
        normalized[posix_relative_path] = password
    return normalized


def normalize_relative_path(source_folder: Path, raw_relative_path: str) -> str:
    """Convert caller input to a safe normalized relative path."""

    normalized = normalize_safe_relative_member_path(raw_relative_path)
    concrete_path = source_folder / Path(normalized)
    if not concrete_path.exists():
        raise FileNotFoundError(concrete_path)
    return normalized


def write_zip_from_directory(source_root: Path, zip_path: Path) -> None:
    """Write a deterministic ZIP file preserving the root directory name."""

    write_zip_file_entries(
        (
            (file_path, (PurePosixPath(source_root.name) / file_path.relative_to(source_root).as_posix()).as_posix())
            for file_path in sorted(path for path in source_root.rglob("*") if path.is_file())
        ),
        zip_path,
    )


def write_zip_file_entries(
    file_entries: Iterable[tuple[Path, str]],
    zip_target: str | Path | BinaryIO,
) -> None:
    """Write validated file entries to a ZIP path or write-only stream."""

    seen_names: set[str] = set()
    with zipfile.ZipFile(zip_target, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        for source_path, archive_name in sorted(file_entries, key=lambda entry: entry[1]):
            normalized_archive_name = normalize_safe_relative_member_path(archive_name, "zip archive entry")
            if normalized_archive_name in seen_names:
                raise ValueError(f"duplicate zip archive entry: {normalized_archive_name}")
            seen_names.add(normalized_archive_name)
            zip_file.write(source_path, normalized_archive_name)
