"""Utilities used while building encrypted folder packages."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import zipfile


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
        posix_relative_path = PurePosixPath(str(raw_relative_path).replace("\\", "/")).as_posix()
        normalized[posix_relative_path] = password
    return normalized


def normalize_relative_path(source_folder: Path, raw_relative_path: str) -> str:
    """Convert caller input to a safe normalized relative path."""

    candidate = PurePosixPath(str(raw_relative_path).replace("\\", "/"))
    if candidate.is_absolute():
        raise ValueError(f"folder entry must be relative: {raw_relative_path}")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise ValueError(f"folder entry contains unsafe path segments: {raw_relative_path}")

    normalized = candidate.as_posix()
    concrete_path = source_folder / Path(normalized)
    if not concrete_path.exists():
        raise FileNotFoundError(concrete_path)
    return normalized


def write_zip_from_directory(source_root: Path, zip_path: Path) -> None:
    """Write a deterministic ZIP file preserving the root directory name."""

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in sorted(path for path in source_root.rglob("*") if path.is_file()):
            archive_name = Path(source_root.name) / file_path.relative_to(source_root)
            zip_file.write(file_path, archive_name.as_posix())
