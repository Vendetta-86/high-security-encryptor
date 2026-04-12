"""Input normalization helpers for batch encryption workflows."""

from __future__ import annotations

from pathlib import Path


def get_encrypted_target_path(source: str | Path, output_dir: str | Path | None = None) -> Path:
    """Calculate the encrypted output path for one top-level file."""

    source_path = Path(source)
    base_dir = Path(output_dir) if output_dir is not None else source_path.parent
    return base_dir / f"{source_path.name}.hse"


def normalize_folder_selection_mapping(
    individually_encrypted_files_by_folder: dict[str | Path, list[str]],
) -> dict[str, list[str]]:
    """Normalize folder selection keys for stable lookup during encryption."""

    return {str(Path(folder)): list(relative_paths) for folder, relative_paths in individually_encrypted_files_by_folder.items()}


def resolve_top_level_password(passwords_by_source: dict, source_path: Path) -> str:
    """Resolve the outer password for one top-level source."""

    try:
        return passwords_by_source[source_path]
    except KeyError:
        try:
            return passwords_by_source[str(source_path)]
        except KeyError as exc:
            raise KeyError(f"missing password for source: {source_path}") from exc


def resolve_inner_passwords(
    passwords_by_source: dict,
    source_path: Path,
    individually_encrypted_relative_paths: list[str],
) -> dict[str, str]:
    """Resolve passwords for folder members marked for independent encryption."""

    inner_passwords: dict[str, str] = {}
    for relative_path in individually_encrypted_relative_paths:
        tuple_key_path = (source_path, relative_path)
        tuple_key_str = (str(source_path), relative_path)
        combined_key = f"{source_path}::{relative_path}"
        if tuple_key_path in passwords_by_source:
            inner_passwords[relative_path] = passwords_by_source[tuple_key_path]
        elif tuple_key_str in passwords_by_source:
            inner_passwords[relative_path] = passwords_by_source[tuple_key_str]
        elif combined_key in passwords_by_source:
            inner_passwords[relative_path] = passwords_by_source[combined_key]
        else:
            raise KeyError(f"missing password for folder entry: {source_path}::{relative_path}")
    return inner_passwords
