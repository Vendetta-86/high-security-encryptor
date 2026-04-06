"""Non-UI batch encryption workflow.

This module is the first orchestration layer that turns the lower-level
streaming encryption primitives and metadata artifact helpers into a usable
batch process. It now supports both plain files and folders:

- plain files become standalone `.hse` outputs
- folders become `.zip.hse` outputs
- selected inner folder files may be converted into independent `.hse` members
  before packaging, with encrypted sidecars embedded inside the package so
  later tooling can validate and import their password metadata
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .api import encrypt_file_streaming
from .batch_artifacts import (
    load_manifest_artifact,
    load_password_table_artifact,
    load_template_artifact,
    write_manifest_artifact,
    write_password_table_artifact,
    write_template_artifact,
)
from .batch_binding import BatchBinding
from .batch_payloads import PasswordRecord
from .folder_workflow import FolderPackageResult, get_folder_package_target_path, package_folder_to_encrypted_archive


@dataclass(frozen=True)
class BatchEncryptionResult:
    """Summarize all files produced by one batch encryption run."""

    encrypted_files: list[Path]
    folder_packages: list[FolderPackageResult]
    manifest_path: Path
    password_table_path: Path
    template_path: Path
    binding: BatchBinding


def get_encrypted_target_path(source: str | Path, output_dir: str | Path | None = None) -> Path:
    """Compute the output path for one encrypted file."""

    source_path = Path(source)
    base_dir = Path(output_dir) if output_dir is not None else source_path.parent
    return base_dir / f"{source_path.name}.hse"


def encrypt_batch_files(
    sources: list[str | Path],
    passwords_by_source: dict[str | Path, str],
    metadata_password: str,
    output_dir: str | Path | None = None,
    batch_id: str | None = None,
    individually_encrypted_files_by_folder: dict[str | Path, list[str]] | None = None,
) -> BatchEncryptionResult:
    """Encrypt a batch of files and folders and emit bound metadata artifacts.

    Each top-level source uses its own encryption password, while metadata
    artifacts are protected by a separate metadata password. Folder sources may
    optionally list inner relative file paths that should be independently
    encrypted before the folder is zipped and wrapped in the outer `.hse`
    container. Inner folder passwords are resolved from `passwords_by_source`
    using tuple keys of the form `(folder_source, "relative/path.txt")`.
    """

    if not sources:
        raise ValueError("at least one source is required")
    if not metadata_password:
        raise ValueError("metadata_password is required")

    normalized_sources = [Path(source) for source in sources]
    destination_dir = Path(output_dir) if output_dir is not None else normalized_sources[0].parent
    destination_dir.mkdir(parents=True, exist_ok=True)
    normalized_folder_selection = _normalize_folder_selection_mapping(individually_encrypted_files_by_folder or {})

    encrypted_files: list[Path] = []
    folder_packages: list[FolderPackageResult] = []
    encrypted_names: list[str] = []
    password_records: list[PasswordRecord] = []
    source_names: list[str] = []

    for source_path in normalized_sources:
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        file_password = _resolve_top_level_password(passwords_by_source, source_path)
        if source_path.is_dir():
            individually_encrypted_relative_paths = normalized_folder_selection.get(str(source_path), [])
            inner_passwords = _resolve_inner_passwords(
                passwords_by_source,
                source_path,
                individually_encrypted_relative_paths,
            )
            target_path = get_folder_package_target_path(source_path, destination_dir)
            folder_package = package_folder_to_encrypted_archive(
                source_path,
                target_path,
                folder_password=file_password,
                metadata_password=metadata_password,
                individually_encrypted_relative_paths=individually_encrypted_relative_paths,
                inner_passwords_by_relative_path=inner_passwords,
            )
            folder_packages.append(folder_package)
        elif source_path.is_file():
            target_path = get_encrypted_target_path(source_path, destination_dir)
            encrypt_file_streaming(source_path, target_path, file_password)
        else:
            raise FileNotFoundError(source_path)

        encrypted_files.append(target_path)
        encrypted_names.append(target_path.name)
        source_names.append(source_path.name)
        password_records.append(
            PasswordRecord(
                source_name=source_path.name,
                encrypted_name=target_path.name,
                password=file_password,
            )
        )

    manifest_path = destination_dir / "batch_manifest.hsm"
    password_table_path = destination_dir / "batch_password_table.hsm"
    template_path = destination_dir / "batch_template.hsm"

    binding = write_manifest_artifact(
        manifest_path,
        encrypted_names,
        mode="mixed_batch",
        password=metadata_password,
        batch_id=batch_id,
    )
    write_password_table_artifact(
        password_table_path,
        password_records,
        encrypted_names,
        password=metadata_password,
        batch_id=binding.batch_id,
    )
    write_template_artifact(
        template_path,
        source_names,
        encrypted_names,
        password=metadata_password,
        batch_id=binding.batch_id,
    )

    return BatchEncryptionResult(
        encrypted_files=encrypted_files,
        folder_packages=folder_packages,
        manifest_path=manifest_path,
        password_table_path=password_table_path,
        template_path=template_path,
        binding=binding,
    )


def load_batch_sidecars(result: BatchEncryptionResult, metadata_password: str) -> dict[str, dict]:
    """Load and validate the manifest, password table, and template for one batch."""

    return {
        "manifest": load_manifest_artifact(result.manifest_path, metadata_password, result.binding),
        "password_table": load_password_table_artifact(result.password_table_path, metadata_password, result.binding),
        "template": load_template_artifact(result.template_path, metadata_password, result.binding),
    }


def _normalize_folder_selection_mapping(
    individually_encrypted_files_by_folder: dict[str | Path, list[str]],
) -> dict[str, list[str]]:
    """Normalize the folder-selection mapping so folder lookup is stable.

    The public workflow accepts both `Path` and `str` keys. Internally the
    folder path is normalized to `str(Path(...))` so later resolution can use
    the same comparison regardless of which key type the caller used.
    """

    return {str(Path(folder)): list(relative_paths) for folder, relative_paths in individually_encrypted_files_by_folder.items()}


def _resolve_top_level_password(passwords_by_source: dict, source_path: Path) -> str:
    """Resolve the outer password for one top-level source path."""

    try:
        return passwords_by_source[source_path]
    except KeyError:
        try:
            return passwords_by_source[str(source_path)]
        except KeyError as exc:
            raise KeyError(f"missing password for source: {source_path}") from exc


def _resolve_inner_passwords(
    passwords_by_source: dict,
    source_path: Path,
    individually_encrypted_relative_paths: list[str],
) -> dict[str, str]:
    """Resolve passwords for folder members selected for independent encryption.

    The supported key formats deliberately stay simple and explicit:

    - `(Path(folder_source), "relative/path.txt")`
    - `(str(folder_source), "relative/path.txt")`
    - `"{folder_source}::relative/path.txt"`

    This keeps the API easy to express from tests and future UI code while
    still making the folder/source relationship unambiguous.
    """

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
