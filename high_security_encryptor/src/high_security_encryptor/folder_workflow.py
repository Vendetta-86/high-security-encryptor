"""Folder packaging helpers for the hardened batch workflow.

This module handles the folder-specific mechanics that do not belong inside the
generic batch orchestration layer:

- copying a source folder into an isolated staging area
- optionally converting selected inner files into independently encrypted
  `.hse` files before packaging
- emitting encrypted sidecars inside the package so later import and password
  resolution can still validate batch binding for those inner encrypted files
- building a temporary zip archive and immediately wrapping it in the outer
  streaming encryption container, so no persistent plaintext archive is left in
  the caller's output directory
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import zipfile

from .api import encrypt_file_streaming
from .batch_artifacts import (
    write_manifest_artifact,
    write_password_table_artifact,
    write_template_artifact,
)
from .batch_binding import BatchBinding
from .batch_payloads import PasswordRecord


INTERNAL_SIDECAR_DIRNAME = "_hse_sidecars"


@dataclass(frozen=True)
class FolderPackageResult:
    """Describe the outputs created while packaging one encrypted folder.

    `package_path` is the final outer encrypted archive. The inner sidecar paths
    are stored as relative package paths because the actual files only exist
    transiently inside the zip until a caller decrypts and extracts it.
    """

    source_folder: Path
    package_path: Path
    internal_encrypted_files: list[str]
    internal_binding: BatchBinding | None
    internal_manifest_relative_path: str | None
    internal_password_table_relative_path: str | None
    internal_template_relative_path: str | None


def get_folder_package_target_path(source_folder: str | Path, output_dir: str | Path | None = None) -> Path:
    """Compute the final target path for one encrypted folder package."""

    source_path = Path(source_folder)
    base_dir = Path(output_dir) if output_dir is not None else source_path.parent
    return base_dir / f"{source_path.name}.zip.hse"


def package_folder_to_encrypted_archive(
    source_folder: str | Path,
    target_path: str | Path,
    folder_password: str,
    metadata_password: str,
    individually_encrypted_relative_paths: list[str] | None = None,
    inner_passwords_by_relative_path: dict[str, str] | None = None,
) -> FolderPackageResult:
    """Package one folder into an encrypted archive.

    The function stages the whole folder tree in a temporary directory. Files
    listed in `individually_encrypted_relative_paths` are replaced in that
    staging tree by independently encrypted `.hse` files before the folder is
    zipped. If any such inner encrypted files exist, encrypted sidecars are
    written into the package so later tooling can validate and import the inner
    password table and template against a dedicated binding.
    """

    source_path = Path(source_folder)
    destination_path = Path(target_path)
    if not folder_password:
        raise ValueError("folder_password is required")
    if not metadata_password:
        raise ValueError("metadata_password is required")
    if not source_path.is_dir():
        raise FileNotFoundError(source_path)

    normalized_relative_paths = _normalize_relative_path_list(
        source_path,
        individually_encrypted_relative_paths or [],
    )
    normalized_inner_passwords = _normalize_inner_password_mapping(inner_passwords_by_relative_path or {})

    destination_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        staged_folder_root = temp_root / source_path.name
        shutil.copytree(source_path, staged_folder_root)

        internal_records: list[PasswordRecord] = []
        internal_source_names: list[str] = []
        internal_encrypted_names: list[str] = []

        for relative_path in normalized_relative_paths:
            staged_plain_path = staged_folder_root / Path(relative_path)
            if not staged_plain_path.is_file():
                raise FileNotFoundError(staged_plain_path)
            try:
                inner_password = normalized_inner_passwords[relative_path]
            except KeyError as exc:
                raise KeyError(f"missing inner password for folder entry: {relative_path}") from exc

            staged_encrypted_path = staged_plain_path.with_name(f"{staged_plain_path.name}.hse")
            encrypt_file_streaming(staged_plain_path, staged_encrypted_path, inner_password)
            staged_plain_path.unlink()

            encrypted_name = staged_encrypted_path.relative_to(staged_folder_root).as_posix()
            internal_source_names.append(relative_path)
            internal_encrypted_names.append(encrypted_name)
            internal_records.append(
                PasswordRecord(
                    source_name=relative_path,
                    encrypted_name=encrypted_name,
                    password=inner_password,
                )
            )

        internal_binding: BatchBinding | None = None
        manifest_relative_path: str | None = None
        password_table_relative_path: str | None = None
        template_relative_path: str | None = None

        if internal_records:
            sidecar_root = staged_folder_root / INTERNAL_SIDECAR_DIRNAME
            sidecar_root.mkdir(parents=True, exist_ok=True)

            manifest_path = sidecar_root / "batch_manifest.hsm"
            password_table_path = sidecar_root / "batch_password_table.hsm"
            template_path = sidecar_root / "batch_template.hsm"

            internal_binding = write_manifest_artifact(
                manifest_path,
                internal_encrypted_names,
                mode="folder_internal_selection",
                password=metadata_password,
            )
            write_password_table_artifact(
                password_table_path,
                internal_records,
                internal_encrypted_names,
                password=metadata_password,
                batch_id=internal_binding.batch_id,
            )
            write_template_artifact(
                template_path,
                internal_source_names,
                internal_encrypted_names,
                password=metadata_password,
                batch_id=internal_binding.batch_id,
            )

            manifest_relative_path = manifest_path.relative_to(staged_folder_root).as_posix()
            password_table_relative_path = password_table_path.relative_to(staged_folder_root).as_posix()
            template_relative_path = template_path.relative_to(staged_folder_root).as_posix()

        plaintext_zip_path = temp_root / f"{source_path.name}.zip"
        _write_zip_from_directory(staged_folder_root, plaintext_zip_path)
        encrypt_file_streaming(plaintext_zip_path, destination_path, folder_password)

    return FolderPackageResult(
        source_folder=source_path,
        package_path=destination_path,
        internal_encrypted_files=internal_encrypted_names,
        internal_binding=internal_binding,
        internal_manifest_relative_path=manifest_relative_path,
        internal_password_table_relative_path=password_table_relative_path,
        internal_template_relative_path=template_relative_path,
    )


def _normalize_relative_path_list(source_folder: Path, relative_paths: list[str]) -> list[str]:
    """Validate and normalize caller-provided folder-relative file paths.

    The workflow stores relative paths in package metadata, so the normalized
    representation must be stable and platform-neutral. Posix separators are
    used even on Windows to keep manifests deterministic.
    """

    normalized: list[str] = []
    seen: set[str] = set()
    for raw_relative_path in relative_paths:
        posix_relative_path = _normalize_relative_path(source_folder, raw_relative_path)
        if posix_relative_path not in seen:
            seen.add(posix_relative_path)
            normalized.append(posix_relative_path)
    return sorted(normalized)


def _normalize_inner_password_mapping(passwords_by_relative_path: dict[str, str]) -> dict[str, str]:
    """Normalize the mapping used for individually encrypted folder entries."""

    normalized: dict[str, str] = {}
    for raw_relative_path, password in passwords_by_relative_path.items():
        posix_relative_path = PurePosixPath(str(raw_relative_path).replace("\\", "/")).as_posix()
        normalized[posix_relative_path] = password
    return normalized


def _normalize_relative_path(source_folder: Path, raw_relative_path: str) -> str:
    """Convert one user-supplied relative path into a safe normalized form."""

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


def _write_zip_from_directory(source_root: Path, zip_path: Path) -> None:
    """Write a deterministic folder zip that retains the folder's root name."""

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in sorted(path for path in source_root.rglob("*") if path.is_file()):
            archive_name = Path(source_root.name) / file_path.relative_to(source_root)
            zip_file.write(file_path, archive_name.as_posix())
