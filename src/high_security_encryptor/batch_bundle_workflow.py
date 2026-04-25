"""Easy multi-source bundle encryption workflow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import shutil

from .batch_artifacts import write_manifest_artifact, write_password_table_artifact, write_template_artifact
from .batch_payloads import PasswordRecord
from .batch_workflow_inputs import (
    normalize_folder_selection_mapping,
    resolve_inner_passwords,
    resolve_top_level_password,
)
from .folder_package_utils import normalize_relative_path_list
from .folder_workflow import FolderPackageResult, package_folder_to_encrypted_archive
from .secure_temp import secure_temporary_directory


@dataclass(frozen=True)
class BatchBundleEncryptionResult:
    """Outputs from encrypting multiple sources into one encrypted bundle."""

    bundle_path: Path
    folder_package: FolderPackageResult
    manifest_path: Path | None
    password_table_path: Path | None
    template_path: Path | None


def get_batch_bundle_target_path(
    sources: list[str | Path],
    output_dir: str | Path | None = None,
    bundle_name: str = "multi_file_bundle",
) -> Path:
    """Return the default encrypted bundle output path."""

    if not sources:
        raise ValueError("at least one source is required")
    base_dir = Path(output_dir) if output_dir is not None else Path(sources[0]).parent
    return base_dir / f"{bundle_name}.zip.hse"


def encrypt_batch_bundle(
    sources: list[str | Path],
    passwords_by_source: dict[str | Path, str],
    main_password: str,
    output_dir: str | Path | None = None,
    bundle_path: str | Path | None = None,
    bundle_name: str = "multi_file_bundle",
    metadata_password: str | None = None,
    individually_encrypted_files_by_folder: dict[str | Path, list[str]] | None = None,
    write_password_table: bool = True,
    write_internal_password_tables: bool = True,
    manifest_path: str | Path | None = None,
    password_table_path: str | Path | None = None,
    template_path: str | Path | None = None,
) -> BatchBundleEncryptionResult:
    """Encrypt several files/folders into one outer encrypted folder package."""

    if not sources:
        raise ValueError("at least one source is required")
    if not main_password:
        raise ValueError("main_password is required")

    normalized_sources = [Path(source) for source in sources]
    destination_dir = Path(output_dir) if output_dir is not None else normalized_sources[0].parent
    destination_dir.mkdir(parents=True, exist_ok=True)
    target_bundle_path = Path(bundle_path) if bundle_path is not None else get_batch_bundle_target_path(
        normalized_sources,
        destination_dir,
        bundle_name,
    )
    target_bundle_path.parent.mkdir(parents=True, exist_ok=True)

    effective_metadata_password = metadata_password or main_password
    normalized_folder_selection = normalize_folder_selection_mapping(individually_encrypted_files_by_folder or {})

    with secure_temporary_directory(prefix="hse-bundle-") as temp_root:
        staging_root = temp_root / bundle_name
        staging_root.mkdir(parents=True)

        relative_passwords: dict[str, str] = {}
        source_names: list[str] = []
        encrypted_names: list[str] = []
        records: list[PasswordRecord] = []

        for index, source_path in enumerate(normalized_sources, start=1):
            if not source_path.exists():
                raise FileNotFoundError(source_path)

            staged_name = f"{index:03d}_{source_path.name}"
            staged_source = staging_root / staged_name
            top_level_password = resolve_top_level_password(passwords_by_source, source_path)

            if source_path.is_dir():
                shutil.copytree(source_path, staged_source)
                selected_relative_paths = normalize_relative_path_list(
                    source_path,
                    normalized_folder_selection.get(str(source_path), []),
                )
                selected_inner_passwords = resolve_inner_passwords(
                    passwords_by_source,
                    source_path,
                    selected_relative_paths,
                )
                for staged_file in sorted(path for path in staged_source.rglob("*") if path.is_file()):
                    original_relative_path = staged_file.relative_to(staged_source).as_posix()
                    bundle_relative_path = (PurePosixPath(staged_name) / original_relative_path).as_posix()
                    file_password = selected_inner_passwords.get(original_relative_path, top_level_password)
                    _append_bundle_record(
                        bundle_relative_path,
                        file_password,
                        relative_passwords,
                        source_names,
                        encrypted_names,
                        records,
                    )
            elif source_path.is_file():
                shutil.copy2(source_path, staged_source)
                _append_bundle_record(
                    staged_name,
                    top_level_password,
                    relative_passwords,
                    source_names,
                    encrypted_names,
                    records,
                )
            else:
                raise FileNotFoundError(source_path)

        folder_package = package_folder_to_encrypted_archive(
            staging_root,
            target_bundle_path,
            folder_password=main_password,
            metadata_password=effective_metadata_password,
            individually_encrypted_relative_paths=list(relative_passwords),
            inner_passwords_by_relative_path=relative_passwords,
            write_internal_password_table=write_internal_password_tables,
        )

    external_manifest_path = _write_external_manifest(
        manifest_path,
        encrypted_names,
        effective_metadata_password,
        folder_package,
    )
    external_password_table_path = _write_external_password_table(
        password_table_path,
        records,
        encrypted_names,
        effective_metadata_password,
        target_bundle_path,
        folder_package,
        write_password_table,
    )
    external_template_path = _write_external_template(
        template_path,
        source_names,
        encrypted_names,
        effective_metadata_password,
        folder_package,
    )

    return BatchBundleEncryptionResult(
        bundle_path=target_bundle_path,
        folder_package=folder_package,
        manifest_path=external_manifest_path,
        password_table_path=external_password_table_path,
        template_path=external_template_path,
    )


def _append_bundle_record(
    relative_path: str,
    password: str,
    relative_passwords: dict[str, str],
    source_names: list[str],
    encrypted_names: list[str],
    records: list[PasswordRecord],
) -> None:
    encrypted_name = _encrypted_relative_name(relative_path)
    relative_passwords[relative_path] = password
    source_names.append(relative_path)
    encrypted_names.append(encrypted_name)
    records.append(
        PasswordRecord(
            source_name=relative_path,
            encrypted_name=encrypted_name,
            password=password,
        )
    )


def _encrypted_relative_name(relative_path: str) -> str:
    pure_path = PurePosixPath(relative_path)
    return (pure_path.parent / f"{pure_path.name}.hse").as_posix()


def _write_external_manifest(
    manifest_path: str | Path | None,
    encrypted_names: list[str],
    metadata_password: str,
    folder_package: FolderPackageResult,
) -> Path | None:
    if manifest_path is None or folder_package.internal_binding is None:
        return None
    target = Path(manifest_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    write_manifest_artifact(
        target,
        encrypted_names,
        mode="bundle_inner_batch",
        password=metadata_password,
        batch_id=folder_package.internal_binding.batch_id,
    )
    return target


def _write_external_password_table(
    password_table_path: str | Path | None,
    records: list[PasswordRecord],
    encrypted_names: list[str],
    metadata_password: str,
    bundle_path: Path,
    folder_package: FolderPackageResult,
    write_password_table: bool,
) -> Path | None:
    if not write_password_table or folder_package.internal_binding is None:
        return None
    target = Path(password_table_path) if password_table_path is not None else bundle_path.parent / "batch_password_table.hsm"
    target.parent.mkdir(parents=True, exist_ok=True)
    write_password_table_artifact(
        target,
        records,
        encrypted_names,
        password=metadata_password,
        batch_id=folder_package.internal_binding.batch_id,
    )
    return target


def _write_external_template(
    template_path: str | Path | None,
    source_names: list[str],
    encrypted_names: list[str],
    metadata_password: str,
    folder_package: FolderPackageResult,
) -> Path | None:
    if template_path is None or folder_package.internal_binding is None:
        return None
    target = Path(template_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    write_template_artifact(
        target,
        source_names,
        encrypted_names,
        password=metadata_password,
        batch_id=folder_package.internal_binding.batch_id,
    )
    return target
