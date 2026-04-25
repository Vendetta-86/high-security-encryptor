"""无界面的批量加密工作流。"""

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
from .batch_workflow_inputs import (
    get_encrypted_target_path,
    normalize_folder_selection_mapping,
    resolve_inner_passwords,
    resolve_top_level_password,
)
from .folder_workflow import FolderPackageResult, get_folder_package_target_path, package_folder_to_encrypted_archive


@dataclass(frozen=True)
class BatchEncryptionResult:
    """汇总一次批量加密运行产出的所有文件。"""

    encrypted_files: list[Path]
    folder_packages: list[FolderPackageResult]
    manifest_path: Path
    password_table_path: Path | None
    template_path: Path
    binding: BatchBinding


def encrypt_batch_files(
    sources: list[str | Path],
    passwords_by_source: dict[str | Path, str],
    metadata_password: str,
    output_dir: str | Path | None = None,
    batch_id: str | None = None,
    individually_encrypted_files_by_folder: dict[str | Path, list[str]] | None = None,
    write_password_table: bool = True,
    write_internal_password_tables: bool = True,
    manifest_path: str | Path | None = None,
    password_table_path: str | Path | None = None,
    template_path: str | Path | None = None,
) -> BatchEncryptionResult:
    """批量加密文件和文件夹，并生成带绑定关系的元数据副产物。"""

    if not sources:
        raise ValueError("at least one source is required")
    if not metadata_password:
        raise ValueError("metadata_password is required")

    normalized_sources = [Path(source) for source in sources]
    destination_dir = Path(output_dir) if output_dir is not None else normalized_sources[0].parent
    destination_dir.mkdir(parents=True, exist_ok=True)
    normalized_folder_selection = normalize_folder_selection_mapping(individually_encrypted_files_by_folder or {})

    encrypted_files: list[Path] = []
    folder_packages: list[FolderPackageResult] = []
    encrypted_names: list[str] = []
    password_records: list[PasswordRecord] = []
    source_names: list[str] = []

    for source_path in normalized_sources:
        if not source_path.exists():
            raise FileNotFoundError(source_path)
        file_password = resolve_top_level_password(passwords_by_source, source_path)
        if source_path.is_dir():
            individually_encrypted_relative_paths = normalized_folder_selection.get(str(source_path), [])
            inner_passwords = resolve_inner_passwords(
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
                write_internal_password_table=write_internal_password_tables,
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

    manifest_path = Path(manifest_path) if manifest_path is not None else destination_dir / "batch_manifest.hsm"
    password_table_path = (
        Path(password_table_path) if password_table_path is not None else destination_dir / "batch_password_table.hsm"
    )
    template_path = Path(template_path) if template_path is not None else destination_dir / "batch_template.hsm"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    password_table_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.parent.mkdir(parents=True, exist_ok=True)

    binding = write_manifest_artifact(
        manifest_path,
        encrypted_names,
        mode="mixed_batch",
        password=metadata_password,
        batch_id=batch_id,
    )
    if write_password_table:
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
        password_table_path=password_table_path if write_password_table else None,
        template_path=template_path,
        binding=binding,
    )


def load_batch_sidecars(result: BatchEncryptionResult, metadata_password: str) -> dict[str, dict]:
    """加载并校验一个批次对应的 manifest、密码表和模板。"""

    sidecars = {
        "manifest": load_manifest_artifact(result.manifest_path, metadata_password, result.binding),
        "template": load_template_artifact(result.template_path, metadata_password, result.binding),
    }
    if result.password_table_path is not None:
        sidecars["password_table"] = load_password_table_artifact(
            result.password_table_path,
            metadata_password,
            result.binding,
        )
    return sidecars
