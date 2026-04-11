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


def get_encrypted_target_path(source: str | Path, output_dir: str | Path | None = None) -> Path:
    """计算单个加密文件的输出路径。"""

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
    write_password_table: bool = True,
    write_internal_password_tables: bool = True,
) -> BatchEncryptionResult:
    """批量加密文件和文件夹，并生成带绑定关系的元数据副产物。"""

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


def _normalize_folder_selection_mapping(
    individually_encrypted_files_by_folder: dict[str | Path, list[str]],
) -> dict[str, list[str]]:
    """归一化文件夹选择映射，确保后续查找稳定。"""

    return {str(Path(folder)): list(relative_paths) for folder, relative_paths in individually_encrypted_files_by_folder.items()}


def _resolve_top_level_password(passwords_by_source: dict, source_path: Path) -> str:
    """解析一个顶层输入项对应的外层密码。"""

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
    """解析被标记为独立加密的文件夹成员密码。"""

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
