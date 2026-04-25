"""文件夹打包辅助逻辑。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .api import encrypt_file_streaming
from .batch_artifacts import (
    write_manifest_artifact,
    write_password_table_artifact,
    write_template_artifact,
)
from .batch_binding import BatchBinding
from .batch_payloads import PasswordRecord
from .folder_package_utils import (
    normalize_inner_password_mapping,
    normalize_relative_path_list,
    normalize_safe_relative_member_path,
    write_zip_file_entries,
)
from .secure_temp import secure_temporary_directory
from .streaming_format import encrypted_output_stream


INTERNAL_SIDECAR_DIRNAME = "_hse_sidecars"


@dataclass(frozen=True)
class FolderPackageResult:
    """描述一个加密文件夹打包过程产生的输出。"""

    source_folder: Path
    package_path: Path
    internal_encrypted_files: list[str]
    internal_binding: BatchBinding | None
    internal_manifest_relative_path: str | None
    internal_password_table_relative_path: str | None
    internal_template_relative_path: str | None


def get_folder_package_target_path(source_folder: str | Path, output_dir: str | Path | None = None) -> Path:
    """计算单个加密文件夹包的最终输出路径。"""

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
    write_internal_password_table: bool = True,
) -> FolderPackageResult:
    """把一个文件夹打包成加密归档。"""

    source_path = Path(source_folder)
    destination_path = Path(target_path)
    if not folder_password:
        raise ValueError("folder_password is required")
    if not metadata_password:
        raise ValueError("metadata_password is required")
    if not source_path.is_dir():
        raise FileNotFoundError(source_path)

    normalized_relative_paths = normalize_relative_path_list(
        source_path,
        individually_encrypted_relative_paths or [],
    )
    normalized_inner_passwords = normalize_inner_password_mapping(inner_passwords_by_relative_path or {})

    destination_path.parent.mkdir(parents=True, exist_ok=True)

    root_name = normalize_safe_relative_member_path(source_path.name, "folder root name")
    _reject_reserved_sidecar_directory(source_path)
    with secure_temporary_directory(prefix="hse-folder-encrypt-") as temp_root:
        internal_records: list[PasswordRecord] = []
        internal_source_names: list[str] = []
        internal_encrypted_names: list[str] = []
        internal_encrypted_paths: dict[str, Path] = {}

        for relative_path in normalized_relative_paths:
            source_plain_path = source_path / Path(relative_path)
            if not source_plain_path.is_file():
                raise FileNotFoundError(source_plain_path)
            try:
                inner_password = normalized_inner_passwords[relative_path]
            except KeyError as exc:
                raise KeyError(f"missing inner password for folder entry: {relative_path}") from exc

            encrypted_name = _encrypted_relative_name(relative_path)
            staged_encrypted_path = temp_root / "inner" / Path(encrypted_name)
            staged_encrypted_path.parent.mkdir(parents=True, exist_ok=True)
            encrypt_file_streaming(source_plain_path, staged_encrypted_path, inner_password)
            internal_encrypted_paths[encrypted_name] = staged_encrypted_path
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
            sidecar_root = temp_root / INTERNAL_SIDECAR_DIRNAME
            sidecar_root.mkdir(parents=True, exist_ok=True)

            manifest_path = sidecar_root / "batch_manifest.hsm"
            template_path = sidecar_root / "batch_template.hsm"
            password_table_path = sidecar_root / "batch_password_table.hsm"

            internal_binding = write_manifest_artifact(
                manifest_path,
                internal_encrypted_names,
                mode="folder_internal_selection",
                password=metadata_password,
            )
            if write_internal_password_table:
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

            manifest_relative_path = (PurePosixPath(INTERNAL_SIDECAR_DIRNAME) / manifest_path.name).as_posix()
            password_table_relative_path = (
                (PurePosixPath(INTERNAL_SIDECAR_DIRNAME) / password_table_path.name).as_posix()
                if write_internal_password_table
                else None
            )
            template_relative_path = (PurePosixPath(INTERNAL_SIDECAR_DIRNAME) / template_path.name).as_posix()

        with encrypted_output_stream(destination_path, folder_password) as encrypted_zip_stream:
            write_zip_file_entries(
                _iter_folder_zip_entries(
                    source_path=source_path,
                    root_name=root_name,
                    selected_relative_paths=set(normalized_relative_paths),
                    internal_encrypted_paths=internal_encrypted_paths,
                    sidecar_root=temp_root / INTERNAL_SIDECAR_DIRNAME,
                ),
                encrypted_zip_stream,
            )

    return FolderPackageResult(
        source_folder=source_path,
        package_path=destination_path,
        internal_encrypted_files=internal_encrypted_names,
        internal_binding=internal_binding,
        internal_manifest_relative_path=manifest_relative_path,
        internal_password_table_relative_path=password_table_relative_path,
        internal_template_relative_path=template_relative_path,
    )


def _encrypted_relative_name(relative_path: str) -> str:
    pure_path = PurePosixPath(relative_path)
    return (pure_path.parent / f"{pure_path.name}.hse").as_posix()


def _iter_folder_zip_entries(
    *,
    source_path: Path,
    root_name: str,
    selected_relative_paths: set[str],
    internal_encrypted_paths: dict[str, Path],
    sidecar_root: Path,
) -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    root = PurePosixPath(root_name)
    for file_path in sorted(path for path in source_path.rglob("*") if path.is_file()):
        relative_path = file_path.relative_to(source_path).as_posix()
        if relative_path in selected_relative_paths:
            continue
        entries.append((file_path, (root / relative_path).as_posix()))
    for encrypted_name, encrypted_path in internal_encrypted_paths.items():
        entries.append((encrypted_path, (root / encrypted_name).as_posix()))
    if sidecar_root.exists():
        for sidecar_path in sorted(path for path in sidecar_root.rglob("*") if path.is_file()):
            relative_path = sidecar_path.relative_to(sidecar_root).as_posix()
            entries.append((sidecar_path, (root / INTERNAL_SIDECAR_DIRNAME / relative_path).as_posix()))
    return entries


def _reject_reserved_sidecar_directory(source_path: Path) -> None:
    reserved_path = source_path / INTERNAL_SIDECAR_DIRNAME
    if reserved_path.exists():
        raise ValueError(f"source folder contains reserved sidecar directory: {reserved_path}")
