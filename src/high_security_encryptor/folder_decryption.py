"""加密文件夹包的解密工作流。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import zipfile

from .api import decrypt_file_streaming
from .batch_artifacts import load_password_table_artifact
from .batch_binding import BatchBinding, extract_binding
from .batch_payloads import deserialize_manifest_payload, deserialize_template_payload
from .folder_workflow import INTERNAL_SIDECAR_DIRNAME
from .integrity import EntrySetComparison, collect_internal_encrypted_entries, validate_entry_sets_match
from .metadata_crypto import read_encrypted_metadata_file
from .password_sources import PasswordResolver
from .runtime_password_plan import RuntimePasswordPlan, resolve_password_plan_from_template


@dataclass(frozen=True)
class InnerFileDecryptionResult:
    """描述一个在解压后继续解密成功的包内成员。"""

    encrypted_relative_path: str
    decrypted_relative_path: str
    decrypted_path: Path


@dataclass(frozen=True)
class FolderDecryptionResult:
    """描述一个文件夹归档完成解密后的输出结果。"""

    package_path: Path
    extracted_root: Path
    discovered_binding: BatchBinding | None
    internal_manifest_path: Path | None
    internal_password_table_path: Path | None
    internal_template_path: Path | None
    internal_entry_comparison: EntrySetComparison | None
    decrypted_inner_files: list[InnerFileDecryptionResult]


def decrypt_folder_archive(
    package_path: str | Path,
    output_dir: str | Path,
    folder_password: str,
    metadata_password: str | None = None,
    auto_decrypt_inner_files: bool = True,
    internal_runtime_password_plan: RuntimePasswordPlan | None = None,
    password_resolver: PasswordResolver | None = None,
    inner_password_overrides: dict[str, str] | None = None,
) -> FolderDecryptionResult:
    """解密一个外层文件夹包，并可选继续解密包内独立文件。"""

    source_package = Path(package_path)
    destination_dir = Path(output_dir)
    if not folder_password:
        raise ValueError("folder_password is required")
    if not source_package.is_file():
        raise FileNotFoundError(source_package)

    destination_dir.mkdir(parents=True, exist_ok=True)

    extracted_root: Path | None = None
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plaintext_zip_path = temp_root / _derive_plaintext_zip_name(source_package)
            decrypt_file_streaming(source_package, plaintext_zip_path, folder_password)
            extracted_root = safe_extract_folder_archive(plaintext_zip_path, destination_dir)

        manifest_path, password_table_path, template_path = discover_internal_sidecars(extracted_root)
        discovered_binding: BatchBinding | None = None
        internal_entry_comparison: EntrySetComparison | None = None
        decrypted_inner_files: list[InnerFileDecryptionResult] = []

        if manifest_path is not None and metadata_password:
            manifest_payload = deserialize_manifest_payload(read_encrypted_metadata_file(manifest_path, metadata_password))
            discovered_binding = extract_binding(manifest_payload)
            template_payload = deserialize_template_payload(read_encrypted_metadata_file(template_path, metadata_password)) if template_path else None
            internal_entry_comparison = validate_entry_sets_match(
                expected_entries=[str(entry["encrypted_name"]) for entry in manifest_payload.get("entries", [])],
                actual_entries=collect_internal_encrypted_entries(extracted_root, INTERNAL_SIDECAR_DIRNAME),
                context="folder-internal encrypted members",
            )

            if auto_decrypt_inner_files:
                password_table_payload = _load_internal_password_payload(
                    password_table_path=password_table_path,
                    template_payload=template_payload,
                    metadata_password=metadata_password,
                    discovered_binding=discovered_binding,
                    internal_runtime_password_plan=internal_runtime_password_plan,
                    password_resolver=password_resolver,
                )
                decrypted_inner_files = decrypt_inner_hse_members(
                    extracted_root,
                    password_table_payload,
                    inner_password_overrides=inner_password_overrides or {},
                )

        return FolderDecryptionResult(
            package_path=source_package,
            extracted_root=extracted_root,
            discovered_binding=discovered_binding,
            internal_manifest_path=manifest_path,
            internal_password_table_path=password_table_path,
            internal_template_path=template_path,
            internal_entry_comparison=internal_entry_comparison,
            decrypted_inner_files=decrypted_inner_files,
        )
    except Exception:
        if extracted_root is not None and extracted_root.exists():
            shutil.rmtree(extracted_root, ignore_errors=True)
        raise


def safe_extract_folder_archive(zip_path: str | Path, output_dir: str | Path) -> Path:
    """以安全方式解压文件夹 ZIP，阻止路径穿越。"""

    archive_path = Path(zip_path)
    destination_dir = Path(output_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zip_file:
        validated_members, root_name = _validate_zip_members(zip_file.infolist())
        final_root = destination_dir / root_name
        if final_root.exists():
            raise FileExistsError(f"extraction target already exists: {final_root}")

        staging_parent = Path(tempfile.mkdtemp(prefix=f".{root_name}.", dir=destination_dir))
        try:
            for member, normalized_member in validated_members:
                target_path = staging_parent / Path(*PurePosixPath(normalized_member).parts)
                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zip_file.open(member, "r") as source_file, target_path.open("wb") as target_file:
                    shutil.copyfileobj(source_file, target_file)
            staged_root = staging_parent / root_name
            staged_root.replace(final_root)
            return final_root
        finally:
            if staging_parent.exists():
                shutil.rmtree(staging_parent, ignore_errors=True)


def discover_internal_sidecars(extracted_root: str | Path) -> tuple[Path | None, Path | None, Path | None]:
    """在解压目录中发现包内 sidecar 文件。"""

    root_path = Path(extracted_root)
    sidecar_root = root_path / INTERNAL_SIDECAR_DIRNAME
    if not sidecar_root.is_dir():
        return None, None, None
    manifest_path = sidecar_root / "batch_manifest.hsm"
    password_table_path = sidecar_root / "batch_password_table.hsm"
    template_path = sidecar_root / "batch_template.hsm"
    return (
        manifest_path if manifest_path.is_file() else None,
        password_table_path if password_table_path.is_file() else None,
        template_path if template_path.is_file() else None,
    )


def decrypt_inner_hse_members(
    extracted_root: str | Path,
    password_table_payload: dict,
    inner_password_overrides: dict[str, str] | None = None,
) -> list[InnerFileDecryptionResult]:
    """解密受保护密码表中列出的包内 `.hse` 成员。"""

    root_path = Path(extracted_root)
    overrides = {PurePosixPath(path).as_posix(): password for path, password in (inner_password_overrides or {}).items()}
    results: list[InnerFileDecryptionResult] = []

    for record in password_table_payload.get("records", []):
        encrypted_relative_path = PurePosixPath(str(record["encrypted_name"])).as_posix()
        encrypted_path = root_path / Path(*PurePosixPath(encrypted_relative_path).parts)
        decrypted_relative_path = _remove_trailing_hse_suffix(encrypted_relative_path)
        decrypted_path = root_path / Path(*PurePosixPath(decrypted_relative_path).parts)
        password = overrides.get(encrypted_relative_path, str(record["password"]))
        if decrypted_path.exists():
            raise FileExistsError(f"decrypted inner target already exists: {decrypted_relative_path}")
        decrypt_file_streaming(encrypted_path, decrypted_path, password)
        results.append(
            InnerFileDecryptionResult(
                encrypted_relative_path=encrypted_relative_path,
                decrypted_relative_path=decrypted_relative_path,
                decrypted_path=decrypted_path,
            )
        )

    return results


def _load_internal_password_payload(
    password_table_path: Path | None,
    template_payload: dict | None,
    metadata_password: str,
    discovered_binding: BatchBinding,
    internal_runtime_password_plan: RuntimePasswordPlan | None,
    password_resolver: PasswordResolver | None,
) -> dict:
    """加载或构造包内成员解密所需的密码载荷。"""

    if password_table_path is not None:
        return load_password_table_artifact(
            password_table_path,
            metadata_password,
            discovered_binding,
        )
    if template_payload is None:
        raise FileNotFoundError("internal template is missing")
    if internal_runtime_password_plan is None:
        raise FileNotFoundError("internal password table is missing")
    if password_resolver is None:
        raise ValueError("password_resolver is required when internal_runtime_password_plan is used")
    resolved_passwords = resolve_password_plan_from_template(
        template_payload=template_payload,
        resolver=password_resolver,
        plan=internal_runtime_password_plan,
    )
    expected_encrypted_names = [str(row["encrypted_name"]) for row in template_payload.get("rows", [])]
    missing_passwords = [name for name in expected_encrypted_names if name not in resolved_passwords]
    if missing_passwords:
        raise KeyError(
            "missing runtime passwords for internal encrypted members: "
            + ", ".join(sorted(missing_passwords))
        )
    return {
        "kind": "password_table",
        "records": [
            {
                "source_name": str(row["source_name"]),
                "encrypted_name": str(row["encrypted_name"]),
                "password": resolved_passwords[str(row["encrypted_name"])],
            }
            for row in template_payload.get("rows", [])
            if str(row["encrypted_name"]) in resolved_passwords
        ],
        "binding": discovered_binding.as_dict(),
    }


def _derive_plaintext_zip_name(package_path: Path) -> str:
    """根据加密包路径推导临时明文 ZIP 文件名。"""

    if package_path.name.endswith(".zip.hse"):
        return package_path.name[:-4]
    if package_path.name.endswith(".hse"):
        return f"{package_path.stem}.zip"
    return f"{package_path.name}.zip"


def _validate_zip_member(member: zipfile.ZipInfo) -> str:
    """在解压前校验一个 ZIP 成员名称是否合法。"""

    member_name = member.filename.replace("\\", "/")
    pure_path = PurePosixPath(member_name)
    if pure_path.is_absolute():
        raise ValueError(f"zip member must be relative: {member.filename}")
    if any(part in ("", ".", "..") or ":" in part for part in pure_path.parts):
        raise ValueError(f"zip member contains unsafe path segments: {member.filename}")

    unix_mode = member.external_attr >> 16
    file_type_bits = unix_mode & 0o170000
    if file_type_bits == 0o120000:
        raise ValueError(f"zip member must not be a symlink: {member.filename}")
    return pure_path.as_posix()


def _validate_zip_members(members: list[zipfile.ZipInfo]) -> tuple[list[tuple[zipfile.ZipInfo, str]], str]:
    """Validate the complete ZIP member set before writing anything to disk."""

    if not members:
        raise ValueError("archive is empty")

    validated_members: list[tuple[zipfile.ZipInfo, str]] = []
    root_names: set[str] = set()
    seen_names: set[str] = set()
    for member in members:
        normalized_member = _validate_zip_member(member)
        if normalized_member in seen_names:
            raise ValueError(f"zip archive contains duplicate member: {normalized_member}")
        seen_names.add(normalized_member)
        root_names.add(PurePosixPath(normalized_member).parts[0])
        validated_members.append((member, normalized_member))

    if len(root_names) != 1:
        raise ValueError("archive must contain exactly one top-level folder")
    return validated_members, next(iter(root_names))


def _remove_trailing_hse_suffix(relative_path: str) -> str:
    """移除相对路径末尾的 `.hse` 后缀。"""

    pure_path = PurePosixPath(relative_path)
    if pure_path.suffix != ".hse":
        raise ValueError(f"expected .hse member path, got: {relative_path}")
    return str(pure_path.with_suffix(""))
