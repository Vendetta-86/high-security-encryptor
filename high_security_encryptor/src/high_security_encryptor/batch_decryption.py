"""无界面的混合批量解密工作流。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .api import decrypt_file_streaming
from .batch_artifacts import (
    load_manifest_artifact,
    load_password_table_artifact,
    load_template_artifact,
)
from .batch_binding import BatchBinding
from .folder_decryption import FolderDecryptionResult, decrypt_folder_archive
from .integrity import EntrySetComparison, validate_entry_sets_match
from .runtime_password_plan import RuntimePasswordPlan, resolve_password_plan_from_template
from .password_sources import PasswordResolver


@dataclass(frozen=True)
class DecryptedTopLevelFile:
    """描述一个从批次中解出的顶层普通文件。"""

    encrypted_path: Path
    decrypted_path: Path


@dataclass(frozen=True)
class BatchDecryptionResult:
    """描述一次顶层批量解密产生的输出。"""

    binding: BatchBinding
    manifest_payload: dict
    password_table_payload: dict
    template_payload: dict
    top_level_entry_comparison: EntrySetComparison
    decrypted_files: list[DecryptedTopLevelFile]
    decrypted_folder_packages: list[FolderDecryptionResult]


def decrypt_batch_files(
    encrypted_files: list[str | Path],
    manifest_path: str | Path,
    password_table_path: str | Path | None,
    template_path: str | Path,
    metadata_password: str,
    output_dir: str | Path,
    passwords_by_encrypted_name: dict[str, str] | None = None,
    runtime_password_plan: RuntimePasswordPlan | None = None,
    password_resolver: PasswordResolver | None = None,
    auto_decrypt_folder_inner_files: bool = True,
    folder_inner_password_overrides: dict[str, dict[str, str]] | None = None,
    folder_internal_runtime_password_plans: dict[str, RuntimePasswordPlan] | None = None,
) -> BatchDecryptionResult:
    """解密一个包含普通文件和文件夹包的混合批次。"""

    normalized_encrypted_files = [Path(path) for path in encrypted_files]
    destination_dir = Path(output_dir)
    if not normalized_encrypted_files:
        raise ValueError("at least one encrypted file is required")
    if not metadata_password:
        raise ValueError("metadata_password is required")

    destination_dir.mkdir(parents=True, exist_ok=True)

    discovered_binding = _discover_binding(manifest_path, metadata_password)
    manifest_payload = load_manifest_artifact(manifest_path, metadata_password, discovered_binding)
    template_payload = load_template_artifact(template_path, metadata_password, discovered_binding)
    if password_table_path is not None:
        password_table_payload = load_password_table_artifact(
            password_table_path,
            metadata_password,
            discovered_binding,
        )
    else:
        password_table_payload = {
            "kind": "password_table",
            "records": [],
            "binding": discovered_binding.as_dict(),
        }
    top_level_entry_comparison = validate_entry_sets_match(
        expected_entries=_extract_manifest_entries(manifest_payload),
        actual_entries=[path.name for path in normalized_encrypted_files],
        context="top-level batch",
    )

    top_level_passwords = _build_top_level_password_mapping(password_table_payload, passwords_by_encrypted_name or {})
    if runtime_password_plan is not None:
        if password_resolver is None:
            raise ValueError("password_resolver is required when runtime_password_plan is used")
        top_level_passwords.update(
            resolve_password_plan_from_template(
                template_payload=template_payload,
                resolver=password_resolver,
                plan=runtime_password_plan,
            )
        )
    folder_overrides = {str(name): dict(value) for name, value in (folder_inner_password_overrides or {}).items()}
    folder_runtime_plans = dict(folder_internal_runtime_password_plans or {})

    decrypted_files: list[DecryptedTopLevelFile] = []
    decrypted_folder_packages: list[FolderDecryptionResult] = []

    for encrypted_path in normalized_encrypted_files:
        if not encrypted_path.is_file():
            raise FileNotFoundError(encrypted_path)
        encrypted_name = encrypted_path.name
        try:
            password = top_level_passwords[encrypted_name]
        except KeyError as exc:
            raise KeyError(f"missing password for encrypted file: {encrypted_name}") from exc

        if encrypted_name.endswith(".zip.hse"):
            folder_output_dir = destination_dir / encrypted_path.stem[:-4]
            folder_result = decrypt_folder_archive(
                encrypted_path,
                folder_output_dir,
                folder_password=password,
                metadata_password=metadata_password,
                auto_decrypt_inner_files=auto_decrypt_folder_inner_files,
                internal_runtime_password_plan=folder_runtime_plans.get(encrypted_name),
                password_resolver=password_resolver,
                inner_password_overrides=folder_overrides.get(encrypted_name, {}),
            )
            decrypted_folder_packages.append(folder_result)
        else:
            decrypted_path = destination_dir / _derive_plain_file_output_name(encrypted_name)
            decrypt_file_streaming(encrypted_path, decrypted_path, password)
            decrypted_files.append(
                DecryptedTopLevelFile(
                    encrypted_path=encrypted_path,
                    decrypted_path=decrypted_path,
                )
            )

    return BatchDecryptionResult(
        binding=discovered_binding,
        manifest_payload=manifest_payload,
        password_table_payload=password_table_payload,
        template_payload=template_payload,
        top_level_entry_comparison=top_level_entry_comparison,
        decrypted_files=decrypted_files,
        decrypted_folder_packages=decrypted_folder_packages,
    )


def _discover_binding(manifest_path: str | Path, metadata_password: str) -> BatchBinding:
    """先读取 manifest，以获得该批次的权威绑定信息。"""

    from .batch_payloads import deserialize_manifest_payload
    from .batch_binding import extract_binding
    from .metadata_crypto import read_encrypted_metadata_file

    manifest_payload = deserialize_manifest_payload(read_encrypted_metadata_file(manifest_path, metadata_password))
    return extract_binding(manifest_payload)


def _build_top_level_password_mapping(
    password_table_payload: dict,
    password_overrides: dict[str, str],
) -> dict[str, str]:
    """构建顶层输出使用的密码映射。"""

    mapping = {
        str(record["encrypted_name"]): str(record["password"])
        for record in password_table_payload.get("records", [])
    }
    mapping.update({str(name): password for name, password in password_overrides.items()})
    return mapping


def _derive_plain_file_output_name(encrypted_name: str) -> str:
    """推导普通 `.hse` 输出对应的明文文件名。"""

    if not encrypted_name.endswith(".hse"):
        raise ValueError(f"expected .hse file name, got: {encrypted_name}")
    return encrypted_name[:-4]


def _extract_manifest_entries(manifest_payload: dict) -> list[str]:
    """从 manifest 载荷中提取加密条目名称。"""

    return [str(entry["encrypted_name"]) for entry in manifest_payload.get("entries", [])]
