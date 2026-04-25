"""Decryption workflow for encrypted folder packages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from .api import decrypt_file_streaming
from .batch_binding import BatchBinding, extract_binding
from .batch_payloads import deserialize_manifest_payload, deserialize_template_payload
from .folder_archive import safe_extract_folder_archive
from .folder_inner_decryption import (
    InnerFileDecryptionResult,
    decrypt_inner_hse_members,
    discover_internal_sidecars,
    load_internal_password_payload,
)
from .folder_workflow import INTERNAL_SIDECAR_DIRNAME
from .integrity import EntrySetComparison, collect_internal_encrypted_entries, validate_entry_sets_match
from .metadata_crypto import read_encrypted_metadata_file
from .password_sources import PasswordResolver
from .runtime_password_plan import RuntimePasswordPlan
from .secure_temp import secure_temporary_directory


@dataclass(frozen=True)
class FolderDecryptionResult:
    """Describes the outputs from one decrypted folder archive."""

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
    """Decrypt one encrypted folder archive and optionally decrypt protected inner members."""

    source_package = Path(package_path)
    destination_dir = Path(output_dir)
    if not folder_password:
        raise ValueError("folder_password is required")
    if not source_package.is_file():
        raise FileNotFoundError(source_package)

    destination_dir.mkdir(parents=True, exist_ok=True)

    extracted_root: Path | None = None
    try:
        with secure_temporary_directory(prefix="hse-folder-decrypt-") as temp_root:
            plaintext_zip_path = temp_root / _derive_plaintext_zip_name(source_package)
            decrypt_file_streaming(source_package, plaintext_zip_path, folder_password)
            extracted_root = safe_extract_folder_archive(plaintext_zip_path, destination_dir)

        manifest_path, password_table_path, template_path = discover_internal_sidecars(extracted_root)
        discovered_binding: BatchBinding | None = None
        internal_entry_comparison: EntrySetComparison | None = None
        decrypted_inner_files: list[InnerFileDecryptionResult] = []

        if manifest_path is not None and metadata_password:
            manifest_payload = deserialize_manifest_payload(
                read_encrypted_metadata_file(manifest_path, metadata_password)
            )
            discovered_binding = extract_binding(manifest_payload)
            template_payload = (
                deserialize_template_payload(read_encrypted_metadata_file(template_path, metadata_password))
                if template_path
                else None
            )
            internal_entry_comparison = validate_entry_sets_match(
                expected_entries=[str(entry["encrypted_name"]) for entry in manifest_payload.get("entries", [])],
                actual_entries=collect_internal_encrypted_entries(extracted_root, INTERNAL_SIDECAR_DIRNAME),
                context="folder-internal encrypted members",
            )

            if auto_decrypt_inner_files:
                password_table_payload = load_internal_password_payload(
                    password_table_path=password_table_path,
                    template_payload=template_payload,
                    metadata_password=metadata_password,
                    discovered_binding=discovered_binding,
                    internal_runtime_password_plan=internal_runtime_password_plan,
                    password_resolver=password_resolver,
                    expected_encrypted_names=[str(entry["encrypted_name"]) for entry in manifest_payload.get("entries", [])],
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


def _derive_plaintext_zip_name(package_path: Path) -> str:
    """Derive the temporary plaintext ZIP name from an encrypted package path."""

    if package_path.name.endswith(".zip.hse"):
        return package_path.name[:-4]
    if package_path.name.endswith(".hse"):
        return f"{package_path.stem}.zip"
    return f"{package_path.name}.zip"
