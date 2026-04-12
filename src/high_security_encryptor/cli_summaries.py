"""Serializable CLI summaries for workflow results."""

from __future__ import annotations

from typing import Any

from .batch_decryption import BatchDecryptionResult
from .batch_workflow import BatchEncryptionResult


def summarize_batch_encryption_result(
    result: BatchEncryptionResult,
    security_mode: str,
) -> dict[str, Any]:
    """Build the JSON payload returned by `encrypt-batch`."""

    return {
        "command": "encrypt-batch",
        "security_mode": security_mode,
        "binding": result.binding.as_dict(),
        "encrypted_files": [str(path) for path in result.encrypted_files],
        "folder_packages": [
            {
                "package_path": str(folder_package.package_path),
                "internal_encrypted_files": list(folder_package.internal_encrypted_files),
                "internal_binding": (
                    folder_package.internal_binding.as_dict() if folder_package.internal_binding is not None else None
                ),
                "internal_manifest_relative_path": folder_package.internal_manifest_relative_path,
                "internal_password_table_relative_path": folder_package.internal_password_table_relative_path,
                "internal_template_relative_path": folder_package.internal_template_relative_path,
            }
            for folder_package in result.folder_packages
        ],
        "manifest_path": str(result.manifest_path),
        "password_table_path": str(result.password_table_path) if result.password_table_path is not None else None,
        "template_path": str(result.template_path),
    }


def summarize_batch_decryption_result(
    result: BatchDecryptionResult,
    security_mode: str,
) -> dict[str, Any]:
    """Build the JSON payload returned by `decrypt-batch`."""

    return {
        "command": "decrypt-batch",
        "security_mode": security_mode,
        "binding": result.binding.as_dict(),
        "top_level_entry_comparison": {
            "expected_entries": result.top_level_entry_comparison.expected_entries,
            "actual_entries": result.top_level_entry_comparison.actual_entries,
            "missing_entries": result.top_level_entry_comparison.missing_entries,
            "extra_entries": result.top_level_entry_comparison.extra_entries,
            "duplicate_entries": result.top_level_entry_comparison.duplicate_entries,
        },
        "decrypted_files": [
            {
                "encrypted_path": str(entry.encrypted_path),
                "decrypted_path": str(entry.decrypted_path),
            }
            for entry in result.decrypted_files
        ],
        "decrypted_folder_packages": [
            {
                "package_path": str(folder_result.package_path),
                "extracted_root": str(folder_result.extracted_root),
                "discovered_binding": (
                    folder_result.discovered_binding.as_dict() if folder_result.discovered_binding is not None else None
                ),
                "internal_manifest_path": str(folder_result.internal_manifest_path)
                if folder_result.internal_manifest_path is not None
                else None,
                "internal_password_table_path": str(folder_result.internal_password_table_path)
                if folder_result.internal_password_table_path is not None
                else None,
                "internal_template_path": str(folder_result.internal_template_path)
                if folder_result.internal_template_path is not None
                else None,
                "internal_entry_comparison": (
                    {
                        "expected_entries": folder_result.internal_entry_comparison.expected_entries,
                        "actual_entries": folder_result.internal_entry_comparison.actual_entries,
                        "missing_entries": folder_result.internal_entry_comparison.missing_entries,
                        "extra_entries": folder_result.internal_entry_comparison.extra_entries,
                        "duplicate_entries": folder_result.internal_entry_comparison.duplicate_entries,
                    }
                    if folder_result.internal_entry_comparison is not None
                    else None
                ),
                "decrypted_inner_files": [
                    {
                        "encrypted_relative_path": item.encrypted_relative_path,
                        "decrypted_relative_path": item.decrypted_relative_path,
                        "decrypted_path": str(item.decrypted_path),
                    }
                    for item in folder_result.decrypted_inner_files
                ],
            }
            for folder_result in result.decrypted_folder_packages
        ],
    }
