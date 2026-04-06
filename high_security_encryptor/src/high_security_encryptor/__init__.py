"""Public package exports for the hardened encryption prototype."""

from .api import decrypt_file_streaming, encrypt_file_streaming
from .batch_artifacts import (
    load_manifest_artifact,
    load_password_table_artifact,
    load_template_artifact,
    write_manifest_artifact,
    write_password_table_artifact,
    write_template_artifact,
)
from .batch_binding import BatchBinding, BindingValidationError, create_batch_binding, validate_binding
from .batch_payloads import (
    PasswordRecord,
    create_manifest_payload,
    create_password_table_payload,
    create_template_payload,
)
from .batch_workflow import BatchEncryptionResult, encrypt_batch_files, load_batch_sidecars
from .folder_workflow import FolderPackageResult, package_folder_to_encrypted_archive

__all__ = [
    "encrypt_file_streaming",
    "decrypt_file_streaming",
    "BatchBinding",
    "BindingValidationError",
    "create_batch_binding",
    "validate_binding",
    "PasswordRecord",
    "create_manifest_payload",
    "create_password_table_payload",
    "create_template_payload",
    "write_manifest_artifact",
    "load_manifest_artifact",
    "write_password_table_artifact",
    "load_password_table_artifact",
    "write_template_artifact",
    "load_template_artifact",
    "BatchEncryptionResult",
    "encrypt_batch_files",
    "load_batch_sidecars",
    "FolderPackageResult",
    "package_folder_to_encrypted_archive",
]
