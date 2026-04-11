"""项目公共导出入口。"""

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
from .batch_decryption import BatchDecryptionResult, DecryptedTopLevelFile, decrypt_batch_files
from .cli import main as cli_main
from .config import BatchDecryptionConfig, BatchEncryptionConfig
from .folder_workflow import FolderPackageResult, package_folder_to_encrypted_archive
from .folder_decryption import FolderDecryptionResult, decrypt_folder_archive, safe_extract_folder_archive
from .integrity import EntrySetComparison, IntegrityValidationError
from .password_sources import PasswordResolver, PasswordSourceError, create_default_password_resolver
from .runtime_password_plan import RuntimePasswordPlan, resolve_password_plan_from_template
from .security_mode import (
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    SECURITY_MODE_NO_PASSWORD_TABLES,
    SecurityModeProfile,
    get_security_mode_profile,
)

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
    "BatchDecryptionResult",
    "DecryptedTopLevelFile",
    "BatchEncryptionConfig",
    "BatchDecryptionConfig",
    "PasswordResolver",
    "PasswordSourceError",
    "encrypt_batch_files",
    "decrypt_batch_files",
    "load_batch_sidecars",
    "cli_main",
    "create_default_password_resolver",
    "RuntimePasswordPlan",
    "resolve_password_plan_from_template",
    "SECURITY_MODE_COMPATIBLE",
    "SECURITY_MODE_HARDENED",
    "SECURITY_MODE_NO_PASSWORD_TABLES",
    "SecurityModeProfile",
    "get_security_mode_profile",
    "FolderPackageResult",
    "package_folder_to_encrypted_archive",
    "FolderDecryptionResult",
    "decrypt_folder_archive",
    "safe_extract_folder_archive",
    "EntrySetComparison",
    "IntegrityValidationError",
]
