"""Batch-encryption config object."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from .config_parsing import (
    normalize_secret_spec,
    read_bool,
    read_nested_secret_mapping,
    read_optional_string,
    read_secret_mapping,
    read_string,
    read_string_list,
    read_string_list_mapping,
    require_config_object,
)
from .password_sources import PasswordResolver, SecretSpec
from .security_mode import (
    DEFAULT_SECURITY_MODE,
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    get_security_mode_profile,
)


@dataclass(frozen=True)
class BatchEncryptionConfig:
    """Serializable configuration for one batch-encryption workflow."""

    sources: list[str]
    source_passwords: dict[str, SecretSpec]
    metadata_password: SecretSpec
    output_dir: str
    batch_id: str | None = None
    security_mode: str = DEFAULT_SECURITY_MODE
    package_as_bundle: bool = False
    bundle_output_path: str | None = None
    manifest_output_path: str | None = None
    password_table_output_path: str | None = None
    template_output_path: str | None = None
    individually_encrypted_files_by_folder: dict[str, list[str]] = field(default_factory=dict)
    folder_inner_passwords: dict[str, dict[str, SecretSpec]] = field(default_factory=dict)
    write_password_table: bool = False
    write_internal_password_tables: bool = False

    @classmethod
    def from_json_file(cls, path: str | Path) -> "BatchEncryptionConfig":
        """Load a batch-encryption config from a JSON file."""

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "BatchEncryptionConfig":
        """Construct a config object from a deserialized JSON payload."""

        payload_object = require_config_object(payload)
        security_mode = _read_encryption_security_mode(payload_object)
        profile = get_security_mode_profile(security_mode)

        config = cls(
            sources=read_string_list(payload_object, "sources"),
            source_passwords=read_secret_mapping(payload_object, "source_passwords"),
            metadata_password=normalize_secret_spec(
                payload_object.get("metadata_password", ""),
                "metadata_password",
            ),
            output_dir=read_string(payload_object, "output_dir", ""),
            batch_id=read_optional_string(payload_object, "batch_id"),
            security_mode=security_mode,
            package_as_bundle=read_bool(payload_object, "package_as_bundle", False),
            bundle_output_path=read_optional_string(payload_object, "bundle_output_path"),
            manifest_output_path=read_optional_string(payload_object, "manifest_output_path"),
            password_table_output_path=read_optional_string(payload_object, "password_table_output_path"),
            template_output_path=read_optional_string(payload_object, "template_output_path"),
            individually_encrypted_files_by_folder=read_string_list_mapping(
                payload_object,
                "individually_encrypted_files_by_folder",
            ),
            folder_inner_passwords=read_nested_secret_mapping(
                payload_object,
                "folder_inner_passwords",
            ),
            write_password_table=read_bool(
                payload_object,
                "write_password_table",
                profile.write_password_table,
            ),
            write_internal_password_tables=read_bool(
                payload_object,
                "write_internal_password_tables",
                profile.write_internal_password_tables,
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Reject missing fields and inconsistent folder-inner password mappings."""

        if not self.sources:
            raise ValueError("sources is required")
        if not self.metadata_password:
            raise ValueError("metadata_password is required")
        if not self.output_dir:
            raise ValueError("output_dir is required")
        for source in self.sources:
            if source not in self.source_passwords:
                raise ValueError(f"missing top-level password for source: {source}")
        for folder, relative_paths in self.individually_encrypted_files_by_folder.items():
            inner_passwords = self.folder_inner_passwords.get(folder, {})
            for relative_path in relative_paths:
                if relative_path not in inner_passwords:
                    raise ValueError(f"missing folder inner password for {folder}::{relative_path}")
        get_security_mode_profile(self.security_mode)

    def resolve_metadata_password(self, resolver: PasswordResolver) -> str:
        """Resolve the metadata password source."""

        return resolver.resolve(self.metadata_password, "metadata_password")

    def build_workflow_password_mapping(self, resolver: PasswordResolver) -> dict:
        """Resolve config password sources into the mixed mapping used by the workflow."""

        mapping: dict = {
            source: resolver.resolve(secret_spec, f"source_passwords[{source}]")
            for source, secret_spec in self.source_passwords.items()
        }
        for folder, relative_passwords in self.folder_inner_passwords.items():
            for relative_path, secret_spec in relative_passwords.items():
                mapping[(Path(folder), relative_path)] = resolver.resolve(
                    secret_spec,
                    f"folder_inner_passwords[{folder}][{relative_path}]",
                )
        return mapping


def _read_encryption_security_mode(payload: dict[str, object]) -> str:
    """Infer safer defaults while preserving explicit password-table intent."""

    if "security_mode" in payload:
        return read_string(payload, "security_mode", DEFAULT_SECURITY_MODE)
    if payload.get("write_password_table") is True or _has_nonblank_string(payload, "password_table_output_path"):
        return SECURITY_MODE_COMPATIBLE
    if payload.get("write_internal_password_tables") is True:
        return SECURITY_MODE_HARDENED
    return DEFAULT_SECURITY_MODE


def _has_nonblank_string(payload: dict[str, object], field_name: str) -> bool:
    value = payload.get(field_name)
    return isinstance(value, str) and bool(value.strip())
