"""Batch-decryption config object."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from .config_parsing import (
    normalize_secret_spec,
    read_bool,
    read_folder_template_passwords,
    read_nested_secret_mapping,
    read_optional_string,
    read_secret_mapping,
    read_string,
    read_string_list,
    require_config_object,
)
from .password_sources import PasswordResolver, SecretSpec
from .security_mode import (
    DEFAULT_SECURITY_MODE,
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    SECURITY_MODE_NO_PASSWORD_TABLES,
    get_security_mode_profile,
)


@dataclass(frozen=True)
class BatchDecryptionConfig:
    """Serializable configuration for one mixed batch-decryption workflow."""

    encrypted_files: list[str]
    manifest_path: str
    password_table_path: str | None
    template_path: str
    metadata_password: SecretSpec
    output_dir: str
    security_mode: str = DEFAULT_SECURITY_MODE
    passwords_by_encrypted_name: dict[str, SecretSpec] = field(default_factory=dict)
    template_passwords_by_encrypted_name: dict[str, SecretSpec] = field(default_factory=dict)
    template_passwords_by_source_name: dict[str, SecretSpec] = field(default_factory=dict)
    auto_decrypt_folder_inner_files: bool = True
    folder_inner_password_overrides: dict[str, dict[str, SecretSpec]] = field(default_factory=dict)
    folder_template_passwords_by_package_encrypted_name: dict[str, dict[str, dict[str, SecretSpec]]] = field(
        default_factory=dict
    )

    @classmethod
    def from_json_file(cls, path: str | Path) -> "BatchDecryptionConfig":
        """Load a batch-decryption config from a JSON file."""

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "BatchDecryptionConfig":
        """Construct a config object from a deserialized JSON payload."""

        payload_object = require_config_object(payload)
        config = cls(
            encrypted_files=read_string_list(payload_object, "encrypted_files"),
            manifest_path=read_string(payload_object, "manifest_path", ""),
            password_table_path=read_optional_string(payload_object, "password_table_path"),
            template_path=read_string(payload_object, "template_path", ""),
            metadata_password=normalize_secret_spec(
                payload_object.get("metadata_password", ""),
                "metadata_password",
            ),
            output_dir=read_string(payload_object, "output_dir", ""),
            security_mode=_read_decryption_security_mode(payload_object),
            passwords_by_encrypted_name=read_secret_mapping(payload_object, "passwords_by_encrypted_name"),
            template_passwords_by_encrypted_name=read_secret_mapping(
                payload_object,
                "template_passwords_by_encrypted_name",
            ),
            template_passwords_by_source_name=read_secret_mapping(
                payload_object,
                "template_passwords_by_source_name",
            ),
            auto_decrypt_folder_inner_files=read_bool(
                payload_object,
                "auto_decrypt_folder_inner_files",
                True,
            ),
            folder_inner_password_overrides=read_nested_secret_mapping(
                payload_object,
                "folder_inner_password_overrides",
            ),
            folder_template_passwords_by_package_encrypted_name=read_folder_template_passwords(
                payload_object,
                "folder_template_passwords_by_package_encrypted_name",
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Reject missing fields and security-mode incompatible password-table usage."""

        if not self.encrypted_files:
            raise ValueError("encrypted_files is required")
        if not self.manifest_path:
            raise ValueError("manifest_path is required")
        if not self.template_path:
            raise ValueError("template_path is required")
        if not self.metadata_password:
            raise ValueError("metadata_password is required")
        if not self.output_dir:
            raise ValueError("output_dir is required")
        get_security_mode_profile(self.security_mode)
        if self.security_mode in {SECURITY_MODE_HARDENED, SECURITY_MODE_NO_PASSWORD_TABLES} and self.password_table_path is not None:
            raise ValueError(
                f"security_mode={self.security_mode!r} expects password_table_path to be omitted"
            )
        if (
            self.password_table_path is None
            and not self.passwords_by_encrypted_name
            and not self.template_passwords_by_encrypted_name
            and not self.template_passwords_by_source_name
        ):
            raise ValueError(
                "either password_table_path or runtime password sources are required for batch decryption"
            )

    def resolve_metadata_password(self, resolver: PasswordResolver) -> str:
        """Resolve the metadata password source."""

        return resolver.resolve(self.metadata_password, "metadata_password")

    def resolve_top_level_password_overrides(self, resolver: PasswordResolver) -> dict[str, str]:
        """Resolve explicit top-level passwords indexed by encrypted file name."""

        return {
            encrypted_name: resolver.resolve(secret_spec, f"passwords_by_encrypted_name[{encrypted_name}]")
            for encrypted_name, secret_spec in self.passwords_by_encrypted_name.items()
        }

    def resolve_template_passwords_by_encrypted_name(self, resolver: PasswordResolver) -> dict[str, str]:
        """Resolve template runtime passwords indexed by encrypted file name."""

        return {
            encrypted_name: resolver.resolve(
                secret_spec,
                f"template_passwords_by_encrypted_name[{encrypted_name}]",
            )
            for encrypted_name, secret_spec in self.template_passwords_by_encrypted_name.items()
        }

    def resolve_template_passwords_by_source_name(self, resolver: PasswordResolver) -> dict[str, str]:
        """Resolve template runtime passwords indexed by source file name."""

        return {
            source_name: resolver.resolve(
                secret_spec,
                f"template_passwords_by_source_name[{source_name}]",
            )
            for source_name, secret_spec in self.template_passwords_by_source_name.items()
        }

    def resolve_folder_inner_password_overrides(self, resolver: PasswordResolver) -> dict[str, dict[str, str]]:
        """Resolve explicit password overrides for encrypted members inside folder packages."""

        resolved: dict[str, dict[str, str]] = {}
        for encrypted_name, inner_map in self.folder_inner_password_overrides.items():
            resolved[encrypted_name] = {
                relative_path: resolver.resolve(
                    secret_spec,
                    f"folder_inner_password_overrides[{encrypted_name}][{relative_path}]",
                )
                for relative_path, secret_spec in inner_map.items()
            }
        return resolved

    def resolve_folder_template_runtime_plans(
        self,
        resolver: PasswordResolver,
    ) -> dict[str, dict[str, dict[str, str]]]:
        """Resolve package-scoped runtime password plans for folder-internal members."""

        resolved: dict[str, dict[str, dict[str, str]]] = {}
        for package_name, package_plan in self.folder_template_passwords_by_package_encrypted_name.items():
            resolved[package_name] = {
                "by_encrypted_name": {
                    name: resolver.resolve(
                        secret_spec,
                        f"folder_template_passwords_by_package_encrypted_name[{package_name}][by_encrypted_name][{name}]",
                    )
                    for name, secret_spec in package_plan.get("by_encrypted_name", {}).items()
                },
                "by_source_name": {
                    name: resolver.resolve(
                        secret_spec,
                        f"folder_template_passwords_by_package_encrypted_name[{package_name}][by_source_name][{name}]",
                    )
                    for name, secret_spec in package_plan.get("by_source_name", {}).items()
                },
            }
        return resolved


def _read_decryption_security_mode(payload: dict[str, object]) -> str:
    """Keep legacy password-table configs compatible while defaulting new configs safer."""

    if "security_mode" in payload:
        return read_string(payload, "security_mode", DEFAULT_SECURITY_MODE)
    if _has_nonblank_string(payload, "password_table_path"):
        return SECURITY_MODE_COMPATIBLE
    return DEFAULT_SECURITY_MODE


def _has_nonblank_string(payload: dict[str, object], field_name: str) -> bool:
    value = payload.get(field_name)
    return isinstance(value, str) and bool(value.strip())
