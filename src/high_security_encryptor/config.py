"""批量工作流配置对象。"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from .password_sources import PasswordResolver, SecretSpec
from .security_mode import (
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    SECURITY_MODE_NO_PASSWORD_TABLES,
    get_security_mode_profile,
)


@dataclass(frozen=True)
class BatchEncryptionConfig:
    """描述一次批量加密所需的可序列化配置。"""

    sources: list[str]
    source_passwords: dict[str, SecretSpec]
    metadata_password: SecretSpec
    output_dir: str
    batch_id: str | None = None
    security_mode: str = SECURITY_MODE_COMPATIBLE
    individually_encrypted_files_by_folder: dict[str, list[str]] = field(default_factory=dict)
    folder_inner_passwords: dict[str, dict[str, SecretSpec]] = field(default_factory=dict)
    write_password_table: bool = True
    write_internal_password_tables: bool = True

    @classmethod
    def from_json_file(cls, path: str | Path) -> "BatchEncryptionConfig":
        """从 JSON 文件加载批量加密配置。"""

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "BatchEncryptionConfig":
        """从反序列化后的字典构造配置对象。"""

        payload_object = _require_config_object(payload)
        security_mode = _read_string(payload_object, "security_mode", SECURITY_MODE_COMPATIBLE)
        profile = get_security_mode_profile(security_mode)

        config = cls(
            sources=_read_string_list(payload_object, "sources"),
            source_passwords=_read_secret_mapping(payload_object, "source_passwords"),
            metadata_password=_normalize_secret_spec(
                payload_object.get("metadata_password", ""),
                "metadata_password",
            ),
            output_dir=_read_string(payload_object, "output_dir", ""),
            batch_id=_read_optional_string(payload_object, "batch_id"),
            security_mode=security_mode,
            individually_encrypted_files_by_folder=_read_string_list_mapping(
                payload_object,
                "individually_encrypted_files_by_folder",
            ),
            folder_inner_passwords=_read_nested_secret_mapping(
                payload_object,
                "folder_inner_passwords",
            ),
            write_password_table=_read_bool(
                payload_object,
                "write_password_table",
                profile.write_password_table,
            ),
            write_internal_password_tables=_read_bool(
                payload_object,
                "write_internal_password_tables",
                profile.write_internal_password_tables,
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """拒绝缺失字段或结构不合法的加密配置。"""

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
        """按配置指定的密码来源解析元数据密码。"""

        return resolver.resolve(self.metadata_password, "metadata_password")

    def build_workflow_password_mapping(self, resolver: PasswordResolver) -> dict:
        """把密码来源配置解析成工作流内部使用的混合映射。"""

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


@dataclass(frozen=True)
class BatchDecryptionConfig:
    """描述一次混合批量解密所需的可序列化配置。"""

    encrypted_files: list[str]
    manifest_path: str
    password_table_path: str | None
    template_path: str
    metadata_password: SecretSpec
    output_dir: str
    security_mode: str = SECURITY_MODE_COMPATIBLE
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
        """从 JSON 文件加载批量解密配置。"""

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "BatchDecryptionConfig":
        """从反序列化后的字典构造配置对象。"""

        payload_object = _require_config_object(payload)
        config = cls(
            encrypted_files=_read_string_list(payload_object, "encrypted_files"),
            manifest_path=_read_string(payload_object, "manifest_path", ""),
            password_table_path=_read_optional_string(payload_object, "password_table_path"),
            template_path=_read_string(payload_object, "template_path", ""),
            metadata_password=_normalize_secret_spec(
                payload_object.get("metadata_password", ""),
                "metadata_password",
            ),
            output_dir=_read_string(payload_object, "output_dir", ""),
            security_mode=_read_string(payload_object, "security_mode", SECURITY_MODE_COMPATIBLE),
            passwords_by_encrypted_name=_read_secret_mapping(payload_object, "passwords_by_encrypted_name"),
            template_passwords_by_encrypted_name=_read_secret_mapping(
                payload_object,
                "template_passwords_by_encrypted_name",
            ),
            template_passwords_by_source_name=_read_secret_mapping(
                payload_object,
                "template_passwords_by_source_name",
            ),
            auto_decrypt_folder_inner_files=_read_bool(
                payload_object,
                "auto_decrypt_folder_inner_files",
                True,
            ),
            folder_inner_password_overrides=_read_nested_secret_mapping(
                payload_object,
                "folder_inner_password_overrides",
            ),
            folder_template_passwords_by_package_encrypted_name=_read_folder_template_passwords(
                payload_object,
                "folder_template_passwords_by_package_encrypted_name",
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """拒绝缺失字段或结构不合法的解密配置。"""

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
        """按配置指定的密码来源解析元数据密码。"""

        return resolver.resolve(self.metadata_password, "metadata_password")

    def resolve_top_level_password_overrides(self, resolver: PasswordResolver) -> dict[str, str]:
        """解析按密文文件名指定的顶层密码覆盖。"""

        return {
            encrypted_name: resolver.resolve(secret_spec, f"passwords_by_encrypted_name[{encrypted_name}]")
            for encrypted_name, secret_spec in self.passwords_by_encrypted_name.items()
        }

    def resolve_template_passwords_by_encrypted_name(self, resolver: PasswordResolver) -> dict[str, str]:
        """解析按密文文件名索引的运行时模板密码来源。"""

        return {
            encrypted_name: resolver.resolve(
                secret_spec,
                f"template_passwords_by_encrypted_name[{encrypted_name}]",
            )
            for encrypted_name, secret_spec in self.template_passwords_by_encrypted_name.items()
        }

    def resolve_template_passwords_by_source_name(self, resolver: PasswordResolver) -> dict[str, str]:
        """解析按源文件名索引的运行时模板密码来源。"""

        return {
            source_name: resolver.resolve(
                secret_spec,
                f"template_passwords_by_source_name[{source_name}]",
            )
            for source_name, secret_spec in self.template_passwords_by_source_name.items()
        }

    def resolve_folder_inner_password_overrides(self, resolver: PasswordResolver) -> dict[str, dict[str, str]]:
        """解析文件夹内部文件的显式密码覆盖。"""

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
        """解析按外层包分组的内部运行时密码计划来源。"""

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


def _require_config_object(payload: object) -> dict[str, object]:
    """Reject non-object top-level JSON payloads before field parsing."""

    if not isinstance(payload, dict):
        raise ValueError("config must be a JSON object")
    return payload


def _read_string(payload: dict[str, object], field_name: str, default: str) -> str:
    """Read an optional string field without coercing non-strings."""

    if field_name not in payload:
        return default
    value = payload[field_name]
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


def _read_optional_string(payload: dict[str, object], field_name: str) -> str | None:
    """Read a nullable or blank-as-missing string field."""

    if field_name not in payload or payload[field_name] is None:
        return None
    value = payload[field_name]
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or null")
    normalized = value.strip()
    return normalized or None


def _read_bool(payload: dict[str, object], field_name: str, default: bool) -> bool:
    """Read a boolean field without accepting string truthiness."""

    if field_name not in payload:
        return default
    value = payload[field_name]
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _read_object_mapping(payload: dict[str, object], field_name: str) -> dict[str, object]:
    """Read a JSON object field and preserve key names."""

    if field_name not in payload:
        return {}
    value = payload[field_name]
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    result: dict[str, object] = {}
    for key, inner_value in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{field_name} keys must be strings")
        result[key] = inner_value
    return result


def _read_string_list(payload: dict[str, object], field_name: str) -> list[str]:
    """Read a list of strings without iterating accidental scalar values."""

    if field_name not in payload:
        return []
    value = payload[field_name]
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{field_name}[{index}] must be a string")
        result.append(item)
    return result


def _read_string_list_mapping(payload: dict[str, object], field_name: str) -> dict[str, list[str]]:
    """Read a JSON object whose values are string lists."""

    raw_mapping = _read_object_mapping(payload, field_name)
    result: dict[str, list[str]] = {}
    for key, value in raw_mapping.items():
        if not isinstance(value, list):
            raise ValueError(f"{field_name}[{key}] must be a list")
        items: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str):
                raise ValueError(f"{field_name}[{key}][{index}] must be a string")
            items.append(item)
        result[key] = items
    return result


def _read_secret_mapping(payload: dict[str, object], field_name: str) -> dict[str, SecretSpec]:
    """Read a JSON object whose values are password source specs."""

    raw_mapping = _read_object_mapping(payload, field_name)
    return {
        key: _normalize_secret_spec(value, f"{field_name}[{key}]")
        for key, value in raw_mapping.items()
    }


def _read_nested_secret_mapping(payload: dict[str, object], field_name: str) -> dict[str, dict[str, SecretSpec]]:
    """Read a two-level JSON object whose leaf values are password source specs."""

    raw_mapping = _read_object_mapping(payload, field_name)
    result: dict[str, dict[str, SecretSpec]] = {}
    for key, inner_value in raw_mapping.items():
        if not isinstance(inner_value, dict):
            raise ValueError(f"{field_name}[{key}] must be an object")
        result[key] = {}
        for inner_key, secret_value in inner_value.items():
            if not isinstance(inner_key, str):
                raise ValueError(f"{field_name}[{key}] keys must be strings")
            result[key][inner_key] = _normalize_secret_spec(
                secret_value,
                f"{field_name}[{key}][{inner_key}]",
            )
    return result


def _read_folder_template_passwords(
    payload: dict[str, object],
    field_name: str,
) -> dict[str, dict[str, dict[str, SecretSpec]]]:
    """Read package-scoped runtime password plans for folder internals."""

    raw_mapping = _read_object_mapping(payload, field_name)
    result: dict[str, dict[str, dict[str, SecretSpec]]] = {}
    for package_name, package_plan in raw_mapping.items():
        if not isinstance(package_plan, dict):
            raise ValueError(f"{field_name}[{package_name}] must be an object")
        normalized_package_plan: dict[str, dict[str, SecretSpec]] = {}
        for scope, scope_map in package_plan.items():
            if not isinstance(scope, str):
                raise ValueError(f"{field_name}[{package_name}] keys must be strings")
            if scope not in {"by_encrypted_name", "by_source_name"}:
                raise ValueError(f"{field_name}[{package_name}] has unsupported scope: {scope}")
            if not isinstance(scope_map, dict):
                raise ValueError(f"{field_name}[{package_name}][{scope}] must be an object")
            normalized_package_plan[scope] = {}
            for name, secret_value in scope_map.items():
                if not isinstance(name, str):
                    raise ValueError(f"{field_name}[{package_name}][{scope}] keys must be strings")
                normalized_package_plan[scope][name] = _normalize_secret_spec(
                    secret_value,
                    f"{field_name}[{package_name}][{scope}][{name}]",
                )
        result[package_name] = normalized_package_plan
    return result


def _normalize_secret_spec(value: object, context: str) -> SecretSpec:
    """Normalize JSON password-source config without scalar coercion."""

    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, inner_value in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{context}: password source keys must be strings")
            result[key] = _normalize_secret_spec_value(inner_value, f"{context}.{key}")
        return result
    raise ValueError(f"{context} must be a string or password source object")


def _normalize_secret_spec_value(value: object, context: str) -> object:
    """Normalize nested password-source values without scalar coercion."""

    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [
            _normalize_secret_spec_value(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, inner_value in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{context}: password source keys must be strings")
            result[key] = _normalize_secret_spec_value(inner_value, f"{context}.{key}")
        return result
    raise ValueError(f"{context} must be a string, list, or object")

