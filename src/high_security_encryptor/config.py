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
    def from_dict(cls, payload: dict) -> "BatchEncryptionConfig":
        """从反序列化后的字典构造配置对象。"""

        security_mode = str(payload.get("security_mode", SECURITY_MODE_COMPATIBLE))
        profile = get_security_mode_profile(security_mode)

        config = cls(
            sources=[str(value) for value in payload.get("sources", [])],
            source_passwords={str(key): _normalize_secret_spec(value) for key, value in payload.get("source_passwords", {}).items()},
            metadata_password=_normalize_secret_spec(payload.get("metadata_password", "")),
            output_dir=str(payload.get("output_dir", "")),
            batch_id=str(payload["batch_id"]) if payload.get("batch_id") is not None else None,
            security_mode=security_mode,
            individually_encrypted_files_by_folder={
                str(folder): [str(relative_path) for relative_path in relative_paths]
                for folder, relative_paths in payload.get("individually_encrypted_files_by_folder", {}).items()
            },
            folder_inner_passwords={
                str(folder): {
                    str(relative_path): _normalize_secret_spec(password)
                    for relative_path, password in relative_passwords.items()
                }
                for folder, relative_passwords in payload.get("folder_inner_passwords", {}).items()
            },
            write_password_table=bool(payload["write_password_table"]) if "write_password_table" in payload else profile.write_password_table,
            write_internal_password_tables=(
                bool(payload["write_internal_password_tables"])
                if "write_internal_password_tables" in payload
                else profile.write_internal_password_tables
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
    def from_dict(cls, payload: dict) -> "BatchDecryptionConfig":
        """从反序列化后的字典构造配置对象。"""

        config = cls(
            encrypted_files=[str(value) for value in payload.get("encrypted_files", [])],
            manifest_path=str(payload.get("manifest_path", "")),
            password_table_path=(
                str(payload["password_table_path"])
                if payload.get("password_table_path") is not None and str(payload.get("password_table_path", "")).strip()
                else None
            ),
            template_path=str(payload.get("template_path", "")),
            metadata_password=_normalize_secret_spec(payload.get("metadata_password", "")),
            output_dir=str(payload.get("output_dir", "")),
            security_mode=str(payload.get("security_mode", SECURITY_MODE_COMPATIBLE)),
            passwords_by_encrypted_name={
                str(name): _normalize_secret_spec(password)
                for name, password in payload.get("passwords_by_encrypted_name", {}).items()
            },
            template_passwords_by_encrypted_name={
                str(name): _normalize_secret_spec(password)
                for name, password in payload.get("template_passwords_by_encrypted_name", {}).items()
            },
            template_passwords_by_source_name={
                str(name): _normalize_secret_spec(password)
                for name, password in payload.get("template_passwords_by_source_name", {}).items()
            },
            auto_decrypt_folder_inner_files=bool(payload.get("auto_decrypt_folder_inner_files", True)),
            folder_inner_password_overrides={
                str(encrypted_name): {
                    str(relative_path): _normalize_secret_spec(password)
                    for relative_path, password in inner_map.items()
                }
                for encrypted_name, inner_map in payload.get("folder_inner_password_overrides", {}).items()
            },
            folder_template_passwords_by_package_encrypted_name={
                str(package_name): {
                    str(scope): {
                        str(name): _normalize_secret_spec(password)
                        for name, password in scope_map.items()
                    }
                    for scope, scope_map in package_plan.items()
                }
                for package_name, package_plan in payload.get(
                    "folder_template_passwords_by_package_encrypted_name",
                    {},
                ).items()
            },
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


def _normalize_secret_spec(value: object) -> SecretSpec:
    """把 JSON 解析出的密码配置归一化为统一形式。"""

    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return {str(key): _normalize_secret_spec_value(inner_value) for key, inner_value in value.items()}
    return str(value)


def _normalize_secret_spec_value(value: object) -> object:
    """递归归一化结构化密码配置里的嵌套值。"""

    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_normalize_secret_spec_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize_secret_spec_value(inner_value) for key, inner_value in value.items()}
    return str(value)
