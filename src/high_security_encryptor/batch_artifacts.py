"""批次 sidecar 的文件级读写辅助逻辑。"""

from __future__ import annotations

from pathlib import Path

from .batch_binding import BatchBinding, extract_binding
from .batch_payloads import (
    PasswordRecord,
    create_manifest_payload,
    create_password_table_payload,
    create_template_payload,
    deserialize_manifest_payload,
    deserialize_password_table_payload,
    deserialize_template_payload,
    serialize_manifest_payload,
    serialize_password_table_payload,
    serialize_template_payload,
    validate_manifest_payload,
    validate_password_table_payload,
    validate_template_payload,
)
from .metadata_crypto import read_encrypted_metadata_file, write_encrypted_metadata_file


def write_manifest_artifact(
    path: str | Path,
    encrypted_names: list[str],
    mode: str,
    password: str,
    batch_id: str | None = None,
) -> BatchBinding:
    """创建并持久化加密后的 manifest 副产物。"""

    payload = create_manifest_payload(encrypted_names, mode=mode, batch_id=batch_id)
    write_encrypted_metadata_file(path, serialize_manifest_payload(payload), password)
    return extract_binding(payload)


def load_manifest_artifact(path: str | Path, password: str, expected_binding: BatchBinding) -> dict:
    """加载、解密并校验加密 manifest 副产物。"""

    payload = deserialize_manifest_payload(read_encrypted_metadata_file(path, password))
    validate_manifest_payload(payload, expected_binding)
    return payload


def write_password_table_artifact(
    path: str | Path,
    records: list[PasswordRecord],
    encrypted_names: list[str],
    password: str,
    batch_id: str | None = None,
) -> BatchBinding:
    """创建并持久化加密后的密码表副产物。"""

    payload, binding = create_password_table_payload(records, encrypted_names, batch_id=batch_id)
    write_encrypted_metadata_file(path, serialize_password_table_payload(payload), password)
    return binding


def load_password_table_artifact(path: str | Path, password: str, expected_binding: BatchBinding) -> dict:
    """加载、解密并校验加密密码表副产物。"""

    payload = deserialize_password_table_payload(read_encrypted_metadata_file(path, password))
    validate_password_table_payload(payload, expected_binding)
    return payload


def write_template_artifact(
    path: str | Path,
    source_names: list[str],
    encrypted_names: list[str],
    password: str,
    batch_id: str | None = None,
) -> BatchBinding:
    """创建并持久化加密后的模板副产物。"""

    payload, binding = create_template_payload(source_names, encrypted_names, batch_id=batch_id)
    write_encrypted_metadata_file(path, serialize_template_payload(payload), password)
    return binding


def load_template_artifact(path: str | Path, password: str, expected_binding: BatchBinding) -> dict:
    """加载、解密并校验加密模板副产物。"""

    payload = deserialize_template_payload(read_encrypted_metadata_file(path, password))
    validate_template_payload(payload, expected_binding)
    return payload
