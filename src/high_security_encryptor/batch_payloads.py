"""批次元数据载荷的结构化辅助逻辑。"""

from __future__ import annotations

from dataclasses import dataclass

from .batch_binding import (
    BatchBinding,
    BindingValidationError,
    attach_binding,
    build_manifest_fingerprint,
    create_batch_binding,
    extract_binding,
    validate_binding,
)
from .batch_payload_limits import (
    MAX_MODE_CHARS,
    require_bounded_string,
    validate_entry_count,
    validate_entry_name,
    validate_password_value,
)
from .batch_payload_serialization import (
    deserialize_manifest_payload,
    deserialize_password_table_payload,
    deserialize_template_payload,
    serialize_manifest_payload,
    serialize_password_table_payload,
    serialize_template_payload,
)


@dataclass(frozen=True)
class PasswordRecord:
    """密码表副产物中的一行记录。"""

    source_name: str
    encrypted_name: str
    password: str

    def as_dict(self) -> dict[str, str]:
        """把记录转换成可序列化字典。"""

        return {
            "source_name": self.source_name,
            "encrypted_name": self.encrypted_name,
            "password": self.password,
        }


def create_manifest_payload(encrypted_names: list[str], mode: str, batch_id: str | None = None) -> dict:
    """创建 manifest 载荷并附加绑定信息。"""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
    validated_mode = require_bounded_string(mode, "manifest.mode", MAX_MODE_CHARS)
    payload = {
        "kind": "manifest",
        "mode": validated_mode,
        "entries": [{"encrypted_name": name} for name in sorted(encrypted_names)],
    }
    return attach_binding(payload, binding)


def validate_manifest_payload(payload: dict, expected_binding: BatchBinding) -> None:
    """确保 manifest 载荷属于预期批次。"""

    if payload.get("kind") != "manifest":
        raise BindingValidationError("payload is not a manifest")
    validate_binding(expected_binding, payload)
    binding = extract_binding(payload)
    encrypted_names = _extract_manifest_entry_names(payload)
    _validate_names_match_binding(encrypted_names, binding, "manifest")
    _validate_names_match_binding(encrypted_names, expected_binding, "manifest")


def create_password_table_payload(
    records: list[PasswordRecord],
    encrypted_names: list[str],
    batch_id: str | None = None,
) -> tuple[dict, BatchBinding]:
    """创建密码表载荷，并返回其绑定信息。"""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
    validate_entry_count(len(records), "password table")
    if len(records) != len(encrypted_names):
        raise ValueError("password table record count must match encrypted names")
    payload = {
        "kind": "password_table",
        "records": [record.as_dict() for record in records],
    }
    return attach_binding(payload, binding), binding


def validate_password_table_payload(payload: dict, expected_binding: BatchBinding) -> None:
    """确保密码表载荷属于预期批次。"""

    if payload.get("kind") != "password_table":
        raise BindingValidationError("payload is not a password table")
    validate_binding(expected_binding, payload)
    records = _extract_tabular_rows(payload, "records", password_required=True)
    _validate_names_match_binding([record["encrypted_name"] for record in records], expected_binding, "password table")


def create_template_payload(
    source_names: list[str],
    encrypted_names: list[str],
    batch_id: str | None = None,
) -> tuple[dict, BatchBinding]:
    """创建一个带绑定信息、供后续填写密码的模板载荷。"""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
    validate_entry_count(len(source_names), "template")
    if len(source_names) != len(encrypted_names):
        raise ValueError("template source count must match encrypted names")
    payload = {
        "kind": "template",
        "rows": [
            {
                "source_name": source_name,
                "encrypted_name": encrypted_name,
                "password": "",
            }
            for source_name, encrypted_name in zip(source_names, encrypted_names, strict=True)
        ],
    }
    return attach_binding(payload, binding), binding


def validate_template_payload(payload: dict, expected_binding: BatchBinding) -> None:
    """确保模板载荷属于预期批次。"""

    if payload.get("kind") != "template":
        raise BindingValidationError("payload is not a template")
    validate_binding(expected_binding, payload)
    rows = _extract_tabular_rows(payload, "rows", password_required=False)
    _validate_names_match_binding([row["encrypted_name"] for row in rows], expected_binding, "template")


def _extract_manifest_entry_names(payload: dict) -> list[str]:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise BindingValidationError("manifest entries must be a list")
    validate_entry_count(len(entries), "manifest")
    encrypted_names: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BindingValidationError(f"manifest entries[{index}] must be an object")
        try:
            encrypted_names.append(
                validate_entry_name(entry["encrypted_name"], f"manifest.entries[{index}].encrypted_name")
            )
        except (KeyError, ValueError) as exc:
            raise BindingValidationError("invalid manifest entry") from exc
    _validate_unique_names(encrypted_names, "manifest")
    return encrypted_names


def _extract_tabular_rows(payload: dict, row_key: str, *, password_required: bool) -> list[dict[str, str]]:
    rows = payload.get(row_key)
    if not isinstance(rows, list):
        raise BindingValidationError(f"{row_key} must be a list")
    validate_entry_count(len(rows), row_key)
    normalized_rows: list[dict[str, str]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BindingValidationError(f"{row_key}[{index}] must be an object")
        try:
            normalized_rows.append(
                {
                    "source_name": validate_entry_name(row["source_name"], f"{row_key}[{index}].source_name"),
                    "encrypted_name": validate_entry_name(row["encrypted_name"], f"{row_key}[{index}].encrypted_name"),
                    "password": validate_password_value(
                        row.get("password", ""),
                        f"{row_key}[{index}].password",
                        allow_empty=not password_required,
                    ),
                }
            )
        except (KeyError, ValueError) as exc:
            raise BindingValidationError(f"invalid {row_key} row") from exc
    _validate_unique_names([row["encrypted_name"] for row in normalized_rows], row_key)
    return normalized_rows


def _validate_names_match_binding(encrypted_names: list[str], binding: BatchBinding, context: str) -> None:
    validate_entry_count(len(encrypted_names), context)
    if len(encrypted_names) != binding.file_count:
        raise BindingValidationError(f"{context} entry count mismatch")
    if build_manifest_fingerprint(encrypted_names) != binding.manifest_fingerprint:
        raise BindingValidationError(f"{context} entry fingerprint mismatch")


def _validate_unique_names(encrypted_names: list[str], context: str) -> None:
    if len(set(encrypted_names)) != len(encrypted_names):
        raise BindingValidationError(f"{context} contains duplicate encrypted names")
