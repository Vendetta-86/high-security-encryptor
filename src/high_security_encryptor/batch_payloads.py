"""批次元数据载荷的结构化辅助逻辑。"""

from __future__ import annotations

from dataclasses import dataclass

from .batch_binding import (
    BatchBinding,
    BindingValidationError,
    attach_binding,
    create_batch_binding,
    validate_binding,
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
    payload = {
        "kind": "manifest",
        "mode": mode,
        "entries": [{"encrypted_name": name} for name in sorted(encrypted_names)],
    }
    return attach_binding(payload, binding)


def validate_manifest_payload(payload: dict, expected_binding: BatchBinding) -> None:
    """确保 manifest 载荷属于预期批次。"""

    if payload.get("kind") != "manifest":
        raise BindingValidationError("payload is not a manifest")
    validate_binding(expected_binding, payload)


def create_password_table_payload(
    records: list[PasswordRecord],
    encrypted_names: list[str],
    batch_id: str | None = None,
) -> tuple[dict, BatchBinding]:
    """创建密码表载荷，并返回其绑定信息。"""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
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


def create_template_payload(
    source_names: list[str],
    encrypted_names: list[str],
    batch_id: str | None = None,
) -> tuple[dict, BatchBinding]:
    """创建一个带绑定信息、供后续填写密码的模板载荷。"""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
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

