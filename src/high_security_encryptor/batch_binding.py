"""批次绑定原语。"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from .batch_payload_limits import (
    validate_batch_id,
    validate_entry_count,
    validate_entry_name,
    validate_manifest_fingerprint,
)


class BindingValidationError(Exception):
    """当批次绑定信息缺失或不匹配时抛出。"""

    pass


@dataclass(frozen=True)
class BatchBinding:
    """描述一个加密批次的标准绑定元数据。"""

    batch_id: str
    file_count: int
    manifest_fingerprint: str

    def as_dict(self) -> dict[str, str | int]:
        """把绑定信息转换成适合 JSON/CSV 的字典结构。"""

        return {
            "batch_id": self.batch_id,
            "file_count": self.file_count,
            "manifest_fingerprint": self.manifest_fingerprint,
        }


def canonicalize_names(names: list[str]) -> list[str]:
    """把加密条目名称归一化为确定性的路径顺序。"""

    validate_entry_count(len(names), "batch")
    return sorted(validate_entry_name(str(Path(name).as_posix()), "encrypted_name") for name in names)


def build_manifest_fingerprint(names: list[str]) -> str:
    """对加密条目集合计算确定性指纹。"""

    canonical_names = canonicalize_names(names)
    digest = hashlib.sha256()
    for name in canonical_names:
        digest.update(name.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def create_batch_binding(names: list[str], batch_id: str | None = None) -> BatchBinding:
    """根据一个批次的加密文件名创建绑定信息。"""

    canonical_names = canonicalize_names(names)
    return BatchBinding(
        batch_id=validate_batch_id(batch_id) if batch_id is not None else str(uuid.uuid4()),
        file_count=len(canonical_names),
        manifest_fingerprint=build_manifest_fingerprint(canonical_names),
    )


def attach_binding(payload: dict, binding: BatchBinding) -> dict:
    """返回附带绑定信息的载荷浅拷贝。"""

    result = dict(payload)
    result["binding"] = binding.as_dict()
    return result


def extract_binding(payload: dict) -> BatchBinding:
    """从已附带绑定信息的载荷中解析绑定元数据。"""

    binding = payload.get("binding")
    if not isinstance(binding, dict):
        raise BindingValidationError("missing binding metadata")
    try:
        batch_id = validate_batch_id(binding["batch_id"])
        file_count = int(binding["file_count"])
        validate_entry_count(file_count, "binding")
        manifest_fingerprint = validate_manifest_fingerprint(binding["manifest_fingerprint"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BindingValidationError("invalid binding metadata") from exc
    return BatchBinding(
        batch_id=batch_id,
        file_count=file_count,
        manifest_fingerprint=manifest_fingerprint,
    )


def validate_binding(expected: BatchBinding, actual_payload: dict) -> None:
    """拒绝绑定信息与预期批次不一致的载荷。"""

    actual = extract_binding(actual_payload)
    if actual.batch_id != expected.batch_id:
        raise BindingValidationError("batch id mismatch")
    if actual.file_count != expected.file_count:
        raise BindingValidationError("file count mismatch")
    if actual.manifest_fingerprint != expected.manifest_fingerprint:
        raise BindingValidationError("manifest fingerprint mismatch")


def serialize_binding_payload(payload: dict) -> bytes:
    """以确定性方式序列化载荷，用于哈希或存储。"""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
