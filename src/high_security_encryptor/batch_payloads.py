"""批次元数据载荷的结构化辅助逻辑。"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass

from .batch_binding import (
    BatchBinding,
    BindingValidationError,
    attach_binding,
    create_batch_binding,
    extract_binding,
    validate_binding,
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


def serialize_manifest_payload(payload: dict) -> bytes:
    """把 manifest 载荷序列化成稳定的 JSON 字节串。"""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def deserialize_manifest_payload(blob: bytes) -> dict:
    """把 JSON 字节串反序列化回 manifest 载荷字典。"""

    return json.loads(blob.decode("utf-8"))


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


def serialize_password_table_payload(payload: dict) -> bytes:
    """把密码表载荷序列化成基于 CSV 的字节流。"""

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    binding = extract_binding(payload)
    writer.writerow(["meta", "kind", payload["kind"]])
    writer.writerow(["meta", "batch_id", binding.batch_id])
    writer.writerow(["meta", "file_count", str(binding.file_count)])
    writer.writerow(["meta", "manifest_fingerprint", binding.manifest_fingerprint])
    writer.writerow(["data", "source_name", "encrypted_name", "password"])
    for record in payload.get("records", []):
        writer.writerow(["data", record["source_name"], record["encrypted_name"], record["password"]])
    return buffer.getvalue().encode("utf-8")


def deserialize_password_table_payload(blob: bytes) -> dict:
    """从字节串中解析基于 CSV 的密码表载荷。"""

    reader = csv.reader(io.StringIO(blob.decode("utf-8")))
    meta: dict[str, str] = {}
    records: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        if row[0] == "meta" and len(row) >= 3:
            meta[row[1]] = row[2]
        elif row[0] == "data" and len(row) >= 4 and row[1] != "source_name":
            records.append(
                {
                    "source_name": row[1],
                    "encrypted_name": row[2],
                    "password": row[3],
                }
            )
    payload = {
        "kind": meta.get("kind", ""),
        "records": records,
        "binding": {
            "batch_id": meta.get("batch_id", ""),
            "file_count": int(meta.get("file_count", "0")),
            "manifest_fingerprint": meta.get("manifest_fingerprint", ""),
        },
    }
    return payload


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


def serialize_template_payload(payload: dict) -> bytes:
    """把模板载荷序列化成 CSV 字节串。"""

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    binding = extract_binding(payload)
    writer.writerow(["meta", "kind", payload["kind"]])
    writer.writerow(["meta", "batch_id", binding.batch_id])
    writer.writerow(["meta", "file_count", str(binding.file_count)])
    writer.writerow(["meta", "manifest_fingerprint", binding.manifest_fingerprint])
    writer.writerow(["data", "source_name", "encrypted_name", "password"])
    for row in payload.get("rows", []):
        writer.writerow(["data", row["source_name"], row["encrypted_name"], row["password"]])
    return buffer.getvalue().encode("utf-8")


def deserialize_template_payload(blob: bytes) -> dict:
    """从 CSV 字节串中解析模板载荷。"""

    reader = csv.reader(io.StringIO(blob.decode("utf-8")))
    meta: dict[str, str] = {}
    rows: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        if row[0] == "meta" and len(row) >= 3:
            meta[row[1]] = row[2]
        elif row[0] == "data" and len(row) >= 4 and row[1] != "source_name":
            rows.append(
                {
                    "source_name": row[1],
                    "encrypted_name": row[2],
                    "password": row[3],
                }
            )
    return {
        "kind": meta.get("kind", ""),
        "rows": rows,
        "binding": {
            "batch_id": meta.get("batch_id", ""),
            "file_count": int(meta.get("file_count", "0")),
            "manifest_fingerprint": meta.get("manifest_fingerprint", ""),
        },
    }
