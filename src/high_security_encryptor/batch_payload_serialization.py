"""Serialization helpers for batch metadata payloads."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .batch_binding import extract_binding


def serialize_manifest_payload(payload: dict) -> bytes:
    """Serialize a manifest payload as stable JSON bytes."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def deserialize_manifest_payload(blob: bytes) -> dict:
    """Deserialize manifest JSON bytes."""

    return json.loads(blob.decode("utf-8"))


def serialize_password_table_payload(payload: dict) -> bytes:
    """Serialize a password-table payload as CSV bytes."""

    return _serialize_tabular_payload(payload, row_key="records")


def deserialize_password_table_payload(blob: bytes) -> dict:
    """Deserialize password-table CSV bytes."""

    meta, rows = _deserialize_tabular_payload(blob)
    return {
        "kind": meta.get("kind", ""),
        "records": rows,
        "binding": _binding_from_meta(meta),
    }


def serialize_template_payload(payload: dict) -> bytes:
    """Serialize a template payload as CSV bytes."""

    return _serialize_tabular_payload(payload, row_key="rows")


def deserialize_template_payload(blob: bytes) -> dict:
    """Deserialize template CSV bytes."""

    meta, rows = _deserialize_tabular_payload(blob)
    return {
        "kind": meta.get("kind", ""),
        "rows": rows,
        "binding": _binding_from_meta(meta),
    }


def _serialize_tabular_payload(payload: dict, row_key: str) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    binding = extract_binding(payload)
    writer.writerow(["meta", "kind", payload["kind"]])
    writer.writerow(["meta", "batch_id", binding.batch_id])
    writer.writerow(["meta", "file_count", str(binding.file_count)])
    writer.writerow(["meta", "manifest_fingerprint", binding.manifest_fingerprint])
    writer.writerow(["data", "source_name", "encrypted_name", "password"])
    for row in payload.get(row_key, []):
        writer.writerow(["data", row["source_name"], row["encrypted_name"], row["password"]])
    return buffer.getvalue().encode("utf-8")


def _deserialize_tabular_payload(blob: bytes) -> tuple[dict[str, str], list[dict[str, str]]]:
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
    return meta, rows


def _binding_from_meta(meta: dict[str, str]) -> dict[str, Any]:
    return {
        "batch_id": meta.get("batch_id", ""),
        "file_count": int(meta.get("file_count", "0")),
        "manifest_fingerprint": meta.get("manifest_fingerprint", ""),
    }
