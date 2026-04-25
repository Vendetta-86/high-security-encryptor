"""Serialization helpers for batch metadata payloads."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .batch_payload_limits import (
    MAX_CSV_FIELD_CHARS,
    MAX_MODE_CHARS,
    require_bounded_string,
    validate_entry_count,
    validate_entry_name,
    validate_password_value,
)
from .batch_binding import extract_binding


_CSV_META_KEYS = {"kind", "batch_id", "file_count", "manifest_fingerprint"}
csv.field_size_limit(MAX_CSV_FIELD_CHARS)


def serialize_manifest_payload(payload: dict) -> bytes:
    """Serialize a manifest payload as stable JSON bytes."""

    _validate_manifest_for_serialization(payload)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def deserialize_manifest_payload(blob: bytes) -> dict:
    """Deserialize manifest JSON bytes."""

    payload = json.loads(blob.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest payload must be an object")
    return payload


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
    rows = payload.get(row_key, [])
    if not isinstance(rows, list):
        raise ValueError(f"{row_key} must be a list")
    validate_entry_count(len(rows), row_key)
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{row_key}[{index}] must be an object")
        writer.writerow(
            [
                "data",
                validate_entry_name(row["source_name"], f"{row_key}[{index}].source_name"),
                validate_entry_name(row["encrypted_name"], f"{row_key}[{index}].encrypted_name"),
                validate_password_value(row["password"], f"{row_key}[{index}].password", allow_empty=True),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def _validate_manifest_for_serialization(payload: dict) -> None:
    if payload.get("kind") != "manifest":
        raise ValueError("payload is not a manifest")
    require_bounded_string(payload.get("mode"), "manifest.mode", MAX_MODE_CHARS)
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("manifest entries must be a list")
    validate_entry_count(len(entries), "manifest")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest.entries[{index}] must be an object")
        validate_entry_name(entry.get("encrypted_name"), f"manifest.entries[{index}].encrypted_name")


def _deserialize_tabular_payload(blob: bytes) -> tuple[dict[str, str], list[dict[str, str]]]:
    reader = csv.reader(io.StringIO(blob.decode("utf-8")))
    meta: dict[str, str] = {}
    rows: list[dict[str, str]] = []
    try:
        for row_number, row in enumerate(reader, start=1):
            if not row:
                continue
            if row[0] == "meta":
                _read_meta_row(row, row_number, meta)
            elif row[0] == "data":
                _read_data_row(row, row_number, rows)
            else:
                raise ValueError(f"unsupported CSV row type at line {row_number}: {row[0]!r}")
    except csv.Error as exc:
        raise ValueError("invalid CSV metadata payload") from exc
    return meta, rows


def _read_meta_row(row: list[str], row_number: int, meta: dict[str, str]) -> None:
    if len(row) != 3:
        raise ValueError(f"invalid meta row at line {row_number}")
    key = row[1]
    if key not in _CSV_META_KEYS:
        raise ValueError(f"unsupported meta key at line {row_number}: {key!r}")
    if key in meta:
        raise ValueError(f"duplicate meta key at line {row_number}: {key!r}")
    meta[key] = row[2]


def _read_data_row(row: list[str], row_number: int, rows: list[dict[str, str]]) -> None:
    if row == ["data", "source_name", "encrypted_name", "password"]:
        return
    if len(row) != 4:
        raise ValueError(f"invalid data row at line {row_number}")
    validate_entry_count(len(rows) + 1, "CSV metadata")
    rows.append(
        {
            "source_name": validate_entry_name(row[1], f"data[{len(rows)}].source_name"),
            "encrypted_name": validate_entry_name(row[2], f"data[{len(rows)}].encrypted_name"),
            "password": validate_password_value(row[3], f"data[{len(rows)}].password", allow_empty=True),
        }
    )


def _binding_from_meta(meta: dict[str, str]) -> dict[str, Any]:
    return {
        "batch_id": meta.get("batch_id", ""),
        "file_count": int(meta.get("file_count", "0")),
        "manifest_fingerprint": meta.get("manifest_fingerprint", ""),
    }
