"""Structured payload helpers for batch metadata files.

These helpers define the in-memory and serialized representations for manifests,
password tables, and templates. They are intentionally pure-data helpers so they
can be tested independently from file encryption and UI code.
"""

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
    """One row in a password table artifact."""

    source_name: str
    encrypted_name: str
    password: str

    def as_dict(self) -> dict[str, str]:
        """Convert the record into a serializable dictionary."""

        return {
            "source_name": self.source_name,
            "encrypted_name": self.encrypted_name,
            "password": self.password,
        }


def create_manifest_payload(encrypted_names: list[str], mode: str, batch_id: str | None = None) -> dict:
    """Create a manifest payload and attach binding metadata."""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
    payload = {
        "kind": "manifest",
        "mode": mode,
        "entries": [{"encrypted_name": name} for name in sorted(encrypted_names)],
    }
    return attach_binding(payload, binding)


def validate_manifest_payload(payload: dict, expected_binding: BatchBinding) -> None:
    """Ensure a manifest payload belongs to the expected batch."""

    if payload.get("kind") != "manifest":
        raise BindingValidationError("payload is not a manifest")
    validate_binding(expected_binding, payload)


def serialize_manifest_payload(payload: dict) -> bytes:
    """Serialize a manifest payload into stable JSON bytes."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def deserialize_manifest_payload(blob: bytes) -> dict:
    """Deserialize JSON bytes back into a manifest payload dictionary."""

    return json.loads(blob.decode("utf-8"))


def create_password_table_payload(
    records: list[PasswordRecord],
    encrypted_names: list[str],
    batch_id: str | None = None,
) -> tuple[dict, BatchBinding]:
    """Create a password table payload plus the binding used for it."""

    binding = create_batch_binding(encrypted_names, batch_id=batch_id)
    payload = {
        "kind": "password_table",
        "records": [record.as_dict() for record in records],
    }
    return attach_binding(payload, binding), binding


def validate_password_table_payload(payload: dict, expected_binding: BatchBinding) -> None:
    """Ensure a password table payload belongs to the expected batch."""

    if payload.get("kind") != "password_table":
        raise BindingValidationError("payload is not a password table")
    validate_binding(expected_binding, payload)


def serialize_password_table_payload(payload: dict) -> bytes:
    """Serialize a password table payload into a CSV-based byte stream."""

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
    """Parse a CSV-based password table payload from bytes."""

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
    """Create a bound template payload for later password entry."""

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
    """Ensure a template payload belongs to the expected batch."""

    if payload.get("kind") != "template":
        raise BindingValidationError("payload is not a template")
    validate_binding(expected_binding, payload)


def serialize_template_payload(payload: dict) -> bytes:
    """Serialize a template payload into CSV bytes."""

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
    """Parse a template payload from CSV bytes."""

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
