"""Batch binding primitives.

The purpose of this module is to bind manifests, password tables, and templates
to the exact encrypted batch they belong to. This prevents a user from
accidentally or maliciously reusing metadata from a different batch.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path


class BindingValidationError(Exception):
    """Raised when batch binding metadata is missing or does not match."""

    pass


@dataclass(frozen=True)
class BatchBinding:
    """Canonical binding metadata for one encrypted batch."""

    batch_id: str
    file_count: int
    manifest_fingerprint: str

    def as_dict(self) -> dict[str, str | int]:
        """Convert the binding into a JSON/CSV-friendly dictionary shape."""

        return {
            "batch_id": self.batch_id,
            "file_count": self.file_count,
            "manifest_fingerprint": self.manifest_fingerprint,
        }


def canonicalize_names(names: list[str]) -> list[str]:
    """Normalize encrypted entry names into a deterministic path ordering."""

    return sorted(str(Path(name).as_posix()) for name in names)


def build_manifest_fingerprint(names: list[str]) -> str:
    """Compute a deterministic fingerprint over the encrypted entry set."""

    canonical_names = canonicalize_names(names)
    digest = hashlib.sha256()
    for name in canonical_names:
        digest.update(name.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def create_batch_binding(names: list[str], batch_id: str | None = None) -> BatchBinding:
    """Create binding metadata from the encrypted names of one batch."""

    canonical_names = canonicalize_names(names)
    return BatchBinding(
        batch_id=batch_id or str(uuid.uuid4()),
        file_count=len(canonical_names),
        manifest_fingerprint=build_manifest_fingerprint(canonical_names),
    )


def attach_binding(payload: dict, binding: BatchBinding) -> dict:
    """Return a shallow copy of `payload` with binding metadata attached."""

    result = dict(payload)
    result["binding"] = binding.as_dict()
    return result


def extract_binding(payload: dict) -> BatchBinding:
    """Parse binding metadata from a previously attached payload."""

    binding = payload.get("binding")
    if not isinstance(binding, dict):
        raise BindingValidationError("missing binding metadata")
    try:
        batch_id = str(binding["batch_id"])
        file_count = int(binding["file_count"])
        manifest_fingerprint = str(binding["manifest_fingerprint"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BindingValidationError("invalid binding metadata") from exc
    return BatchBinding(
        batch_id=batch_id,
        file_count=file_count,
        manifest_fingerprint=manifest_fingerprint,
    )


def validate_binding(expected: BatchBinding, actual_payload: dict) -> None:
    """Reject payloads whose binding metadata does not match the expected batch."""

    actual = extract_binding(actual_payload)
    if actual.batch_id != expected.batch_id:
        raise BindingValidationError("batch id mismatch")
    if actual.file_count != expected.file_count:
        raise BindingValidationError("file count mismatch")
    if actual.manifest_fingerprint != expected.manifest_fingerprint:
        raise BindingValidationError("manifest fingerprint mismatch")


def serialize_binding_payload(payload: dict) -> bytes:
    """Serialize a payload deterministically for hashing or storage."""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
