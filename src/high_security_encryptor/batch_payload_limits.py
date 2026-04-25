"""Bounds and validators for encrypted batch metadata payloads."""

from __future__ import annotations

MAX_BATCH_ENTRIES = 100_000
MAX_BATCH_ID_CHARS = 256
MAX_ENTRY_NAME_CHARS = 4_096
MAX_MODE_CHARS = 64
MAX_PASSWORD_CHARS = 8_192
MANIFEST_FINGERPRINT_CHARS = 64
MAX_CSV_FIELD_CHARS = max(MAX_ENTRY_NAME_CHARS, MAX_PASSWORD_CHARS)


def validate_entry_count(count: int, context: str) -> None:
    if count < 0:
        raise ValueError(f"{context} count must not be negative")
    if count > MAX_BATCH_ENTRIES:
        raise ValueError(f"{context} contains too many entries")


def require_bounded_string(
    value: object,
    field_name: str,
    max_chars: int,
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > max_chars:
        raise ValueError(f"{field_name} is too long")
    return value


def validate_entry_name(value: object, field_name: str) -> str:
    return require_bounded_string(value, field_name, MAX_ENTRY_NAME_CHARS)


def validate_password_value(value: object, field_name: str, *, allow_empty: bool = False) -> str:
    return require_bounded_string(value, field_name, MAX_PASSWORD_CHARS, allow_empty=allow_empty)


def validate_batch_id(value: object, field_name: str = "binding.batch_id") -> str:
    return require_bounded_string(value, field_name, MAX_BATCH_ID_CHARS)


def validate_manifest_fingerprint(value: object, field_name: str = "binding.manifest_fingerprint") -> str:
    fingerprint = require_bounded_string(value, field_name, MANIFEST_FINGERPRINT_CHARS)
    if len(fingerprint) != MANIFEST_FINGERPRINT_CHARS:
        raise ValueError(f"{field_name} must be a SHA-256 hex digest")
    if any(char not in "0123456789abcdef" for char in fingerprint):
        raise ValueError(f"{field_name} must be a SHA-256 hex digest")
    return fingerprint
