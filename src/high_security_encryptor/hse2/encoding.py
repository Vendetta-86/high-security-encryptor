"""Encoding helpers for HSE2 JSON-safe metadata."""

from __future__ import annotations

import base64
import binascii

from .models import HSE2ModelError


def b64encode_bytes(value: bytes) -> str:
    """Encode bytes as an ASCII base64 string for HSE2 JSON metadata."""

    if not isinstance(value, bytes):
        raise HSE2ModelError("base64 input must be bytes")
    return base64.b64encode(value).decode("ascii")


def b64decode_bytes(value: str, *, field_name: str = "value") -> bytes:
    """Decode an HSE2 base64 metadata string with strict validation."""

    if not isinstance(value, str):
        raise HSE2ModelError(f"{field_name} must be a base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise HSE2ModelError(f"{field_name} is not valid base64") from exc
