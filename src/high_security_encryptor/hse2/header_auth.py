"""Deterministic HSE2 header authentication helpers.

Header authentication covers the canonical header bytes with the auth tag field
excluded. This module performs no file I/O, wrapper unlocking, CLI handling, or
GUI work.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

from .encoding import b64decode_bytes, b64encode_bytes
from .keys import HSE2KeyMaterial
from .models import HSE2Header, HSE2ModelError


_HEADER_AUTH_CONTEXT = b"HSE2:header-auth:v1"


def compute_header_auth_tag(header: HSE2Header, *, mek: HSE2KeyMaterial) -> str:
    """Compute the base64 HMAC-SHA256 tag for an HSE2 header."""

    if mek.purpose != "MEK":
        raise HSE2ModelError("header authentication requires a MEK")
    if header.header_auth_algorithm != "HMAC-SHA256":
        raise HSE2ModelError(f"unsupported header auth algorithm: {header.header_auth_algorithm}")
    mac = hmac.new(mek.as_bytes(), digestmod=sha256)
    mac.update(_HEADER_AUTH_CONTEXT)
    mac.update(header.canonical_bytes(include_auth_tag=False))
    return b64encode_bytes(mac.digest())


def attach_header_auth_tag(header: HSE2Header, *, mek: HSE2KeyMaterial) -> HSE2Header:
    """Return a copy of header with a freshly computed header auth tag."""

    tag = compute_header_auth_tag(header, mek=mek)
    return HSE2Header(
        created_utc=header.created_utc,
        cipher_suite=header.cipher_suite,
        manifest_policy=header.manifest_policy,
        payload_layout=header.payload_layout,
        wrappers=header.wrappers,
        format=header.format,
        format_version=header.format_version,
        header_auth_algorithm=header.header_auth_algorithm,
        header_auth_tag=tag,
    )


def verify_header_auth_tag(header: HSE2Header, *, mek: HSE2KeyMaterial) -> bool:
    """Return whether the header auth tag matches the current header fields."""

    if header.header_auth_tag is None:
        raise HSE2ModelError("header auth tag is missing")
    expected = b64decode_bytes(compute_header_auth_tag(header, mek=mek), field_name="computed header auth tag")
    actual = b64decode_bytes(header.header_auth_tag, field_name="header auth tag")
    return hmac.compare_digest(expected, actual)


def require_valid_header_auth_tag(header: HSE2Header, *, mek: HSE2KeyMaterial) -> None:
    """Raise if the header auth tag does not match the current header fields."""

    if not verify_header_auth_tag(header, mek=mek):
        raise HSE2ModelError("header authentication failed")
