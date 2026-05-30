"""Windows DPAPI byte protection primitives for HSE2.

This module is intentionally small and platform-bound. It only protects and
unprotects caller-supplied bytes with the current Windows user context. It does
not perform file I/O, CLI prompting, GUI work, or wrapper-record construction.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys

from .models import HSE2ModelError


CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def is_dpapi_available() -> bool:
    """Return whether Windows DPAPI calls are available in this process."""

    return sys.platform == "win32"


def _require_dpapi() -> None:
    if not is_dpapi_available():
        raise HSE2ModelError("Windows DPAPI is only available on Windows")


def _blob_from_bytes(value: bytes) -> tuple[DATA_BLOB, ctypes.Array[ctypes.c_ubyte]]:
    if not isinstance(value, bytes):
        raise HSE2ModelError("DPAPI input must be bytes")
    if not value:
        raise HSE2ModelError("DPAPI input must not be empty")
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return DATA_BLOB(len(value), buffer), buffer


def _optional_blob(value: bytes | None) -> tuple[DATA_BLOB | None, object | None]:
    if value is None:
        return None, None
    blob, buffer = _blob_from_bytes(value)
    return blob, buffer


def _bytes_from_blob(blob: DATA_BLOB) -> bytes:
    if not blob.pbData or blob.cbData == 0:
        raise HSE2ModelError("DPAPI returned an empty blob")
    return ctypes.string_at(blob.pbData, blob.cbData)


def dpapi_protect_bytes(data: bytes, *, entropy: bytes | None = None, description: str = "HSE2") -> bytes:
    """Protect bytes with the current Windows user's DPAPI context."""

    _require_dpapi()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    data_blob, data_buffer = _blob_from_bytes(data)
    entropy_blob, entropy_buffer = _optional_blob(entropy)
    output_blob = DATA_BLOB()
    entropy_arg = ctypes.byref(entropy_blob) if entropy_blob is not None else None
    ok = crypt32.CryptProtectData(
        ctypes.byref(data_blob),
        description,
        entropy_arg,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    )
    _ = data_buffer, entropy_buffer
    if not ok:
        raise HSE2ModelError("DPAPI protection failed")
    try:
        return _bytes_from_blob(output_blob)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def dpapi_unprotect_bytes(protected_data: bytes, *, entropy: bytes | None = None) -> bytes:
    """Unprotect bytes with the current Windows user's DPAPI context."""

    _require_dpapi()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    data_blob, data_buffer = _blob_from_bytes(protected_data)
    entropy_blob, entropy_buffer = _optional_blob(entropy)
    output_blob = DATA_BLOB()
    entropy_arg = ctypes.byref(entropy_blob) if entropy_blob is not None else None
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(data_blob),
        None,
        entropy_arg,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    )
    _ = data_buffer, entropy_buffer
    if not ok:
        raise HSE2ModelError("DPAPI unprotection failed")
    try:
        return _bytes_from_blob(output_blob)
    finally:
        kernel32.LocalFree(output_blob.pbData)
