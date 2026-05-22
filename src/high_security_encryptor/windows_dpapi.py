"""Windows DPAPI helpers for local user-bound secret material."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import Any

DPAPI_WRAPPER_PREFIX = "hse-dpapi-v1:"
DEFAULT_DPAPI_LABEL = "high-security-encryptor"


class DPAPIError(Exception):
    """Raised when Windows DPAPI protection or unprotection fails."""


@dataclass(frozen=True)
class DPAPIProtectResult:
    """Result for a DPAPI protection operation."""

    output: str
    input_size_bytes: int
    output_size_bytes: int
    scope: str
    overwritten: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": "dpapi-protect",
            "output": self.output,
            "input_size_bytes": self.input_size_bytes,
            "output_size_bytes": self.output_size_bytes,
            "scope": self.scope,
            "overwritten": self.overwritten,
        }


def protect_file_with_dpapi(
    input_path: str | Path,
    output_path: str | Path,
    *,
    scope: str = "current_user",
    force: bool = False,
) -> DPAPIProtectResult:
    """Protect a local binary file with Windows DPAPI and write a portable blob file."""

    _ensure_windows()
    _validate_scope(scope)
    source = Path(input_path)
    target = Path(output_path)
    if not source.is_file():
        raise FileNotFoundError(source)
    already_exists = target.exists()
    if already_exists and not force:
        raise FileExistsError(f"DPAPI output already exists: {target}")
    plaintext = source.read_bytes()
    protected = protect_bytes(plaintext, scope=scope)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DPAPI_WRAPPER_PREFIX + base64.urlsafe_b64encode(protected).decode("ascii"), encoding="utf-8")
    return DPAPIProtectResult(
        output=str(target),
        input_size_bytes=len(plaintext),
        output_size_bytes=target.stat().st_size,
        scope=scope,
        overwritten=already_exists,
    )


def unprotect_dpapi_file(path: str | Path) -> bytes:
    """Read a DPAPI blob file and return unprotected bytes."""

    _ensure_windows()
    raw_value = Path(path).read_text(encoding="utf-8").strip()
    if not raw_value.startswith(DPAPI_WRAPPER_PREFIX):
        raise DPAPIError("DPAPI blob has an unsupported prefix")
    encoded = raw_value[len(DPAPI_WRAPPER_PREFIX) :]
    try:
        protected = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except ValueError as exc:
        raise DPAPIError("DPAPI blob is not valid base64") from exc
    return unprotect_bytes(protected)


def protect_bytes(data: bytes, *, scope: str = "current_user") -> bytes:
    """Protect bytes with Windows DPAPI."""

    _ensure_windows()
    _validate_scope(scope)
    crypt = _load_crypt32()
    kernel = _load_kernel32()
    blob_in = _DATA_BLOB.from_bytes(data)
    blob_out = _DATA_BLOB()
    flags = 0
    if scope == "local_machine":
        flags |= 0x4
    ok = crypt.CryptProtectData(
        _byref(blob_in),
        DEFAULT_DPAPI_LABEL,
        None,
        None,
        None,
        flags,
        _byref(blob_out),
    )
    if not ok:
        raise DPAPIError("CryptProtectData failed")
    try:
        return _blob_to_bytes(blob_out)
    finally:
        kernel.LocalFree(blob_out.pbData)


def unprotect_bytes(data: bytes) -> bytes:
    """Unprotect bytes with Windows DPAPI."""

    _ensure_windows()
    crypt = _load_crypt32()
    kernel = _load_kernel32()
    blob_in = _DATA_BLOB.from_bytes(data)
    blob_out = _DATA_BLOB()
    ok = crypt.CryptUnprotectData(
        _byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        _byref(blob_out),
    )
    if not ok:
        raise DPAPIError("CryptUnprotectData failed")
    try:
        return _blob_to_bytes(blob_out)
    finally:
        kernel.LocalFree(blob_out.pbData)


def is_windows() -> bool:
    return os.name == "nt" and sys.platform == "win32"


def _ensure_windows() -> None:
    if not is_windows():
        raise DPAPIError("Windows DPAPI is only available on Windows")


def _validate_scope(scope: str) -> None:
    if scope not in {"current_user", "local_machine"}:
        raise ValueError("scope must be current_user or local_machine")


def _load_crypt32():
    import ctypes

    crypt = ctypes.windll.crypt32
    crypt.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_wchar_p,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.POINTER(_DATA_BLOB),
    ]
    crypt.CryptProtectData.restype = ctypes.c_bool
    crypt.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.POINTER(_DATA_BLOB),
    ]
    crypt.CryptUnprotectData.restype = ctypes.c_bool
    return crypt


def _load_kernel32():
    import ctypes

    kernel = ctypes.windll.kernel32
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    return kernel


def _byref(value):
    import ctypes

    return ctypes.byref(value)


def _blob_to_bytes(blob) -> bytes:
    import ctypes

    if not blob.pbData or blob.cbData <= 0:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _buffer_from_bytes(data: bytes):
    import ctypes

    return ctypes.create_string_buffer(data, len(data))


class _DATA_BLOB:  # ctypes.Structure assigned after ctypes import to keep non-Windows import cheap.
    pass


def _install_data_blob() -> None:
    import ctypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        @classmethod
        def from_bytes(cls, data: bytes):
            buf = _buffer_from_bytes(data)
            blob = cls(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
            blob._buffer = buf
            return blob

    globals()["_DATA_BLOB"] = DATA_BLOB


_install_data_blob()
