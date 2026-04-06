"""Top-level file encryption API.

This module keeps the external entrypoints very small. Callers use these helpers
 without needing to know whether the input file uses the new streaming format or
 the legacy `GCM1` blob layout.
"""

from __future__ import annotations

from pathlib import Path

from .legacy import decrypt_legacy
from .streaming_format import HEADER_MAGIC, decrypt_streaming, encrypt_streaming


def encrypt_file_streaming(source: str | Path, target: str | Path, password: str) -> Path:
    """Encrypt a file into the new streaming container format.

    The function performs lightweight argument validation and then delegates the
    real work to the streaming-format implementation module.
    """

    source_path = Path(source)
    target_path = Path(target)
    if not password:
        raise ValueError("password is required")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    return encrypt_streaming(source_path, target_path, password)


def decrypt_file_streaming(source: str | Path, target: str | Path, password: str) -> Path:
    """Decrypt a file by dispatching on the file magic.

    `HSE1` files are handled by the new streaming reader. Everything else is
    routed into the legacy compatibility path, which currently understands the
    historical `GCM1` format.
    """

    source_path = Path(source)
    target_path = Path(target)
    if not password:
        raise ValueError("password is required")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    with source_path.open("rb") as file_obj:
        magic = file_obj.read(len(HEADER_MAGIC))
    if magic != HEADER_MAGIC:
        return decrypt_legacy(source_path, target_path, password)
    return decrypt_streaming(source_path, target_path, password)
