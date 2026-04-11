"""顶层文件加解密 API。"""

from __future__ import annotations

from pathlib import Path

from .legacy import decrypt_legacy
from .streaming_format import HEADER_MAGIC, decrypt_streaming, encrypt_streaming


def encrypt_file_streaming(source: str | Path, target: str | Path, password: str) -> Path:
    """把文件加密为新的流式容器格式。"""

    source_path = Path(source)
    target_path = Path(target)
    if not password:
        raise ValueError("password is required")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    return encrypt_streaming(source_path, target_path, password)


def decrypt_file_streaming(source: str | Path, target: str | Path, password: str) -> Path:
    """根据文件魔数分流到对应解密路径。"""

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
