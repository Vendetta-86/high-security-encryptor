"""Temporary-directory helpers for workflows that may touch plaintext."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile
from typing import Iterator


SECURE_TEMP_DIR_ENV = "HSE_TEMP_DIR"


@contextmanager
def secure_temporary_directory(prefix: str = "hse-") -> Iterator[Path]:
    """Create a private temporary directory and remove it on exit."""

    parent = _resolve_temp_parent()
    temp_root = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    _restrict_directory(temp_root)
    try:
        yield temp_root
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def make_secure_temporary_directory(prefix: str, parent: str | Path | None = None) -> Path:
    """Create a private temporary directory for callers that manage cleanup."""

    temp_root = Path(tempfile.mkdtemp(prefix=prefix, dir=Path(parent) if parent is not None else _resolve_temp_parent()))
    _restrict_directory(temp_root)
    return temp_root


def _resolve_temp_parent() -> Path | None:
    raw_parent = os.environ.get(SECURE_TEMP_DIR_ENV)
    if not raw_parent:
        return None
    parent = Path(raw_parent)
    parent.mkdir(parents=True, exist_ok=True)
    _restrict_directory(parent)
    if not parent.is_dir():
        raise NotADirectoryError(parent)
    return parent


def _restrict_directory(path: Path) -> None:
    try:
        path.chmod(0o700)
    except OSError:
        return
