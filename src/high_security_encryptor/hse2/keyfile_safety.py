"""Safety checks for HSE2 keyfile storage locations."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


KEYFILE_COLOCATION_WARNING = (
    "keyfile and HSE2 container share a directory; store the keyfile in a separate secure location "
    "so copying the archive directory does not copy both factors"
)


def keyfile_colocation_warning(
    keyfile_paths: Iterable[str | os.PathLike[str] | None],
    container_paths: Iterable[str | os.PathLike[str]],
) -> str | None:
    """Return a warning when any supplied keyfile shares a directory with an archive."""

    containers = {_normalized_parent(path) for path in container_paths}
    for keyfile_path in keyfile_paths:
        if keyfile_path is None or not str(keyfile_path).strip():
            continue
        if _normalized_parent(keyfile_path) in containers:
            return KEYFILE_COLOCATION_WARNING
    return None


def _normalized_parent(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(str(Path(path).resolve(strict=False).parent))
