"""Helpers for generating local keyfiles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import secrets
from typing import Any

MIN_GENERATED_KEYFILE_BYTES = 16
DEFAULT_GENERATED_KEYFILE_BYTES = 32
MAX_GENERATED_KEYFILE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class KeyfileGenerationResult:
    """Result for a keyfile generation operation."""

    output: str
    size_bytes: int
    overwritten: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": "generate-keyfile",
            "output": self.output,
            "size_bytes": self.size_bytes,
            "overwritten": self.overwritten,
        }


def generate_keyfile(path: str | Path, *, size_bytes: int = DEFAULT_GENERATED_KEYFILE_BYTES, force: bool = False) -> KeyfileGenerationResult:
    """Generate a cryptographically random local keyfile."""

    _validate_size(size_bytes)
    output_path = Path(path)
    already_exists = output_path.exists()
    if already_exists and not force:
        raise FileExistsError(f"keyfile already exists: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(secrets.token_bytes(size_bytes))
    return KeyfileGenerationResult(output=str(output_path), size_bytes=size_bytes, overwritten=already_exists)


def _validate_size(size_bytes: int) -> None:
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
        raise ValueError("size_bytes must be an integer")
    if size_bytes < MIN_GENERATED_KEYFILE_BYTES:
        raise ValueError(f"size_bytes must be at least {MIN_GENERATED_KEYFILE_BYTES}")
    if size_bytes > MAX_GENERATED_KEYFILE_BYTES:
        raise ValueError(f"size_bytes must be at most {MAX_GENERATED_KEYFILE_BYTES}")
