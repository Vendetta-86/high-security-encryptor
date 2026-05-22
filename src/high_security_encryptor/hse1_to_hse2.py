"""Explicit HSE1 to HSE2 migration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Any

from .api import decrypt_file_streaming
from .hse1_to_hse2_config import HSE1ToHSE2MigrationConfig
from .hse2_streaming import encrypt_streaming_hse2
from .password_sources import PasswordResolver


@dataclass(frozen=True)
class HSE1ToHSE2MigrationItemResult:
    """Result for one migration item."""

    index: int
    input: str
    output: str
    ok: bool
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "input": self.input,
            "output": self.output,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass(frozen=True)
class HSE1ToHSE2MigrationResult:
    """Aggregate result for an HSE1 to HSE2 migration command."""

    command: str
    items: tuple[HSE1ToHSE2MigrationItemResult, ...]

    @property
    def succeeded(self) -> int:
        return sum(1 for item in self.items if item.ok)

    @property
    def failed(self) -> int:
        return sum(1 for item in self.items if not item.ok)

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "experimental": True,
            "total": len(self.items),
            "succeeded": self.succeeded,
            "failed": self.failed,
            "items": [item.as_dict() for item in self.items],
        }


def migrate_hse1_to_hse2(
    config: HSE1ToHSE2MigrationConfig,
    resolver: PasswordResolver,
) -> HSE1ToHSE2MigrationResult:
    """Migrate configured HSE1 files to explicit HSE2 outputs."""

    results: list[HSE1ToHSE2MigrationItemResult] = []
    for index, item in enumerate(config.items):
        try:
            legacy_password = config.resolve_hse1_password_for_item(item, resolver, index=index)
            hse2_wrapper = config.resolve_hse2_wrapper_for_item(item, resolver, index=index)
            _migrate_one_item(
                input_path=item.input,
                output_path=item.output,
                legacy_password=legacy_password,
                hse2_wrapper=hse2_wrapper,
                kdf_profile=config.kdf_profile,
                chunk_size=config.chunk_size,
            )
            results.append(
                HSE1ToHSE2MigrationItemResult(
                    index=index,
                    input=item.input,
                    output=item.output,
                    ok=True,
                )
            )
        except Exception as exc:  # noqa: BLE001 - migration summary intentionally captures per-item failures.
            results.append(
                HSE1ToHSE2MigrationItemResult(
                    index=index,
                    input=item.input,
                    output=item.output,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            if not config.continue_on_error:
                break
    return HSE1ToHSE2MigrationResult(command="hse1-to-hse2", items=tuple(results))


def _migrate_one_item(
    *,
    input_path: str,
    output_path: str,
    legacy_password: str,
    hse2_wrapper: str,
    kdf_profile: str,
    chunk_size: int,
) -> None:
    source = Path(input_path)
    target = Path(output_path)
    if not source.is_file():
        raise FileNotFoundError(source)
    with tempfile.TemporaryDirectory(prefix="hse1-to-hse2-") as temp_dir:
        plain_path = Path(temp_dir) / "plaintext.bin"
        decrypt_file_streaming(source, plain_path, legacy_password)
        encrypt_streaming_hse2(
            plain_path,
            target,
            hse2_wrapper,
            kdf_profile_name=kdf_profile,
            chunk_size=chunk_size,
        )
