"""Experimental HSE2 batch workflow helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .hse2_batch_config import HSE2BatchDecryptConfig, HSE2BatchEncryptConfig
from .hse2_streaming import decrypt_streaming_hse2, encrypt_streaming_hse2
from .password_sources import PasswordResolver


@dataclass(frozen=True)
class HSE2BatchItemResult:
    """Result for one HSE2 batch item."""

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
class HSE2BatchResult:
    """Aggregate result for an HSE2 batch command."""

    command: str
    items: tuple[HSE2BatchItemResult, ...]

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


def encrypt_hse2_batch(config: HSE2BatchEncryptConfig, resolver: PasswordResolver) -> HSE2BatchResult:
    """Encrypt each item in an explicit HSE2 batch config."""

    results: list[HSE2BatchItemResult] = []
    for index, item in enumerate(config.items):
        try:
            wrapper = config.resolve_wrapper_for_item(item, resolver, index=index)
            output = encrypt_streaming_hse2(
                item.input,
                item.output,
                wrapper,
                kdf_profile_name=config.kdf_profile,
                chunk_size=config.chunk_size,
            )
            results.append(
                HSE2BatchItemResult(
                    index=index,
                    input=item.input,
                    output=str(output),
                    ok=True,
                )
            )
        except Exception as exc:  # noqa: BLE001 - batch summary intentionally captures per-item failures.
            results.append(
                HSE2BatchItemResult(
                    index=index,
                    input=item.input,
                    output=item.output,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            if not config.continue_on_error:
                break
    return HSE2BatchResult(command="hse2-batch-encrypt", items=tuple(results))


def decrypt_hse2_batch(config: HSE2BatchDecryptConfig, resolver: PasswordResolver) -> HSE2BatchResult:
    """Decrypt each item in an explicit HSE2 batch config."""

    results: list[HSE2BatchItemResult] = []
    for index, item in enumerate(config.items):
        try:
            wrapper = config.resolve_wrapper_for_item(item, resolver, index=index)
            output = decrypt_streaming_hse2(item.input, item.output, wrapper)
            results.append(
                HSE2BatchItemResult(
                    index=index,
                    input=item.input,
                    output=str(output),
                    ok=True,
                )
            )
        except Exception as exc:  # noqa: BLE001 - batch summary intentionally captures per-item failures.
            results.append(
                HSE2BatchItemResult(
                    index=index,
                    input=item.input,
                    output=item.output,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            if not config.continue_on_error:
                break
    return HSE2BatchResult(command="hse2-batch-decrypt", items=tuple(results))
