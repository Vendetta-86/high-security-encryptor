"""Experimental HSE2 batch rewrap workflow helper."""

from __future__ import annotations

from .hse2_batch import HSE2BatchItemResult, HSE2BatchResult
from .hse2_batch_config import HSE2BatchRewrapConfig
from .hse2_rewrap import rewrap_hse2_file
from .password_sources import PasswordResolver


def rewrap_hse2_batch(config: HSE2BatchRewrapConfig, resolver: PasswordResolver) -> HSE2BatchResult:
    """Process each item in an explicit HSE2 batch rewrap config."""

    results: list[HSE2BatchItemResult] = []
    for index, item in enumerate(config.items):
        try:
            current_value = config.resolve_old_wrapper_for_item(item, resolver, index=index)
            replacement_value = config.resolve_new_wrapper_for_item(item, resolver, index=index)
            output = rewrap_hse2_file(
                item.input,
                item.output,
                current_value,
                replacement_value,
                new_kdf_profile_name=config.new_kdf_profile,
            )
            results.append(HSE2BatchItemResult(index=index, input=item.input, output=str(output), ok=True))
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
    return HSE2BatchResult(command="hse2-batch-rewrap", items=tuple(results))
