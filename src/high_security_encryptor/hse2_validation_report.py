"""Read-only HSE2 validation report workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .hse2_validation import HSE2ValidationReport, validate_hse2_file
from .hse2_validation_config import HSE2ValidationConfig
from .password_sources import PasswordResolver


@dataclass(frozen=True)
class HSE2ValidationBatchReport:
    """Aggregate HSE2 validation report."""

    command: str
    items: tuple[HSE2ValidationReport, ...]

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


def build_hse2_validation_report(
    config: HSE2ValidationConfig,
    resolver: PasswordResolver,
) -> HSE2ValidationBatchReport:
    """Validate each configured HSE2 file and return a JSON-ready report."""

    reports: list[HSE2ValidationReport] = []
    for index, item in enumerate(config.items):
        try:
            wrapper = config.resolve_wrapper_for_item(item, resolver, index=index)
            report = validate_hse2_file(item.input, wrapper)
            reports.append(report)
            if not report.ok and not config.continue_on_error:
                break
        except Exception as exc:  # noqa: BLE001 - validation report intentionally normalizes failures.
            reports.append(
                HSE2ValidationReport(
                    input=item.input,
                    ok=False,
                    header_ok=False,
                    payload_ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            if not config.continue_on_error:
                break
    return HSE2ValidationBatchReport(command="hse2-validate", items=tuple(reports))
