"""Validation-report assembly and filtering for config-only CLI checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import BatchDecryptionConfig, BatchEncryptionConfig
from .validation_rules import (
    Issue,
    collect_decryption_config_report_warnings,
    collect_decryption_config_strict_issues,
    collect_encryption_config_report_warnings,
    collect_encryption_config_strict_issues,
    contains_error_issues,
    raise_for_issues,
)


def build_validation_report(kind: str, config_path: Path, strict: bool) -> dict[str, Any]:
    """Build a structured config validation report."""

    issues: list[Issue] = []
    config: BatchEncryptionConfig | BatchDecryptionConfig | None = None
    security_mode = None
    try:
        if kind == "encrypt":
            config = BatchEncryptionConfig.from_json_file(config_path)
        else:
            config = BatchDecryptionConfig.from_json_file(config_path)
        security_mode = config.security_mode
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        issues.append(
            {
                "code": "config-invalid",
                "message": str(exc),
                "severity": "error",
                "suggestion": "Fix missing or invalid config fields and try again.",
            }
        )

    if config is not None and strict:
        if kind == "encrypt":
            issues.extend(collect_encryption_config_strict_issues(config))
        else:
            issues.extend(collect_decryption_config_strict_issues(config))
    if config is not None:
        if kind == "encrypt":
            issues.extend(collect_encryption_config_report_warnings(config))
        else:
            issues.extend(collect_decryption_config_report_warnings(config))

    return {
        "command": "validate-config",
        "kind": kind,
        "config_path": str(config_path),
        "security_mode": security_mode,
        "strict": strict,
        "report": True,
        "valid": not contains_error_issues(issues),
        "issues": issues,
    }


def parse_issue_code_filter(raw_value: str | None, option_name: str = "--include-codes") -> set[str] | None:
    """Parse a comma-separated issue-code filter option."""

    if raw_value is None:
        return None
    normalized_codes = {
        code.strip()
        for code in raw_value.split(",")
        if code.strip()
    }
    if not normalized_codes:
        raise ValueError(f"{option_name} requires at least one non-empty issue code")
    return normalized_codes


def filter_validation_report(
    summary: dict[str, Any],
    include_codes: set[str] | None,
    exclude_codes: set[str] | None,
) -> dict[str, Any]:
    """Filter report issues by include/exclude rules and recalculate validity."""

    filtered_summary = dict(summary)
    filtered_issues = [
        issue
        for issue in summary.get("issues", [])
        if (include_codes is None or issue.get("code") in include_codes)
        and (exclude_codes is None or issue.get("code") not in exclude_codes)
    ]
    filtered_summary["issues"] = filtered_issues
    filtered_summary["valid"] = not contains_error_issues(filtered_issues)
    return filtered_summary
