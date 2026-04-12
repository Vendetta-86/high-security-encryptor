"""Validation issue rules for encryption and decryption configs."""

from __future__ import annotations

from .config import BatchDecryptionConfig, BatchEncryptionConfig
from .security_mode import (
    SECURITY_MODE_COMPATIBLE,
    SecurityModeProfile,
    get_security_mode_profile,
)

Issue = dict[str, str]


def collect_encryption_config_strict_issues(config: BatchEncryptionConfig) -> list[Issue]:
    """Collect strict-mode issues for encryption configs."""

    profile = get_security_mode_profile(config.security_mode)
    issues: list[Issue] = []
    _append_flag_mismatch_issue(
        issues=issues,
        field_name="write_password_table",
        actual_value=config.write_password_table,
        profile=profile,
        expected_value=profile.write_password_table,
    )
    _append_flag_mismatch_issue(
        issues=issues,
        field_name="write_internal_password_tables",
        actual_value=config.write_internal_password_tables,
        profile=profile,
        expected_value=profile.write_internal_password_tables,
    )
    return issues


def collect_decryption_config_strict_issues(config: BatchDecryptionConfig) -> list[Issue]:
    """Collect strict-mode issues for decryption configs."""

    profile = get_security_mode_profile(config.security_mode)
    issues: list[Issue] = []
    if profile.write_password_table:
        if config.password_table_path is None:
            issues.append(
                {
                    "code": "missing-password-table",
                    "message": f"strict mode requires password_table_path for security_mode={config.security_mode!r}",
                    "severity": "error",
                    "suggestion": "Provide top-level password_table_path, or use a security mode that does not rely on password tables.",
                }
            )
        return issues

    if config.passwords_by_encrypted_name:
        issues.append(
            {
                "code": "non-template-runtime-passwords",
                "message": "strict mode requires top-level runtime passwords to come from template mappings, "
                "not passwords_by_encrypted_name",
                "severity": "error",
                "suggestion": "Move top-level runtime passwords into template_passwords_by_encrypted_name or "
                "template_passwords_by_source_name.",
            }
        )
    if not config.template_passwords_by_encrypted_name and not config.template_passwords_by_source_name:
        issues.append(
            {
                "code": "missing-template-runtime-passwords",
                "message": "strict mode requires template runtime password mappings when password tables are disabled",
                "severity": "error",
                "suggestion": "Provide template_passwords_by_encrypted_name or template_passwords_by_source_name.",
            }
        )
    return issues


def collect_encryption_config_report_warnings(config: BatchEncryptionConfig) -> list[Issue]:
    """Collect normal report-mode warnings for encryption configs."""

    issues: list[Issue] = []
    if config.write_password_table:
        issues.append(
            {
                "code": "top-level-password-table-enabled",
                "message": "top-level password table generation is enabled",
                "severity": "warning",
                "suggestion": "For high-value data, consider hardened or no-password-tables mode.",
            }
        )
    return issues


def collect_decryption_config_report_warnings(config: BatchDecryptionConfig) -> list[Issue]:
    """Collect normal report-mode warnings for decryption configs."""

    issues: list[Issue] = []
    if config.password_table_path is not None and config.security_mode == SECURITY_MODE_COMPATIBLE:
        issues.append(
            {
                "code": "top-level-password-table-consumed",
                "message": "top-level password table will be consumed during decryption",
                "severity": "warning",
                "suggestion": "Use templates plus runtime providers when long-term password storage should be minimized.",
            }
        )
    return issues


def raise_for_issues(issues: list[Issue]) -> None:
    """Raise the first issue message for fail-fast non-report mode."""

    if issues:
        raise ValueError(issues[0]["message"])


def contains_error_issues(issues: list[Issue]) -> bool:
    """Return whether the issue list contains at least one error."""

    return any(issue.get("severity") == "error" for issue in issues)


def _append_flag_mismatch_issue(
    *,
    issues: list[Issue],
    field_name: str,
    actual_value: bool,
    profile: SecurityModeProfile,
    expected_value: bool,
) -> None:
    if actual_value != expected_value:
        issues.append(
            {
                "code": "security-mode-override-conflict",
                "message": f"strict mode requires {field_name}={expected_value!r} for security_mode={profile.name!r}",
                "severity": "error",
                "suggestion": f"Remove explicit {field_name}, or set it to {expected_value!r}.",
            }
        )
