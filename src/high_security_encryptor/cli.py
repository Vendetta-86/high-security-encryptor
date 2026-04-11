"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import traceback
from typing import Any

from .batch_decryption import decrypt_batch_files
from .batch_workflow import encrypt_batch_files
from .config import BatchDecryptionConfig, BatchEncryptionConfig
from .integrity import IntegrityValidationError
from .password_sources import PasswordSourceError, create_default_password_resolver
from .runtime_password_plan import RuntimePasswordPlan
from .security_mode import (
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    SECURITY_MODE_NO_PASSWORD_TABLES,
    SecurityModeProfile,
    get_security_mode_profile,
)
from .streaming_format import IntegrityError


EXIT_RUNTIME_ERROR = 1
EXIT_VALIDATION_ISSUES = 2
EXIT_CONFIG_ERROR = 3
EXIT_PASSWORD_SOURCE_ERROR = 4
EXIT_INTEGRITY_ERROR = 5


class CliConfigError(Exception):
    """Raised when CLI input or config files are invalid before workflow execution."""


def build_parser() -> argparse.ArgumentParser:
    """创建顶层命令行解析器。"""

    parser = argparse.ArgumentParser(prog="high-security-encryptor")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print Python tracebacks for CLI errors.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt-batch",
        help="Encrypt a mixed batch of files and folders from a JSON config file.",
    )
    encrypt_parser.add_argument("--config", required=True, help="Path to a JSON batch-encryption config file.")
    encrypt_parser.set_defaults(handler=_handle_encrypt_batch)

    decrypt_parser = subparsers.add_parser(
        "decrypt-batch",
        help="Decrypt a mixed batch of files and folders from a JSON config file.",
    )
    decrypt_parser.add_argument("--config", required=True, help="Path to a JSON batch-decryption config file.")
    decrypt_parser.set_defaults(handler=_handle_decrypt_batch)

    validate_parser = subparsers.add_parser(
        "validate-config",
        help="Validate an encryption or decryption JSON config without executing the workflow.",
    )
    validate_parser.add_argument(
        "--kind",
        required=True,
        choices=["encrypt", "decrypt"],
        help="Whether the config should be validated as an encryption or decryption config.",
    )
    validate_parser.add_argument(
        "--config",
        required=True,
        help="Path to the JSON config file to validate.",
    )
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply stricter opinionated validation rules on top of schema checks.",
    )
    validate_parser.add_argument(
        "--report",
        action="store_true",
        help="Return a structured validation report instead of failing fast on the first issue.",
    )
    validate_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format for --report. Defaults to json.",
    )
    validate_parser.add_argument(
        "--exit-code-on-issues",
        action="store_true",
        help="Return exit code 2 when --report finds validation issues.",
    )
    validate_parser.add_argument(
        "--warnings-as-errors",
        action="store_true",
        help="Treat warning issues as CI-failing issues when combined with --report.",
    )
    validate_parser.add_argument(
        "--output",
        required=False,
        help="Optional path used to persist the validation report content.",
    )
    validate_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only a compact report summary to stdout while keeping full report data for --output.",
    )
    validate_parser.add_argument(
        "--include-codes",
        required=False,
        help="Comma-separated issue codes to keep in the report and exit-code evaluation.",
    )
    validate_parser.add_argument(
        "--exclude-codes",
        required=False,
        help="Comma-separated issue codes to remove from the report and exit-code evaluation.",
    )
    validate_parser.set_defaults(handler=_handle_validate_config)

    init_example_parser = subparsers.add_parser(
        "init-example",
        help="Export an example JSON config for a chosen security mode.",
    )
    init_example_parser.add_argument(
        "--mode",
        required=True,
        choices=[
            SECURITY_MODE_COMPATIBLE,
            SECURITY_MODE_HARDENED,
            SECURITY_MODE_NO_PASSWORD_TABLES,
        ],
        help="Security mode used to pick the example template.",
    )
    init_example_parser.add_argument(
        "--kind",
        required=True,
        choices=["encrypt", "decrypt"],
        help="Whether to export an encryption or decryption example.",
    )
    init_example_parser.add_argument(
        "--output",
        required=False,
        help="Path of the JSON file to be written.",
    )
    init_example_parser.add_argument(
        "--print",
        action="store_true",
        dest="print_to_stdout",
        help="Print the example JSON to stdout instead of writing a file.",
    )
    init_example_parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Override an existing JSON field using a dotted path before export.",
    )
    init_example_parser.add_argument(
        "--set-file",
        action="append",
        default=[],
        metavar="KEY=@PATH",
        help="Override an existing JSON field from a JSON file before export.",
    )
    init_example_parser.set_defaults(handler=_handle_init_example)

    return parser


def main(argv: list[str] | None = None) -> int:
    """运行命令行入口并返回退出码。"""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        summary = args.handler(args)
    except Exception as exc:  # noqa: BLE001 - CLI boundary intentionally normalizes failures.
        return _handle_cli_exception(args, exc)
    exit_code_summary = summary
    if isinstance(summary, dict) and "__raw_stdout__" in summary:
        print(summary.pop("__raw_stdout__"))
        print("###SUMMARY###")
    output_summary = summary.pop("__summary_payload__", summary) if isinstance(summary, dict) else summary
    print(json.dumps(output_summary, ensure_ascii=False, indent=2, sort_keys=True))
    if _should_return_issue_exit_code(args, exit_code_summary):
        return EXIT_VALIDATION_ISSUES
    return 0


def _load_config_file(path: str | Path, loader: Any, kind: str) -> Any:
    """Load a config file and normalize file/JSON/schema failures for CLI output."""

    config_path = Path(path)
    if not config_path.is_file():
        raise CliConfigError(f"{kind} config file not found: {config_path}")
    try:
        return loader(config_path)
    except json.JSONDecodeError as exc:
        raise CliConfigError(
            f"{kind} config is not valid JSON: {config_path} "
            f"(line {exc.lineno}, column {exc.colno})"
        ) from exc
    except OSError as exc:
        raise CliConfigError(f"{kind} config could not be read: {config_path}") from exc
    except ValueError as exc:
        raise CliConfigError(f"{kind} config is invalid: {exc}") from exc


def _handle_cli_exception(args: argparse.Namespace, exc: Exception) -> int:
    """Print a concise CLI error by default and return a stable exit code."""

    if _is_debug_enabled(args):
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
    else:
        print(f"error: {_format_exception_message(exc)}", file=sys.stderr)
    return _classify_cli_exception(exc)


def _is_debug_enabled(args: argparse.Namespace) -> bool:
    """Return whether CLI errors should include tracebacks."""

    return bool(getattr(args, "debug", False) or os.environ.get("HSE_DEBUG") == "1")


def _format_exception_message(exc: Exception) -> str:
    """Render exceptions without Python traceback noise."""

    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    message = str(exc)
    return message if message else exc.__class__.__name__


def _classify_cli_exception(exc: Exception) -> int:
    """Map known failure classes to stable CLI exit codes."""

    if isinstance(exc, PasswordSourceError):
        return EXIT_PASSWORD_SOURCE_ERROR
    if isinstance(exc, (IntegrityError, IntegrityValidationError)):
        return EXIT_INTEGRITY_ERROR
    if isinstance(exc, (CliConfigError, json.JSONDecodeError, ValueError)):
        return EXIT_CONFIG_ERROR
    return EXIT_RUNTIME_ERROR


def _handle_encrypt_batch(args: argparse.Namespace) -> dict[str, Any]:
    """执行 `encrypt-batch` 命令并返回可序列化摘要。"""

    config = _load_config_file(args.config, BatchEncryptionConfig.from_json_file, "encryption")
    resolver = create_default_password_resolver()
    result = encrypt_batch_files(
        sources=config.sources,
        passwords_by_source=config.build_workflow_password_mapping(resolver),
        metadata_password=config.resolve_metadata_password(resolver),
        output_dir=config.output_dir,
        batch_id=config.batch_id,
        individually_encrypted_files_by_folder=config.individually_encrypted_files_by_folder,
        write_password_table=config.write_password_table,
        write_internal_password_tables=config.write_internal_password_tables,
    )
    return {
        "command": "encrypt-batch",
        "security_mode": config.security_mode,
        "binding": result.binding.as_dict(),
        "encrypted_files": [str(path) for path in result.encrypted_files],
        "folder_packages": [
            {
                "package_path": str(folder_package.package_path),
                "internal_encrypted_files": list(folder_package.internal_encrypted_files),
                "internal_binding": (
                    folder_package.internal_binding.as_dict() if folder_package.internal_binding is not None else None
                ),
                "internal_manifest_relative_path": folder_package.internal_manifest_relative_path,
                "internal_password_table_relative_path": folder_package.internal_password_table_relative_path,
                "internal_template_relative_path": folder_package.internal_template_relative_path,
            }
            for folder_package in result.folder_packages
        ],
        "manifest_path": str(result.manifest_path),
        "password_table_path": str(result.password_table_path) if result.password_table_path is not None else None,
        "template_path": str(result.template_path),
    }


def _handle_decrypt_batch(args: argparse.Namespace) -> dict[str, Any]:
    """执行 `decrypt-batch` 命令并返回可序列化摘要。"""

    config = _load_config_file(args.config, BatchDecryptionConfig.from_json_file, "decryption")
    resolver = create_default_password_resolver()
    result = decrypt_batch_files(
        encrypted_files=config.encrypted_files,
        manifest_path=config.manifest_path,
        password_table_path=config.password_table_path,
        template_path=config.template_path,
        metadata_password=config.resolve_metadata_password(resolver),
        output_dir=config.output_dir,
        passwords_by_encrypted_name=config.resolve_top_level_password_overrides(resolver),
        runtime_password_plan=RuntimePasswordPlan(
            by_encrypted_name=config.resolve_template_passwords_by_encrypted_name(resolver),
            by_source_name=config.resolve_template_passwords_by_source_name(resolver),
        )
        if config.template_passwords_by_encrypted_name or config.template_passwords_by_source_name
        else None,
        password_resolver=resolver,
        auto_decrypt_folder_inner_files=config.auto_decrypt_folder_inner_files,
        folder_inner_password_overrides=config.resolve_folder_inner_password_overrides(resolver),
        folder_internal_runtime_password_plans={
            package_name: RuntimePasswordPlan(
                by_encrypted_name=package_plan.get("by_encrypted_name", {}),
                by_source_name=package_plan.get("by_source_name", {}),
            )
            for package_name, package_plan in config.resolve_folder_template_runtime_plans(resolver).items()
        },
    )
    return {
        "command": "decrypt-batch",
        "security_mode": config.security_mode,
        "binding": result.binding.as_dict(),
        "top_level_entry_comparison": {
            "expected_entries": result.top_level_entry_comparison.expected_entries,
            "actual_entries": result.top_level_entry_comparison.actual_entries,
            "missing_entries": result.top_level_entry_comparison.missing_entries,
            "extra_entries": result.top_level_entry_comparison.extra_entries,
            "duplicate_entries": result.top_level_entry_comparison.duplicate_entries,
        },
        "decrypted_files": [
            {
                "encrypted_path": str(entry.encrypted_path),
                "decrypted_path": str(entry.decrypted_path),
            }
            for entry in result.decrypted_files
        ],
        "decrypted_folder_packages": [
            {
                "package_path": str(folder_result.package_path),
                "extracted_root": str(folder_result.extracted_root),
                "discovered_binding": (
                    folder_result.discovered_binding.as_dict() if folder_result.discovered_binding is not None else None
                ),
                "internal_manifest_path": str(folder_result.internal_manifest_path)
                if folder_result.internal_manifest_path is not None
                else None,
                "internal_password_table_path": str(folder_result.internal_password_table_path)
                if folder_result.internal_password_table_path is not None
                else None,
                "internal_template_path": str(folder_result.internal_template_path)
                if folder_result.internal_template_path is not None
                else None,
                "internal_entry_comparison": (
                    {
                        "expected_entries": folder_result.internal_entry_comparison.expected_entries,
                        "actual_entries": folder_result.internal_entry_comparison.actual_entries,
                        "missing_entries": folder_result.internal_entry_comparison.missing_entries,
                        "extra_entries": folder_result.internal_entry_comparison.extra_entries,
                        "duplicate_entries": folder_result.internal_entry_comparison.duplicate_entries,
                    }
                    if folder_result.internal_entry_comparison is not None
                    else None
                ),
                "decrypted_inner_files": [
                    {
                        "encrypted_relative_path": item.encrypted_relative_path,
                        "decrypted_relative_path": item.decrypted_relative_path,
                        "decrypted_path": str(item.decrypted_path),
                    }
                    for item in folder_result.decrypted_inner_files
                ],
            }
            for folder_result in result.decrypted_folder_packages
        ],
    }


def _handle_init_example(args: argparse.Namespace) -> dict[str, Any]:
    """导出指定安全模式和用途的示例配置文件。"""

    example_path = _get_example_template_path(args.mode, args.kind)
    example_payload = json.loads(example_path.read_text(encoding="utf-8"))
    applied_overrides = _apply_example_overrides(example_payload, args.set, args.set_file)
    example_text = json.dumps(example_payload, ensure_ascii=False, indent=2)
    summary = {
        "command": "init-example",
        "security_mode": args.mode,
        "kind": args.kind,
        "source_example": str(example_path),
        "output_path": None,
        "applied_overrides": applied_overrides,
    }
    if args.print_to_stdout:
        summary["__raw_stdout__"] = example_text
        return summary
    if not args.output:
        raise ValueError("--output is required unless --print is used")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(example_text, encoding="utf-8")
    summary["output_path"] = str(output_path)
    return summary


def _handle_validate_config(args: argparse.Namespace) -> dict[str, Any]:
    """只校验配置文件，不执行加解密。"""

    config_path = Path(args.config)
    if not config_path.is_file():
        raise CliConfigError(f"config file not found: {config_path}")
    if args.report:
        summary = _build_validation_report(
            kind=args.kind,
            config_path=config_path,
            strict=bool(args.strict),
        )
        include_codes = _parse_issue_code_filter(args.include_codes)
        exclude_codes = _parse_issue_code_filter(args.exclude_codes, option_name="--exclude-codes")
        summary = _filter_validation_report(summary, include_codes=include_codes, exclude_codes=exclude_codes)
        summary["format"] = args.format
        summary["exit_code_on_issues"] = bool(args.exit_code_on_issues)
        summary["warnings_as_errors"] = bool(args.warnings_as_errors)
        summary["output_path"] = str(args.output) if args.output else None
        summary["summary_only"] = bool(args.summary_only)
        summary["included_codes"] = sorted(include_codes) if include_codes is not None else None
        summary["excluded_codes"] = sorted(exclude_codes) if exclude_codes is not None else None
        if args.format == "text":
            if args.summary_only:
                summary["__raw_stdout__"] = _render_validation_report_summary_text(summary)
            else:
                summary["__raw_stdout__"] = _render_validation_report_text(summary)
        _maybe_write_validation_report(args=args, summary=summary)
        if args.summary_only:
            summary["__summary_payload__"] = _build_validation_report_summary_payload(summary)
        return summary

    if args.kind == "encrypt":
        config = _load_config_file(config_path, BatchEncryptionConfig.from_json_file, "encryption")
        if args.strict:
            _raise_for_issues(_collect_encryption_config_strict_issues(config))
    else:
        config = _load_config_file(config_path, BatchDecryptionConfig.from_json_file, "decryption")
        if args.strict:
            _raise_for_issues(_collect_decryption_config_strict_issues(config))
    return {
        "command": "validate-config",
        "kind": args.kind,
        "config_path": str(config_path),
        "security_mode": config.security_mode,
        "strict": bool(args.strict),
        "report": False,
        "format": "json",
        "exit_code_on_issues": False,
        "warnings_as_errors": False,
        "output_path": None,
        "summary_only": False,
        "included_codes": None,
        "excluded_codes": None,
        "valid": True,
    }


def _get_example_template_path(mode: str, kind: str) -> Path:
    """定位指定模式和用途对应的示例配置文件。"""

    project_root = Path(__file__).resolve().parents[2]
    file_name = f"{mode.replace('-', '_')}_{kind}.json"
    return project_root / "examples" / file_name


def _apply_example_overrides(
    payload: dict[str, Any],
    override_specs: list[str],
    file_override_specs: list[str],
) -> list[str]:
    """按 `--set` 与 `--set-file` 的形式原地替换示例配置中的现有字段。"""

    applied_overrides: list[str] = []
    for override_spec in override_specs:
        key_path, raw_value = _split_override_spec(override_spec)
        parsed_value = _parse_override_value(raw_value)
        _set_existing_path_value(payload, key_path.split("."), parsed_value)
        applied_overrides.append(key_path)
    for file_override_spec in file_override_specs:
        key_path, file_path = _split_override_spec(file_override_spec)
        parsed_value = _load_override_value_from_file(file_path)
        _set_existing_path_value(payload, key_path.split("."), parsed_value)
        applied_overrides.append(f"{key_path}@file")
    return applied_overrides


def _split_override_spec(override_spec: str) -> tuple[str, str]:
    """拆分单条 `KEY=VALUE` 覆盖表达式。"""

    if "=" not in override_spec:
        raise ValueError(f"invalid override {override_spec!r}: expected KEY=VALUE")
    key_path, raw_value = override_spec.split("=", 1)
    normalized_key_path = key_path.strip()
    if not normalized_key_path:
        raise ValueError(f"invalid override {override_spec!r}: key path is empty")
    return normalized_key_path, raw_value


def _parse_override_value(raw_value: str) -> Any:
    """把覆盖值优先解析为 JSON 字面量，失败时保留原始字符串。"""

    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value


def _load_override_value_from_file(file_path: str) -> Any:
    """从 JSON 文件加载覆盖值。"""

    normalized_file_path = file_path[1:] if file_path.startswith("@") else file_path
    override_path = Path(normalized_file_path)
    return json.loads(override_path.read_text(encoding="utf-8"))


def _set_existing_path_value(container: Any, path_parts: list[str], value: Any) -> None:
    """按点路径覆盖字典或列表里的已有字段。"""

    current = container
    for index, part in enumerate(path_parts):
        is_last = index == len(path_parts) - 1
        if isinstance(current, dict):
            if part not in current:
                raise ValueError(f"unknown override path: {'.'.join(path_parts)}")
            if is_last:
                current[part] = value
                return
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                numeric_index = int(part)
            except ValueError as exc:
                raise ValueError(f"list override path requires a numeric index: {'.'.join(path_parts)}") from exc
            if numeric_index < 0 or numeric_index >= len(current):
                raise ValueError(f"list override index out of range: {'.'.join(path_parts)}")
            if is_last:
                current[numeric_index] = value
                return
            current = current[numeric_index]
            continue
        raise ValueError(f"cannot traverse scalar value at path: {'.'.join(path_parts)}")
    raise ValueError(f"invalid override path: {'.'.join(path_parts)}")


def _build_validation_report(kind: str, config_path: Path, strict: bool) -> dict[str, Any]:
    """构建结构化配置校验报告。"""

    issues: list[dict[str, str]] = []
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
                "suggestion": "修正配置中缺失或不合法的字段后再重试。",
            }
        )

    if config is not None and strict:
        if kind == "encrypt":
            issues.extend(_collect_encryption_config_strict_issues(config))
        else:
            issues.extend(_collect_decryption_config_strict_issues(config))
    if config is not None:
        if kind == "encrypt":
            issues.extend(_collect_encryption_config_report_warnings(config))
        else:
            issues.extend(_collect_decryption_config_report_warnings(config))

    return {
        "command": "validate-config",
        "kind": kind,
        "config_path": str(config_path),
        "security_mode": security_mode,
        "strict": strict,
        "report": True,
        "valid": not _contains_error_issues(issues),
        "issues": issues,
    }


def _collect_encryption_config_report_warnings(config: BatchEncryptionConfig) -> list[dict[str, str]]:
    """收集常规报告模式下的加密配置警告。"""

    issues: list[dict[str, str]] = []
    if config.write_password_table:
        issues.append(
            {
                "code": "top-level-password-table-enabled",
                "message": "top-level password table generation is enabled",
                "severity": "warning",
                "suggestion": "如果处理高价值数据，考虑改用 hardened 或 no-password-tables 模式。",
            }
        )
    return issues


def _collect_decryption_config_report_warnings(config: BatchDecryptionConfig) -> list[dict[str, str]]:
    """收集常规报告模式下的解密配置警告。"""

    issues: list[dict[str, str]] = []
    if config.password_table_path is not None and config.security_mode == SECURITY_MODE_COMPATIBLE:
        issues.append(
            {
                "code": "top-level-password-table-consumed",
                "message": "top-level password table will be consumed during decryption",
                "severity": "warning",
                "suggestion": "如果希望减少密码长期落盘，可改用模板加运行时 provider。",
            }
        )
    return issues


def _collect_encryption_config_strict_issues(config: BatchEncryptionConfig) -> list[dict[str, str]]:
    """收集比默认模式更保守的加密配置问题。"""

    profile = get_security_mode_profile(config.security_mode)
    issues: list[dict[str, str]] = []
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


def _collect_decryption_config_strict_issues(config: BatchDecryptionConfig) -> list[dict[str, str]]:
    """收集比默认模式更保守的解密配置问题。"""

    profile = get_security_mode_profile(config.security_mode)
    issues: list[dict[str, str]] = []
    if profile.write_password_table:
        if config.password_table_path is None:
            issues.append(
                {
                    "code": "missing-password-table",
                    "message": f"strict mode requires password_table_path for security_mode={config.security_mode!r}",
                    "severity": "error",
                    "suggestion": "提供顶层 password_table_path，或改用不依赖密码表的安全模式。",
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
                "suggestion": "把顶层运行时密码改写到 template_passwords_by_encrypted_name 或 "
                "template_passwords_by_source_name。",
            }
        )
    if not config.template_passwords_by_encrypted_name and not config.template_passwords_by_source_name:
        issues.append(
            {
                "code": "missing-template-runtime-passwords",
                "message": "strict mode requires template runtime password mappings when password tables are disabled",
                "severity": "error",
                "suggestion": "提供 template_passwords_by_encrypted_name 或 template_passwords_by_source_name。",
            }
        )
    return issues


def _append_flag_mismatch_issue(
    *,
    issues: list[dict[str, str]],
    field_name: str,
    actual_value: bool,
    profile: SecurityModeProfile,
    expected_value: bool,
) -> None:
    """在布尔开关与命名安全模式默认策略不一致时追加问题。"""

    if actual_value != expected_value:
        issues.append(
            {
                "code": "security-mode-override-conflict",
                "message": f"strict mode requires {field_name}={expected_value!r} for security_mode={profile.name!r}",
                "severity": "error",
                "suggestion": f"移除显式 {field_name}，或把它调整为 {expected_value!r}。",
            }
        )


def _raise_for_issues(issues: list[dict[str, str]]) -> None:
    """在存在问题时抛出第一个问题，保持非 report 模式的失败快路径。"""

    if issues:
        raise ValueError(issues[0]["message"])


def _contains_error_issues(issues: list[dict[str, str]]) -> bool:
    """判断问题列表中是否包含 error 级别的问题。"""

    return any(issue.get("severity") == "error" for issue in issues)


def _parse_issue_code_filter(raw_value: str | None, option_name: str = "--include-codes") -> set[str] | None:
    """把逗号分隔的问题码过滤参数解析为集合。"""

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


def _filter_validation_report(
    summary: dict[str, Any],
    include_codes: set[str] | None,
    exclude_codes: set[str] | None,
) -> dict[str, Any]:
    """按 include/exclude 规则过滤校验报告，并重新计算有效性。"""

    filtered_summary = dict(summary)
    filtered_issues = [
        issue
        for issue in summary.get("issues", [])
        if (include_codes is None or issue.get("code") in include_codes)
        and (exclude_codes is None or issue.get("code") not in exclude_codes)
    ]
    filtered_summary["issues"] = filtered_issues
    filtered_summary["valid"] = not _contains_error_issues(filtered_issues)
    return filtered_summary


def _render_validation_report_text(summary: dict[str, Any]) -> str:
    """把结构化校验报告渲染成适合终端阅读的文本。"""

    lines = [
        "配置校验报告",
        f"kind: {summary['kind']}",
        f"config: {summary['config_path']}",
        f"security_mode: {summary['security_mode']}",
        f"strict: {summary['strict']}",
        f"valid: {summary['valid']}",
    ]
    issues = summary.get("issues", [])
    if not issues:
        lines.append("issues: none")
        return "\n".join(lines)

    lines.append(f"issues: {len(issues)}")
    for index, issue in enumerate(issues, start=1):
        lines.append(f"{index}. [{issue['severity']}] {issue['code']}")
        lines.append(f"   message: {issue['message']}")
        lines.append(f"   suggestion: {issue['suggestion']}")
    return "\n".join(lines)


def _render_validation_report_summary_text(summary: dict[str, Any]) -> str:
    """把校验报告渲染成更紧凑的摘要文本。"""

    issues = summary.get("issues", [])
    warning_count = sum(1 for issue in issues if issue.get("severity") == "warning")
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    lines = [
        "配置校验摘要",
        f"kind: {summary['kind']}",
        f"security_mode: {summary['security_mode']}",
        f"valid: {summary['valid']}",
        f"errors: {error_count}",
        f"warnings: {warning_count}",
    ]
    if issues:
        lines.append(f"top_issue: {issues[0]['code']}")
    if summary.get("output_path"):
        lines.append(f"full_report: {summary['output_path']}")
    return "\n".join(lines)


def _build_validation_report_summary_payload(summary: dict[str, Any]) -> dict[str, Any]:
    """构建适合 summary-only 输出的紧凑 JSON 摘要。"""

    issues = summary.get("issues", [])
    warning_count = sum(1 for issue in issues if issue.get("severity") == "warning")
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    return {
        "command": summary["command"],
        "kind": summary["kind"],
        "config_path": summary["config_path"],
        "security_mode": summary["security_mode"],
        "strict": summary["strict"],
        "report": summary["report"],
        "format": summary["format"],
        "summary_only": True,
        "valid": summary["valid"],
        "issue_counts": {
            "error": error_count,
            "warning": warning_count,
            "total": len(issues),
        },
        "top_issue_code": issues[0]["code"] if issues else None,
        "output_path": summary.get("output_path"),
        "exit_code_on_issues": summary.get("exit_code_on_issues", False),
        "warnings_as_errors": summary.get("warnings_as_errors", False),
    }


def _maybe_write_validation_report(args: argparse.Namespace, summary: dict[str, Any]) -> None:
    """在用户提供输出路径时，把报告内容写入文件。"""

    output_path_value = getattr(args, "output", None)
    if not output_path_value:
        return
    output_path = Path(output_path_value)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if summary.get("format") == "text":
        report_text = _render_validation_report_text(summary)
        output_path.write_text(report_text, encoding="utf-8")
        return
    serializable_summary = dict(summary)
    serializable_summary.pop("__raw_stdout__", None)
    output_path.write_text(
        json.dumps(serializable_summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _should_return_issue_exit_code(args: argparse.Namespace, summary: Any) -> bool:
    """判断当前命令是否应在报告存在问题时返回非零退出码。"""

    if not (
        getattr(args, "command", None) == "validate-config"
        and getattr(args, "report", False)
        and getattr(args, "exit_code_on_issues", False)
        and isinstance(summary, dict)
    ):
        return False
    issues = summary.get("issues", [])
    if getattr(args, "warnings_as_errors", False):
        return bool(issues)
    return bool(
        not summary.get("valid", True) or _contains_error_issues(issues)
    )


if __name__ == "__main__":
    raise SystemExit(main())
