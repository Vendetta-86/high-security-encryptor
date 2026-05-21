"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .batch_bundle_workflow import encrypt_batch_bundle
from .batch_decryption import decrypt_batch_files
from .batch_workflow import encrypt_batch_files
from .brute_force_guard import (
    BruteForceGuard,
    BruteForceGuardConfig,
    build_decryption_subject,
)
from .cli_errors import (
    EXIT_CONFIG_ERROR,
    EXIT_INTEGRITY_ERROR,
    EXIT_PASSWORD_SOURCE_ERROR,
    EXIT_RUNTIME_ERROR,
    EXIT_VALIDATION_ISSUES,
    CliConfigError,
    handle_cli_exception,
)
from .cli_parser import build_cli_parser
from .cli_summaries import (
    summarize_batch_bundle_encryption_result,
    summarize_batch_decryption_result,
    summarize_batch_encryption_result,
)
from .config import BatchDecryptionConfig, BatchEncryptionConfig
from .example_templates import export_example_config
from .hse2_rewrap import rewrap_hse2_file
from .hse2_streaming import decrypt_streaming_hse2, encrypt_streaming_hse2
from .integrity import IntegrityValidationError
from .password_sources import PasswordSourceError, create_default_password_resolver
from .runtime_password_plan import RuntimePasswordPlan
from .streaming_format import IntegrityError
from .validation_report import (
    build_validation_report,
    collect_decryption_config_strict_issues,
    collect_encryption_config_strict_issues,
    filter_validation_report,
    parse_issue_code_filter,
    raise_for_issues,
)
from .validation_report_output import (
    build_validation_report_summary_payload,
    maybe_write_validation_report,
    render_validation_report_summary_text,
    render_validation_report_text,
    should_return_issue_exit_code,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level command-line parser."""

    return build_cli_parser(
        encrypt_handler=_handle_encrypt_batch,
        decrypt_handler=_handle_decrypt_batch,
        validate_handler=_handle_validate_config,
        init_example_handler=_handle_init_example,
        hse2_encrypt_handler=_handle_hse2_encrypt,
        hse2_decrypt_handler=_handle_hse2_decrypt,
        hse2_rewrap_handler=_handle_hse2_rewrap,
    )


def main(argv: list[str] | None = None) -> int:
    """运行命令行入口并返回退出码。"""

    _configure_standard_streams()
    parser = build_parser()
    effective_argv = sys.argv[1:] if argv is None else argv
    if not effective_argv:
        parser.print_help()
        _pause_for_windows_double_click()
        return 0
    args = parser.parse_args(effective_argv)
    try:
        summary = args.handler(args)
    except Exception as exc:  # noqa: BLE001 - CLI boundary intentionally normalizes failures.
        return handle_cli_exception(args, exc)
    exit_code_summary = summary
    if isinstance(summary, dict) and "__raw_stdout__" in summary:
        print(summary.pop("__raw_stdout__"))
        print("###SUMMARY###")
    output_summary = summary.pop("__summary_payload__", summary) if isinstance(summary, dict) else summary
    print(json.dumps(output_summary, ensure_ascii=False, indent=2, sort_keys=True))
    if should_return_issue_exit_code(args, exit_code_summary):
        return EXIT_VALIDATION_ISSUES
    return 0


def _configure_standard_streams() -> None:
    """Use UTF-8 for CLI text streams even under non-UTF-8 Windows locales."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            continue


def _pause_for_windows_double_click() -> None:
    """Keep a double-clicked Windows console open after showing help."""

    if sys.platform != "win32" or os.environ.get("HSE_NO_PAUSE") == "1":
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    try:
        input("\nPress Enter to exit...")
    except (EOFError, OSError):
        return


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


def _handle_encrypt_batch(args: argparse.Namespace) -> dict[str, Any]:
    """执行 `encrypt-batch` 命令并返回可序列化摘要。"""

    config = _load_config_file(args.config, BatchEncryptionConfig.from_json_file, "encryption")
    resolver = create_default_password_resolver()
    metadata_password = config.resolve_metadata_password(resolver)
    password_mapping = config.build_workflow_password_mapping(resolver)
    if config.package_as_bundle:
        result = encrypt_batch_bundle(
            sources=config.sources,
            passwords_by_source=password_mapping,
            main_password=metadata_password,
            output_dir=config.output_dir,
            bundle_path=config.bundle_output_path,
            metadata_password=metadata_password,
            individually_encrypted_files_by_folder=config.individually_encrypted_files_by_folder,
            write_password_table=config.write_password_table,
            write_internal_password_tables=config.write_internal_password_tables,
            manifest_path=config.manifest_output_path,
            password_table_path=config.password_table_output_path,
            template_path=config.template_output_path,
        )
        return summarize_batch_bundle_encryption_result(result, config.security_mode)

    result = encrypt_batch_files(
        sources=config.sources,
        passwords_by_source=password_mapping,
        metadata_password=metadata_password,
        output_dir=config.output_dir,
        batch_id=config.batch_id,
        individually_encrypted_files_by_folder=config.individually_encrypted_files_by_folder,
        write_password_table=config.write_password_table,
        write_internal_password_tables=config.write_internal_password_tables,
        manifest_path=config.manifest_output_path,
        password_table_path=config.password_table_output_path,
        template_path=config.template_output_path,
    )
    return summarize_batch_encryption_result(result, config.security_mode)


def _handle_decrypt_batch(args: argparse.Namespace) -> dict[str, Any]:
    """执行 `decrypt-batch` 命令并返回可序列化摘要。"""

    config = _load_config_file(args.config, BatchDecryptionConfig.from_json_file, "decryption")
    guard = _build_brute_force_guard(args)
    guard_subject = build_decryption_subject(
        encrypted_files=config.encrypted_files,
        manifest_path=config.manifest_path,
        template_path=config.template_path,
        password_table_path=config.password_table_path,
    )
    guard.check_allowed(guard_subject)
    resolver = create_default_password_resolver()
    try:
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
    except (IntegrityError, IntegrityValidationError):
        guard.record_failure(guard_subject)
        raise
    guard.record_success(guard_subject)
    summary = summarize_batch_decryption_result(result, config.security_mode)
    summary["brute_force_guard"] = {
        "enabled": guard.config.enabled,
        "state_path": str(guard.state_path) if guard.config.enabled else None,
        "max_failures": guard.config.max_failures,
        "window_seconds": guard.config.window_seconds,
        "lock_seconds": guard.config.lock_seconds,
    }
    return summary


def _handle_hse2_encrypt(args: argparse.Namespace) -> dict[str, Any]:
    """Run the experimental one-file HSE2 encryption helper."""

    wrapper_material = _resolve_hse2_wrapper_input(args, "secret", "hse2-encrypt wrapper")
    output = encrypt_streaming_hse2(
        args.input,
        args.output,
        wrapper_material,
        kdf_profile_name=args.kdf_profile,
        chunk_size=int(args.chunk_size),
    )
    return {
        "command": "hse2-encrypt",
        "experimental": True,
        "input": str(Path(args.input)),
        "output": str(output),
        "kdf_profile": args.kdf_profile,
        "chunk_size": int(args.chunk_size),
        "wrapper_source": _hse2_wrapper_source_name(args, "secret"),
    }


def _handle_hse2_decrypt(args: argparse.Namespace) -> dict[str, Any]:
    """Run the experimental one-file HSE2 decryption helper."""

    wrapper_material = _resolve_hse2_wrapper_input(args, "secret", "hse2-decrypt wrapper")
    output = decrypt_streaming_hse2(args.input, args.output, wrapper_material)
    return {
        "command": "hse2-decrypt",
        "experimental": True,
        "input": str(Path(args.input)),
        "output": str(output),
        "wrapper_source": _hse2_wrapper_source_name(args, "secret"),
    }


def _handle_hse2_rewrap(args: argparse.Namespace) -> dict[str, Any]:
    """Run the experimental one-file HSE2 rewrap helper."""

    old_wrapper_material = _resolve_hse2_wrapper_input(args, "old_secret", "hse2-rewrap current wrapper")
    new_wrapper_material = _resolve_hse2_wrapper_input(args, "new_secret", "hse2-rewrap replacement wrapper")
    output = rewrap_hse2_file(
        args.input,
        args.output,
        old_wrapper_material,
        new_wrapper_material,
        new_kdf_profile_name=args.new_kdf_profile,
    )
    return {
        "command": "hse2-rewrap",
        "experimental": True,
        "input": str(Path(args.input)),
        "output": str(output),
        "new_kdf_profile": args.new_kdf_profile,
        "old_wrapper_source": _hse2_wrapper_source_name(args, "old_secret"),
        "new_wrapper_source": _hse2_wrapper_source_name(args, "new_secret"),
    }


def _resolve_hse2_wrapper_input(args: argparse.Namespace, prefix: str, context: str) -> str:
    spec = _hse2_wrapper_spec(args, prefix, context)
    return create_default_password_resolver().resolve(spec, context)


def _hse2_wrapper_spec(args: argparse.Namespace, prefix: str, context: str) -> str | dict[str, object]:
    direct_value = getattr(args, prefix, None)
    env_name = getattr(args, f"{prefix}_env", None)
    file_path = getattr(args, f"{prefix}_file", None)
    use_prompt = bool(getattr(args, f"{prefix}_prompt", False))
    supplied = [
        bool(direct_value),
        bool(env_name),
        bool(file_path),
        use_prompt,
    ]
    if sum(supplied) != 1:
        raise PasswordSourceError(f"{context}: specify exactly one wrapper input source")
    if direct_value:
        return {"type": "literal", "value": direct_value}
    if env_name:
        return {"type": "env", "name": env_name}
    if file_path:
        return {"type": "file", "path": file_path}
    return {"type": "prompt", "prompt": f"{context}: "}


def _hse2_wrapper_source_name(args: argparse.Namespace, prefix: str) -> str:
    if getattr(args, prefix, None):
        return "literal"
    if getattr(args, f"{prefix}_env", None):
        return "env"
    if getattr(args, f"{prefix}_file", None):
        return "file"
    if getattr(args, f"{prefix}_prompt", False):
        return "prompt"
    return "unknown"


def _build_brute_force_guard(args: argparse.Namespace) -> BruteForceGuard:
    return BruteForceGuard(
        BruteForceGuardConfig(
            enabled=not bool(getattr(args, "disable_brute_force_guard", False)),
            max_failures=int(getattr(args, "brute_force_max_failures", 5)),
            window_seconds=int(getattr(args, "brute_force_window_seconds", 900)),
            lock_seconds=int(getattr(args, "brute_force_lock_seconds", 1800)),
            state_path=Path(args.brute_force_guard_state)
            if getattr(args, "brute_force_guard_state", None)
            else None,
        )
    )


def _handle_init_example(args: argparse.Namespace) -> dict[str, Any]:
    """导出指定安全模式和用途的示例配置文件。"""

    return export_example_config(
        mode=args.mode,
        kind=args.kind,
        output=args.output,
        print_to_stdout=args.print_to_stdout,
        override_specs=args.set,
        file_override_specs=args.set_file,
    )


def _handle_validate_config(args: argparse.Namespace) -> dict[str, Any]:
    """只校验配置文件，不执行加解密。"""

    config_path = Path(args.config)
    if not config_path.is_file():
        raise CliConfigError(f"config file not found: {config_path}")
    if args.report:
        summary = build_validation_report(
            kind=args.kind,
            config_path=config_path,
            strict=bool(args.strict),
        )
        include_codes = parse_issue_code_filter(args.include_codes)
        exclude_codes = parse_issue_code_filter(args.exclude_codes, option_name="--exclude-codes")
        summary = filter_validation_report(summary, include_codes=include_codes, exclude_codes=exclude_codes)
        summary["format"] = args.format
        summary["exit_code_on_issues"] = bool(args.exit_code_on_issues)
        summary["warnings_as_errors"] = bool(args.warnings_as_errors)
        summary["output_path"] = str(args.output) if args.output else None
        summary["summary_only"] = bool(args.summary_only)
        summary["included_codes"] = sorted(include_codes) if include_codes is not None else None
        summary["excluded_codes"] = sorted(exclude_codes) if exclude_codes is not None else None
        if args.format == "text":
            if args.summary_only:
                summary["__raw_stdout__"] = render_validation_report_summary_text(summary)
            else:
                summary["__raw_stdout__"] = render_validation_report_text(summary)
        maybe_write_validation_report(args=args, summary=summary)
        if args.summary_only:
            summary["__summary_payload__"] = build_validation_report_summary_payload(summary)
        return summary

    if args.kind == "encrypt":
        config = _load_config_file(config_path, BatchEncryptionConfig.from_json_file, "encryption")
        if args.strict:
            raise_for_issues(collect_encryption_config_strict_issues(config))
    else:
        config = _load_config_file(config_path, BatchDecryptionConfig.from_json_file, "decryption")
        if args.strict:
            raise_for_issues(collect_decryption_config_strict_issues(config))
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


if __name__ == "__main__":
    raise SystemExit(main())
