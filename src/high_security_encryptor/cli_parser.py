"""Argument parser construction for the command-line interface."""

from __future__ import annotations

import argparse
from typing import Callable

from .kdf_profiles import KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED, KDF_PROFILE_PARANOID
from .keyfile_generation import DEFAULT_GENERATED_KEYFILE_BYTES
from .security_mode import (
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    SECURITY_MODE_NO_PASSWORD_TABLES,
)

Handler = Callable[[argparse.Namespace], dict]


def build_cli_parser(
    *,
    encrypt_handler: Handler,
    decrypt_handler: Handler,
    validate_handler: Handler,
    init_example_handler: Handler,
    hse2_encrypt_handler: Handler | None = None,
    hse2_decrypt_handler: Handler | None = None,
    hse2_rewrap_handler: Handler | None = None,
    hse2_encrypt_config_handler: Handler | None = None,
    hse2_decrypt_config_handler: Handler | None = None,
    hse2_rewrap_config_handler: Handler | None = None,
    hse2_batch_encrypt_handler: Handler | None = None,
    hse2_batch_decrypt_handler: Handler | None = None,
    hse2_batch_rewrap_handler: Handler | None = None,
    hse1_to_hse2_handler: Handler | None = None,
    hse2_validate_handler: Handler | None = None,
    hse2_inspect_handler: Handler | None = None,
    hse2_plan_archive_handler: Handler | None = None,
    generate_keyfile_handler: Handler | None = None,
    hse2_rotate_keyfile_handler: Handler | None = None,
    dpapi_protect_handler: Handler | None = None,
) -> argparse.ArgumentParser:
    """Build the top-level CLI parser and wire subcommands to handlers."""

    parser = argparse.ArgumentParser(prog="high-security-encryptor")
    parser.add_argument("--debug", action="store_true", help="Print Python tracebacks for CLI errors.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt-batch", help="Encrypt a mixed batch of files and folders from a JSON config file.")
    encrypt_parser.add_argument("--config", required=True, help="Path to a JSON batch-encryption config file.")
    encrypt_parser.set_defaults(handler=encrypt_handler)

    decrypt_parser = subparsers.add_parser("decrypt-batch", help="Decrypt a mixed batch of files and folders from a JSON config file.")
    decrypt_parser.add_argument("--config", required=True, help="Path to a JSON batch-decryption config file.")
    decrypt_parser.add_argument("--disable-brute-force-guard", action="store_true", help="Disable local failed-attempt throttling for this decryption run.")
    decrypt_parser.add_argument("--brute-force-guard-state", required=False, help="Optional path for the local brute-force guard state file.")
    decrypt_parser.add_argument("--brute-force-max-failures", type=int, default=5, help="Failed authentication attempts allowed per window before locking. Defaults to 5.")
    decrypt_parser.add_argument("--brute-force-window-seconds", type=int, default=900, help="Rolling failure-count window in seconds. Defaults to 900.")
    decrypt_parser.add_argument("--brute-force-lock-seconds", type=int, default=1800, help="Lock duration in seconds after too many failures. Defaults to 1800.")
    decrypt_parser.set_defaults(handler=decrypt_handler)

    if generate_keyfile_handler is not None:
        keyfile_parser = subparsers.add_parser("generate-keyfile", help="Generate a random local keyfile for file-backed wrapper material.")
        keyfile_parser.add_argument("--output", required=True, help="Path of the keyfile to create.")
        keyfile_parser.add_argument("--size", type=int, default=DEFAULT_GENERATED_KEYFILE_BYTES, help=f"Keyfile size in bytes. Defaults to {DEFAULT_GENERATED_KEYFILE_BYTES}.")
        keyfile_parser.add_argument("--force", action="store_true", help="Overwrite the output keyfile if it already exists.")
        keyfile_parser.set_defaults(handler=generate_keyfile_handler)

    if dpapi_protect_handler is not None:
        dpapi_parser = subparsers.add_parser("dpapi-protect", help="WINDOWS ONLY: Protect a local binary file with Windows DPAPI.")
        dpapi_parser.add_argument("--input", required=True, help="Input binary file to protect.")
        dpapi_parser.add_argument("--output", required=True, help="Output DPAPI blob file.")
        dpapi_parser.add_argument("--scope", choices=["current_user", "local_machine"], default="current_user", help="DPAPI protection scope. Defaults to current_user.")
        dpapi_parser.add_argument("--force", action="store_true", help="Overwrite the output DPAPI blob file if it already exists.")
        dpapi_parser.set_defaults(handler=dpapi_protect_handler)

    if hse2_rotate_keyfile_handler is not None:
        rotate_parser = subparsers.add_parser("hse2-rotate-keyfile", help="EXPERIMENTAL: Rotate HSE2 files from one keyfile to another using a JSON config.")
        rotate_parser.add_argument("--config", required=True, help="Path to an HSE2 keyfile rotation config file.")
        rotate_parser.set_defaults(handler=hse2_rotate_keyfile_handler)

    if hse2_encrypt_handler is not None:
        hse2_encrypt_parser = subparsers.add_parser("hse2-encrypt", help="EXPERIMENTAL: Encrypt one file with the draft HSE2 container format.")
        _add_hse2_file_args(hse2_encrypt_parser)
        _add_hse2_secret_arg(hse2_encrypt_parser, "--secret", "Secret used to wrap the HSE2 data key.")
        hse2_encrypt_parser.add_argument("--kdf-profile", choices=[KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED, KDF_PROFILE_PARANOID], default=KDF_PROFILE_HARDENED, help="Argon2id KDF profile. Defaults to hardened.")
        hse2_encrypt_parser.add_argument("--chunk-size", type=int, default=1024 * 1024, help="Payload chunk size in bytes. Defaults to 1048576.")
        hse2_encrypt_parser.set_defaults(handler=hse2_encrypt_handler)

    if hse2_decrypt_handler is not None:
        hse2_decrypt_parser = subparsers.add_parser("hse2-decrypt", help="EXPERIMENTAL: Decrypt one draft HSE2 container file.")
        _add_hse2_file_args(hse2_decrypt_parser)
        _add_hse2_secret_arg(hse2_decrypt_parser, "--secret", "Secret used to unwrap the HSE2 data key.")
        hse2_decrypt_parser.set_defaults(handler=hse2_decrypt_handler)

    if hse2_rewrap_handler is not None:
        hse2_rewrap_parser = subparsers.add_parser("hse2-rewrap", help="EXPERIMENTAL: Rewrap one draft HSE2 file without rewriting payload chunks.")
        _add_hse2_file_args(hse2_rewrap_parser)
        _add_hse2_secret_arg(hse2_rewrap_parser, "--old-secret", "Current HSE2 wrapper secret.")
        _add_hse2_secret_arg(hse2_rewrap_parser, "--new-secret", "Replacement HSE2 wrapper secret.")
        hse2_rewrap_parser.add_argument("--new-kdf-profile", choices=[KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED, KDF_PROFILE_PARANOID], default=KDF_PROFILE_HARDENED, help="Replacement Argon2id KDF profile. Defaults to hardened.")
        hse2_rewrap_parser.set_defaults(handler=hse2_rewrap_handler)

    if hse2_encrypt_config_handler is not None:
        hse2_encrypt_config_parser = subparsers.add_parser("hse2-encrypt-config", help="EXPERIMENTAL: Encrypt one HSE2 file from a JSON config.")
        hse2_encrypt_config_parser.add_argument("--config", required=True, help="Path to an HSE2 encryption config file.")
        hse2_encrypt_config_parser.set_defaults(handler=hse2_encrypt_config_handler)

    if hse2_decrypt_config_handler is not None:
        hse2_decrypt_config_parser = subparsers.add_parser("hse2-decrypt-config", help="EXPERIMENTAL: Decrypt one HSE2 file from a JSON config.")
        hse2_decrypt_config_parser.add_argument("--config", required=True, help="Path to an HSE2 decryption config file.")
        hse2_decrypt_config_parser.set_defaults(handler=hse2_decrypt_config_handler)

    if hse2_rewrap_config_handler is not None:
        hse2_rewrap_config_parser = subparsers.add_parser("hse2-rewrap-config", help="EXPERIMENTAL: Rewrap one HSE2 file from a JSON config.")
        hse2_rewrap_config_parser.add_argument("--config", required=True, help="Path to an HSE2 rewrap config file.")
        hse2_rewrap_config_parser.set_defaults(handler=hse2_rewrap_config_handler)

    if hse2_batch_encrypt_handler is not None:
        hse2_batch_encrypt_parser = subparsers.add_parser("hse2-batch-encrypt", help="EXPERIMENTAL: Encrypt multiple HSE2 files from a JSON config.")
        hse2_batch_encrypt_parser.add_argument("--config", required=True, help="Path to an HSE2 batch encryption config file.")
        hse2_batch_encrypt_parser.set_defaults(handler=hse2_batch_encrypt_handler)

    if hse2_batch_decrypt_handler is not None:
        hse2_batch_decrypt_parser = subparsers.add_parser("hse2-batch-decrypt", help="EXPERIMENTAL: Decrypt multiple HSE2 files from a JSON config.")
        hse2_batch_decrypt_parser.add_argument("--config", required=True, help="Path to an HSE2 batch decryption config file.")
        hse2_batch_decrypt_parser.set_defaults(handler=hse2_batch_decrypt_handler)

    if hse2_batch_rewrap_handler is not None:
        hse2_batch_rewrap_parser = subparsers.add_parser("hse2-batch-rewrap", help="EXPERIMENTAL: Rewrap multiple HSE2 files from a JSON config.")
        hse2_batch_rewrap_parser.add_argument("--config", required=True, help="Path to an HSE2 batch rewrap config file.")
        hse2_batch_rewrap_parser.set_defaults(handler=hse2_batch_rewrap_handler)

    if hse1_to_hse2_handler is not None:
        migration_parser = subparsers.add_parser("hse1-to-hse2", help="EXPERIMENTAL: Migrate HSE1 files to HSE2 from a JSON config.")
        migration_parser.add_argument("--config", required=True, help="Path to an HSE1 to HSE2 migration config file.")
        migration_parser.set_defaults(handler=hse1_to_hse2_handler)

    if hse2_validate_handler is not None:
        hse2_validate_parser = subparsers.add_parser("hse2-validate", help="EXPERIMENTAL: Validate HSE2 files without writing plaintext output.")
        hse2_validate_parser.add_argument("--config", required=True, help="Path to an HSE2 validation config file.")
        hse2_validate_parser.add_argument("--output", required=False, help="Optional path to write the full JSON validation report.")
        hse2_validate_parser.add_argument("--summary-only", action="store_true", help="Print only aggregate counts to stdout while preserving the full report for --output.")
        hse2_validate_parser.add_argument("--exit-code-on-failure", action="store_true", help="Return a non-zero exit code when any HSE2 item fails validation.")
        hse2_validate_parser.set_defaults(handler=hse2_validate_handler)

    if hse2_inspect_handler is not None:
        hse2_inspect_parser = subparsers.add_parser("hse2-inspect", help="EXPERIMENTAL: Inspect HSE2 container metadata without decrypting payload content.")
        hse2_inspect_parser.add_argument("--input", required=True, help="Input HSE2 container path.")
        hse2_inspect_parser.set_defaults(handler=hse2_inspect_handler)

    if hse2_plan_archive_handler is not None:
        hse2_plan_archive_parser = subparsers.add_parser("hse2-plan-archive", help="EXPERIMENTAL: Preview archive manifest metadata from filesystem roots without encrypting or writing a container.")
        hse2_plan_archive_parser.add_argument("--root", action="append", required=True, help="File or directory root to include. May be supplied multiple times.")
        hse2_plan_archive_parser.set_defaults(handler=hse2_plan_archive_handler)

    validate_parser = subparsers.add_parser("validate-config", help="Validate an encryption or decryption JSON config without executing the workflow.")
    validate_parser.add_argument("--kind", required=True, choices=["encrypt", "decrypt"], help="Whether the config should be validated as an encryption or decryption config.")
    validate_parser.add_argument("--config", required=True, help="Path to the JSON config file to validate.")
    validate_parser.add_argument("--strict", action="store_true", help="Apply stricter opinionated validation rules on top of schema checks.")
    validate_parser.add_argument("--report", action="store_true", help="Return a structured validation report instead of failing fast on the first issue.")
    validate_parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format for --report. Defaults to json.")
    validate_parser.add_argument("--exit-code-on-issues", action="store_true", help="Return exit code 2 when --report finds validation issues.")
    validate_parser.add_argument("--warnings-as-errors", action="store_true", help="Treat warning issues as CI-failing issues when combined with --report.")
    validate_parser.add_argument("--output", required=False, help="Optional path used to persist the validation report content.")
    validate_parser.add_argument("--summary-only", action="store_true", help="Print only a compact report summary to stdout while keeping full report data for --output.")
    validate_parser.add_argument("--include-codes", required=False, help="Comma-separated issue codes to keep in the report and exit-code evaluation.")
    validate_parser.add_argument("--exclude-codes", required=False, help="Comma-separated issue codes to remove from the report and exit-code evaluation.")
    validate_parser.set_defaults(handler=validate_handler)

    init_example_parser = subparsers.add_parser("init-example", help="Export an example JSON config for a chosen security mode.")
    init_example_parser.add_argument("--mode", required=True, choices=[SECURITY_MODE_COMPATIBLE, SECURITY_MODE_HARDENED, SECURITY_MODE_NO_PASSWORD_TABLES], help="Security mode used to pick the example template.")
    init_example_parser.add_argument("--kind", required=True, choices=["encrypt", "decrypt"], help="Whether to export an encryption or decryption example.")
    init_example_parser.add_argument("--output", required=False, help="Path of the JSON file to be written.")
    init_example_parser.add_argument("--print", action="store_true", dest="print_to_stdout", help="Print the example JSON to stdout instead of writing a file.")
    init_example_parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="Override an existing JSON field using a dotted path before export.")
    init_example_parser.add_argument("--set-file", action="append", default=[], metavar="KEY=@PATH", help="Override an existing JSON field from a JSON file before export.")
    init_example_parser.set_defaults(handler=init_example_handler)

    return parser


def _add_hse2_file_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", required=True, help="Input file path.")
    parser.add_argument("--output", required=True, help="Output file path.")


def _add_hse2_secret_arg(parser: argparse.ArgumentParser, name: str, help_text: str) -> None:
    parser.add_argument(name, required=False, help=f"Testing-only literal value. {help_text}")
    parser.add_argument(f"{name}-env", required=False, help="Environment variable containing the value.")
    parser.add_argument(f"{name}-file", required=False, help="UTF-8 file containing the value.")
    parser.add_argument(f"{name}-prompt", action="store_true", help="Prompt interactively for the value.")
