"""Argument parser construction for the command-line interface."""

from __future__ import annotations

import argparse
from typing import Callable

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
) -> argparse.ArgumentParser:
    """Build the top-level CLI parser and wire subcommands to handlers."""

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
    encrypt_parser.set_defaults(handler=encrypt_handler)

    decrypt_parser = subparsers.add_parser(
        "decrypt-batch",
        help="Decrypt a mixed batch of files and folders from a JSON config file.",
    )
    decrypt_parser.add_argument("--config", required=True, help="Path to a JSON batch-decryption config file.")
    decrypt_parser.add_argument(
        "--disable-brute-force-guard",
        action="store_true",
        help="Disable local failed-attempt throttling for this decryption run.",
    )
    decrypt_parser.add_argument(
        "--brute-force-guard-state",
        required=False,
        help="Optional path for the local brute-force guard state file.",
    )
    decrypt_parser.add_argument(
        "--brute-force-max-failures",
        type=int,
        default=5,
        help="Failed authentication attempts allowed per window before locking. Defaults to 5.",
    )
    decrypt_parser.add_argument(
        "--brute-force-window-seconds",
        type=int,
        default=900,
        help="Rolling failure-count window in seconds. Defaults to 900.",
    )
    decrypt_parser.add_argument(
        "--brute-force-lock-seconds",
        type=int,
        default=1800,
        help="Lock duration in seconds after too many failures. Defaults to 1800.",
    )
    decrypt_parser.set_defaults(handler=decrypt_handler)

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
    validate_parser.set_defaults(handler=validate_handler)

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
    init_example_parser.set_defaults(handler=init_example_handler)

    return parser
