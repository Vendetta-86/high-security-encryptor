"""CLI error formatting and exit-code classification."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

from .integrity import IntegrityValidationError
from .password_sources import PasswordSourceError
from .streaming_format import IntegrityError


EXIT_RUNTIME_ERROR = 1
EXIT_VALIDATION_ISSUES = 2
EXIT_CONFIG_ERROR = 3
EXIT_PASSWORD_SOURCE_ERROR = 4
EXIT_INTEGRITY_ERROR = 5


class CliConfigError(Exception):
    """Raised when CLI input or config files are invalid before workflow execution."""


def handle_cli_exception(args: argparse.Namespace, exc: Exception) -> int:
    """Print a concise CLI error by default and return a stable exit code."""

    if is_debug_enabled(args):
        traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
    else:
        print(f"error: {format_exception_message(exc)}", file=sys.stderr)
    return classify_cli_exception(exc)


def is_debug_enabled(args: argparse.Namespace) -> bool:
    """Return whether CLI errors should include tracebacks."""

    return bool(getattr(args, "debug", False) or os.environ.get("HSE_DEBUG") == "1")


def format_exception_message(exc: Exception) -> str:
    """Render exceptions without Python traceback noise."""

    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    message = str(exc)
    return message if message else exc.__class__.__name__


def classify_cli_exception(exc: Exception) -> int:
    """Map known failure classes to stable CLI exit codes."""

    if isinstance(exc, PasswordSourceError):
        return EXIT_PASSWORD_SOURCE_ERROR
    if isinstance(exc, (IntegrityError, IntegrityValidationError)):
        return EXIT_INTEGRITY_ERROR
    if isinstance(exc, (CliConfigError, json.JSONDecodeError, ValueError)):
        return EXIT_CONFIG_ERROR
    return EXIT_RUNTIME_ERROR
