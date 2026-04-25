"""Output redaction helpers for user-facing diagnostics."""

from __future__ import annotations

import re


MAX_REDACTED_MESSAGE_CHARS = 400

_ENV_VAR_PATTERN = re.compile(
    r"(environment variable (?:not set|is empty): )([A-Za-z_][A-Za-z0-9_]*)"
)
_WINDOWS_PATH_PATTERN = re.compile(r"(?<![\w.-])(?:[A-Za-z]:[\\/][^\s\"'<>|]+)")
_POSIX_PATH_PATTERN = re.compile(r"(?<![\w.-])/(?:[^\s\"'<>|]+)")


def redact_text(value: str, max_length: int = MAX_REDACTED_MESSAGE_CHARS) -> str:
    """Redact absolute paths and provider identifiers from CLI-facing text."""

    redacted = _ENV_VAR_PATTERN.sub(r"\1<env>", value)
    redacted = _WINDOWS_PATH_PATTERN.sub("<path>", redacted)
    redacted = _POSIX_PATH_PATTERN.sub("<path>", redacted)
    if len(redacted) <= max_length:
        return redacted
    return f"{redacted[: max_length - 3]}..."
