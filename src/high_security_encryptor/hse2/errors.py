"""Stable exception types for HSE2 operations."""

from __future__ import annotations


class HSE2Error(Exception):
    """Base class for HSE2-specific errors."""


class HSE2FormatError(HSE2Error):
    """Raised when an HSE2 container or header is malformed."""


class HSE2AuthenticationError(HSE2Error):
    """Raised when authenticated metadata or ciphertext validation fails."""


class HSE2UnsupportedProfileError(HSE2Error):
    """Raised when a requested KDF profile is not supported."""


class HSE2KeyError(HSE2Error):
    """Raised when key material or wrapper data is invalid."""
