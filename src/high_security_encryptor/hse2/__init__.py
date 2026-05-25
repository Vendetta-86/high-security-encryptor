"""HSE2 self-describing container support.

This package contains the format and key-management building blocks for the
next HSE2 container implementation. The first iteration is intentionally
isolated from the existing CLI encryption flow so the current HSE1-compatible
workflows remain stable while the format is hardened.
"""

from .constants import HSE2_MAGIC, HSE2_VERSION
from .errors import HSE2Error, HSE2FormatError, HSE2UnsupportedProfileError
from .kdf import KdfProfile, get_kdf_profile
from .keys import KeyBundle, generate_key_bundle

__all__ = [
    "HSE2_MAGIC",
    "HSE2_VERSION",
    "HSE2Error",
    "HSE2FormatError",
    "HSE2UnsupportedProfileError",
    "KdfProfile",
    "KeyBundle",
    "generate_key_bundle",
    "get_kdf_profile",
]
