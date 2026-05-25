"""HSE2 self-describing container support.

This package contains the format and key-management building blocks for the
next HSE2 container implementation. The first iteration is intentionally
isolated from the existing CLI encryption flow so the current HSE1-compatible
workflows remain stable while the format is hardened.
"""

from .constants import HSE2_MAGIC, HSE2_VERSION
from .errors import HSE2Error, HSE2FormatError, HSE2UnsupportedProfileError
from .header import HSE2Header, dumps_canonical_header, loads_canonical_header
from .kdf import KdfProfile, get_kdf_profile
from .keys import KeyBundle, generate_key_bundle
from .wrappers import WrapperRecord, WrappedKeys, make_placeholder_wrapper

__all__ = [
    "HSE2_MAGIC",
    "HSE2_VERSION",
    "HSE2Error",
    "HSE2FormatError",
    "HSE2UnsupportedProfileError",
    "HSE2Header",
    "KdfProfile",
    "KeyBundle",
    "WrapperRecord",
    "WrappedKeys",
    "dumps_canonical_header",
    "generate_key_bundle",
    "get_kdf_profile",
    "loads_canonical_header",
    "make_placeholder_wrapper",
]
