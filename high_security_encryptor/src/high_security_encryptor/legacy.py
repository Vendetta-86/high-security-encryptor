"""Compatibility path for the legacy `GCM1` container.

The original project used a single-blob authenticated format. This module keeps
that data readable while the new project migrates to a streaming container for
large files.
"""

from __future__ import annotations

from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

from .streaming_format import IntegrityError, LegacyFormatDetected

LEGACY_MAGIC = b"GCM1"
LEGACY_VERSION = 1
LEGACY_SALT_LEN = 16
LEGACY_NONCE_LEN = 12
LEGACY_TAG_LEN = 16
LEGACY_KEY_LEN = 32
LEGACY_HEADER_LEN = len(LEGACY_MAGIC) + 1
LEGACY_MIN_BLOB_LEN = LEGACY_HEADER_LEN + LEGACY_SALT_LEN + LEGACY_NONCE_LEN + LEGACY_TAG_LEN
LEGACY_ARGON_TIME_COST = 3
LEGACY_ARGON_MEMORY_COST = 65536
LEGACY_ARGON_PARALLELISM = 4


def decrypt_legacy(source: str | Path, target: str | Path, password: str) -> Path:
    """Decrypt a legacy `GCM1` file and write the plaintext target."""

    source_path = Path(source)
    target_path = Path(target)
    blob = source_path.read_bytes()
    plaintext = decrypt_legacy_bytes(blob, password)
    target_path.write_bytes(plaintext)
    return target_path


def decrypt_legacy_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt a raw legacy blob entirely in memory.

    This is acceptable for compatibility mode because the legacy format itself is
    non-streaming. The caller is expected to use the new format for future files.
    """

    if len(blob) < LEGACY_MIN_BLOB_LEN:
        raise IntegrityError("legacy ciphertext is too short")
    if blob[: len(LEGACY_MAGIC)] != LEGACY_MAGIC:
        raise LegacyFormatDetected("legacy magic is not recognized")
    if blob[len(LEGACY_MAGIC)] != LEGACY_VERSION:
        raise LegacyFormatDetected("unsupported legacy version")

    salt_start = LEGACY_HEADER_LEN
    nonce_start = salt_start + LEGACY_SALT_LEN
    tag_start = nonce_start + LEGACY_NONCE_LEN
    data_start = tag_start + LEGACY_TAG_LEN

    header = blob[:LEGACY_HEADER_LEN]
    salt = blob[salt_start:nonce_start]
    nonce = blob[nonce_start:tag_start]
    tag = blob[tag_start:data_start]
    ciphertext = blob[data_start:]

    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=LEGACY_ARGON_TIME_COST,
        memory_cost=LEGACY_ARGON_MEMORY_COST,
        parallelism=LEGACY_ARGON_PARALLELISM,
        hash_len=LEGACY_KEY_LEN,
        type=Type.ID,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise IntegrityError("legacy authentication failed") from exc
