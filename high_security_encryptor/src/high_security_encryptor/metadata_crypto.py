"""Helpers for encrypting and decrypting small metadata payloads.

These helpers intentionally use a compact authenticated blob format instead of the
streaming container because manifests, password tables, and templates are expected
to remain small. Keeping this separate makes the file-level streaming code simpler
while still enforcing authenticated encryption for metadata artifacts.
"""

from __future__ import annotations

import os
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES


METADATA_MAGIC = b"HSM1"
METADATA_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
ARGON_TIME_COST = 3
ARGON_MEMORY_COST = 65536
ARGON_PARALLELISM = 4


class MetadataIntegrityError(Exception):
    """Raised when a metadata payload fails authentication or format validation."""


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a metadata encryption key from the user password and random salt."""

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def encrypt_metadata_bytes(data: bytes, password: str) -> bytes:
    """Encrypt a small metadata payload into a single authenticated blob.

    Metadata files are intentionally kept out of the streaming container path:
    they are small enough that a compact authenticated blob is simpler and more
    convenient for manifests and batch sidecar files.
    """

    if not password:
        raise ValueError("password is required")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = METADATA_MAGIC + bytes([METADATA_VERSION])
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return header + salt + nonce + tag + ciphertext


def decrypt_metadata_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt and authenticate a metadata blob produced by this module.

    The metadata header is authenticated as AAD so an attacker cannot switch the
    blob type or version without being detected.
    """

    if not password:
        raise ValueError("password is required")
    minimum = len(METADATA_MAGIC) + 1 + SALT_LEN + NONCE_LEN + TAG_LEN
    if len(blob) < minimum:
        raise MetadataIntegrityError("metadata blob is too short")
    if blob[: len(METADATA_MAGIC)] != METADATA_MAGIC:
        raise MetadataIntegrityError("unexpected metadata magic")
    if blob[len(METADATA_MAGIC)] != METADATA_VERSION:
        raise MetadataIntegrityError("unsupported metadata version")

    header_len = len(METADATA_MAGIC) + 1
    salt = blob[header_len : header_len + SALT_LEN]
    nonce_start = header_len + SALT_LEN
    nonce = blob[nonce_start : nonce_start + NONCE_LEN]
    tag_start = nonce_start + NONCE_LEN
    tag = blob[tag_start : tag_start + TAG_LEN]
    ciphertext = blob[tag_start + TAG_LEN :]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(blob[:header_len])
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise MetadataIntegrityError("metadata authentication failed") from exc


def write_encrypted_metadata_file(path: str | Path, data: bytes, password: str) -> Path:
    """Encrypt and write metadata to disk in one step."""

    target = Path(path)
    target.write_bytes(encrypt_metadata_bytes(data, password))
    return target


def read_encrypted_metadata_file(path: str | Path, password: str) -> bytes:
    """Read and decrypt an encrypted metadata artifact from disk."""

    source = Path(path)
    return decrypt_metadata_bytes(source.read_bytes(), password)
