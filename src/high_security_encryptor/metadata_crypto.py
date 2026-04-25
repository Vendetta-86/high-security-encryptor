"""小型元数据载荷的加解密辅助逻辑。"""

from __future__ import annotations

import os
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

from .atomic_io import write_bytes_atomically


METADATA_MAGIC = b"HSM1"
METADATA_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
ARGON_TIME_COST = 3
ARGON_MEMORY_COST = 65536
ARGON_PARALLELISM = 4
METADATA_OVERHEAD = len(METADATA_MAGIC) + 1 + SALT_LEN + NONCE_LEN + TAG_LEN
MAX_METADATA_PLAINTEXT_BYTES = 8 * 1024 * 1024
MAX_ENCRYPTED_METADATA_BYTES = MAX_METADATA_PLAINTEXT_BYTES + METADATA_OVERHEAD


class MetadataIntegrityError(Exception):
    """当元数据载荷认证失败或格式非法时抛出。"""


def _derive_key(password: str, salt: bytes) -> bytes:
    """根据用户密码和随机盐派生元数据加密密钥。"""

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
    """把小型元数据载荷加密成单个带认证的 blob。"""

    if not password:
        raise ValueError("password is required")
    _validate_metadata_plaintext_size(len(data))
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = METADATA_MAGIC + bytes([METADATA_VERSION])
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return header + salt + nonce + tag + ciphertext


def decrypt_metadata_bytes(blob: bytes, password: str) -> bytes:
    """解密并认证由本模块生成的元数据 blob。"""

    if not password:
        raise ValueError("password is required")
    _validate_encrypted_metadata_size(len(blob))
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
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise MetadataIntegrityError("metadata authentication failed") from exc
    _validate_metadata_plaintext_size(len(plaintext))
    return plaintext


def write_encrypted_metadata_file(path: str | Path, data: bytes, password: str) -> Path:
    """一步完成元数据加密并写入磁盘。"""

    target = Path(path)
    write_bytes_atomically(target, encrypt_metadata_bytes(data, password))
    return target


def read_encrypted_metadata_file(path: str | Path, password: str) -> bytes:
    """从磁盘读取并解密加密元数据副产物。"""

    source = Path(path)
    _validate_encrypted_metadata_size(source.stat().st_size)
    return decrypt_metadata_bytes(source.read_bytes(), password)


def _validate_metadata_plaintext_size(size: int) -> None:
    if size > MAX_METADATA_PLAINTEXT_BYTES:
        raise ValueError("metadata payload is too large")


def _validate_encrypted_metadata_size(size: int) -> None:
    if size > MAX_ENCRYPTED_METADATA_BYTES:
        raise MetadataIntegrityError("metadata blob is too large")
