"""流式 AES-GCM 容器实现。"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

HEADER_MAGIC = b"HSE1"
VERSION = 1
FLAGS = 0
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DIGEST_LEN = 32
KEY_LEN = 32
DEFAULT_CHUNK_SIZE = 1024 * 1024
ARGON_TIME_COST = 3
ARGON_MEMORY_COST = 65536
ARGON_PARALLELISM = 4

HEADER_STRUCT = struct.Struct(">4sBBBBII")
CHUNK_HEADER_STRUCT = struct.Struct(">QI")
TRAILER_STRUCT = struct.Struct(">QQ32s16s")
TRAILER_NONCE_INDEX = (1 << 64) - 1


class StreamingFormatError(Exception):
    """流式格式相关错误的基类。"""

    pass


class LegacyFormatDetected(StreamingFormatError):
    """当文件应转交旧版兼容层处理时抛出。"""

    pass


class IntegrityError(StreamingFormatError):
    """当认证、结构或一致性校验失败时抛出。"""

    pass


class HeaderError(StreamingFormatError):
    """当容器头损坏或版本不受支持时抛出。"""

    pass


def build_header(chunk_size: int, salt: bytes, base_nonce: bytes) -> bytes:
    """构造固定头部、随机盐和基础 nonce。"""

    if len(salt) != SALT_LEN:
        raise ValueError("invalid salt length")
    if len(base_nonce) != NONCE_LEN:
        raise ValueError("invalid nonce length")
    fixed = HEADER_STRUCT.pack(
        HEADER_MAGIC,
        VERSION,
        FLAGS,
        SALT_LEN,
        NONCE_LEN,
        chunk_size,
        0,
    )
    return fixed + salt + base_nonce


def parse_header(file_obj) -> tuple[bytes, bytes, int]:
    """从已打开的二进制文件中读取并校验容器头。"""

    fixed = file_obj.read(HEADER_STRUCT.size)
    if len(fixed) != HEADER_STRUCT.size:
        raise HeaderError("truncated header")
    magic, version, _flags, salt_len, nonce_len, chunk_size, _reserved = HEADER_STRUCT.unpack(fixed)
    if magic != HEADER_MAGIC:
        raise LegacyFormatDetected("legacy or unknown format; legacy dispatch path must be implemented")
    if version != VERSION:
        raise HeaderError(f"unsupported version: {version}")
    if salt_len != SALT_LEN or nonce_len != NONCE_LEN:
        raise HeaderError("unexpected salt or nonce size")
    salt = file_obj.read(salt_len)
    base_nonce = file_obj.read(nonce_len)
    if len(salt) != salt_len or len(base_nonce) != nonce_len:
        raise HeaderError("truncated header payload")
    return fixed + salt + base_nonce, salt, chunk_size


def derive_key(password: str, salt: bytes) -> bytes:
    """使用 Argon2id 派生文件加密密钥。"""

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def derive_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """根据基础 nonce 和分块索引派生每块的 nonce。"""

    nonce_int = int.from_bytes(base_nonce, "big") ^ chunk_index
    return nonce_int.to_bytes(len(base_nonce), "big")


def encrypt_streaming(source: str | Path, target: str | Path, password: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Path:
    """把文件加密为 `HSE1` 流式容器。"""

    source_path = Path(source)
    target_path = Path(target)
    temp_target = target_path.with_suffix(target_path.suffix + ".tmp")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not password:
        raise ValueError("password is required")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    salt = os.urandom(SALT_LEN)
    base_nonce = os.urandom(NONCE_LEN)
    header = build_header(chunk_size, salt, base_nonce)
    key = derive_key(password, salt)
    total_plaintext_size = 0
    chunk_count = 0
    plaintext_digest = hashlib.sha256()

    try:
        with source_path.open("rb") as src, temp_target.open("wb") as dst:
            dst.write(header)
            while True:
                plaintext = src.read(chunk_size)
                if not plaintext:
                    break
                # 分块索引和明文长度会进入 AAD，防止分块被静默调换顺序或长度。
                meta = CHUNK_HEADER_STRUCT.pack(chunk_count, len(plaintext))
                cipher = AES.new(key, AES.MODE_GCM, nonce=derive_nonce(base_nonce, chunk_count))
                cipher.update(header + meta)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                dst.write(meta)
                dst.write(tag)
                dst.write(ciphertext)
                total_plaintext_size += len(plaintext)
                plaintext_digest.update(plaintext)
                chunk_count += 1

            # trailer 会绑定完整明文摘要以及汇总计数信息。
            digest_bytes = plaintext_digest.digest()
            trailer_meta = struct.pack(">QQ32s", chunk_count, total_plaintext_size, digest_bytes)
            trailer_cipher = AES.new(key, AES.MODE_GCM, nonce=derive_nonce(base_nonce, TRAILER_NONCE_INDEX))
            trailer_cipher.update(header + trailer_meta)
            trailer_tag = trailer_cipher.encrypt_and_digest(b"")[1]
            dst.write(TRAILER_STRUCT.pack(chunk_count, total_plaintext_size, digest_bytes, trailer_tag))
        temp_target.replace(target_path)
        return target_path
    except Exception:
        if temp_target.exists():
            temp_target.unlink()
        raise


def decrypt_streaming(source: str | Path, target: str | Path, password: str) -> Path:
    """解密 `HSE1` 流式容器并验证全部完整性校验。"""

    source_path = Path(source)
    target_path = Path(target)
    temp_target = target_path.with_suffix(target_path.suffix + ".tmp")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not password:
        raise ValueError("password is required")

    file_size = source_path.stat().st_size
    min_size = HEADER_STRUCT.size + SALT_LEN + NONCE_LEN + TRAILER_STRUCT.size
    if file_size < min_size:
        raise IntegrityError("ciphertext is too short")

    with source_path.open("rb") as src:
        header, salt, _chunk_size = parse_header(src)
        key = derive_key(password, salt)
        payload_end = file_size - TRAILER_STRUCT.size
        chunk_index = 0
        total_plaintext_size = 0
        plaintext_digest = hashlib.sha256()
        try:
            with temp_target.open("wb") as dst:
                while src.tell() < payload_end:
                    meta = src.read(CHUNK_HEADER_STRUCT.size)
                    if len(meta) != CHUNK_HEADER_STRUCT.size:
                        raise IntegrityError("truncated chunk metadata")
                    read_index, plaintext_length = CHUNK_HEADER_STRUCT.unpack(meta)
                    if read_index != chunk_index:
                        raise IntegrityError("unexpected chunk order")
                    tag = src.read(TAG_LEN)
                    if len(tag) != TAG_LEN:
                        raise IntegrityError("truncated chunk tag")
                    ciphertext = src.read(plaintext_length)
                    if len(ciphertext) != plaintext_length:
                        raise IntegrityError("truncated chunk ciphertext")
                    cipher = AES.new(key, AES.MODE_GCM, nonce=derive_nonce(header[-NONCE_LEN:], chunk_index))
                    cipher.update(header + meta)
                    try:
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    except ValueError as exc:
                        raise IntegrityError("chunk authentication failed") from exc
                    dst.write(plaintext)
                    total_plaintext_size += len(plaintext)
                    plaintext_digest.update(plaintext)
                    chunk_index += 1

                trailer_blob = src.read(TRAILER_STRUCT.size)
                if len(trailer_blob) != TRAILER_STRUCT.size:
                    raise IntegrityError("truncated trailer")
                expected_chunk_count, expected_plaintext_size, expected_digest, trailer_tag = TRAILER_STRUCT.unpack(trailer_blob)
                trailer_meta = struct.pack(">QQ32s", expected_chunk_count, expected_plaintext_size, expected_digest)
                trailer_cipher = AES.new(key, AES.MODE_GCM, nonce=derive_nonce(header[-NONCE_LEN:], TRAILER_NONCE_INDEX))
                trailer_cipher.update(header + trailer_meta)
                try:
                    trailer_cipher.decrypt_and_verify(b"", trailer_tag)
                except ValueError as exc:
                    raise IntegrityError("trailer authentication failed") from exc
                if expected_chunk_count != chunk_index:
                    raise IntegrityError("chunk count mismatch")
                if expected_plaintext_size != total_plaintext_size:
                    raise IntegrityError("plaintext size mismatch")
                if expected_digest != plaintext_digest.digest():
                    raise IntegrityError("plaintext digest mismatch")
            temp_target.replace(target_path)
            return target_path
        except Exception:
            if temp_target.exists():
                temp_target.unlink()
            raise
