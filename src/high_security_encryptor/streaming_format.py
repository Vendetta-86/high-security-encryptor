"""流式 AES-GCM 容器实现。"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from Crypto.Cipher import AES

from .atomic_io import atomic_output_path, flush_file
from .streaming_primitives import (
    CHUNK_HEADER_STRUCT,
    DEFAULT_CHUNK_SIZE,
    HEADER_MAGIC,
    HEADER_STRUCT,
    MAX_CHUNK_SIZE,
    NONCE_LEN,
    SALT_LEN,
    TAG_LEN,
    TRAILER_NONCE_INDEX,
    TRAILER_STRUCT,
    HeaderError,
    IntegrityError,
    LegacyFormatDetected,
    StreamingFormatError,
    build_header,
    derive_key,
    derive_nonce,
    parse_header,
)


def encrypt_streaming(source: str | Path, target: str | Path, password: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Path:
    """把文件加密为 `HSE1` 流式容器。"""

    source_path = Path(source)
    target_path = Path(target)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not password:
        raise ValueError("password is required")
    _validate_chunk_size(chunk_size)

    salt = os.urandom(SALT_LEN)
    base_nonce = os.urandom(NONCE_LEN)
    header = build_header(chunk_size, salt, base_nonce)
    key = derive_key(password, salt)
    total_plaintext_size = 0
    chunk_count = 0
    plaintext_digest = hashlib.sha256()

    with atomic_output_path(target_path) as temp_target:
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
            flush_file(dst)
    return target_path


@contextmanager
def encrypted_output_stream(
    target: str | Path,
    password: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Iterator[BinaryIO]:
    """Yield a write-only stream that encrypts plaintext bytes into an `HSE1` file."""

    target_path = Path(target)
    if not password:
        raise ValueError("password is required")
    _validate_chunk_size(chunk_size)

    salt = os.urandom(SALT_LEN)
    base_nonce = os.urandom(NONCE_LEN)
    header = build_header(chunk_size, salt, base_nonce)
    key = derive_key(password, salt)

    with atomic_output_path(target_path) as temp_target:
        with temp_target.open("wb") as dst:
            dst.write(header)
            writer = _EncryptedOutputStream(dst, header, key, base_nonce, chunk_size)
            finished = False
            try:
                yield writer
                writer.finish()
                finished = True
                flush_file(dst)
            finally:
                if not finished:
                    writer.abort()


def decrypt_streaming(source: str | Path, target: str | Path, password: str) -> Path:
    """解密 `HSE1` 流式容器并验证全部完整性校验。"""

    source_path = Path(source)
    target_path = Path(target)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not password:
        raise ValueError("password is required")

    file_size = source_path.stat().st_size
    min_size = HEADER_STRUCT.size + SALT_LEN + NONCE_LEN + TRAILER_STRUCT.size
    if file_size < min_size:
        raise IntegrityError("ciphertext is too short")

    with source_path.open("rb") as src:
        header, salt, declared_chunk_size = parse_header(src)
        if declared_chunk_size <= 0 or declared_chunk_size > MAX_CHUNK_SIZE:
            raise HeaderError("unsupported chunk size")
        key = derive_key(password, salt)
        payload_end = file_size - TRAILER_STRUCT.size
        chunk_index = 0
        total_plaintext_size = 0
        plaintext_digest = hashlib.sha256()
        with atomic_output_path(target_path) as temp_target:
            with temp_target.open("wb") as dst:
                while src.tell() < payload_end:
                    meta = src.read(CHUNK_HEADER_STRUCT.size)
                    if len(meta) != CHUNK_HEADER_STRUCT.size:
                        raise IntegrityError("truncated chunk metadata")
                    read_index, plaintext_length = CHUNK_HEADER_STRUCT.unpack(meta)
                    if read_index != chunk_index:
                        raise IntegrityError("unexpected chunk order")
                    if plaintext_length == 0 or plaintext_length > declared_chunk_size:
                        raise IntegrityError("invalid chunk length")
                    remaining_payload = payload_end - src.tell() - TAG_LEN
                    if plaintext_length > remaining_payload:
                        raise IntegrityError("chunk length exceeds remaining payload")
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
                flush_file(dst)
    return target_path


def _validate_chunk_size(chunk_size: int) -> None:
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_SIZE}")


class _EncryptedOutputStream:
    """Small write-only adapter used by ZIP writers and other streaming producers."""

    def __init__(
        self,
        target: BinaryIO,
        header: bytes,
        key: bytes,
        base_nonce: bytes,
        chunk_size: int,
    ) -> None:
        self._target = target
        self._header = header
        self._key = key
        self._base_nonce = base_nonce
        self._chunk_size = chunk_size
        self._buffer = bytearray()
        self._chunk_count = 0
        self._total_plaintext_size = 0
        self._plaintext_digest = hashlib.sha256()
        self._finished = False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self._finished:
            raise ValueError("encrypted output stream is closed")
        chunk = bytes(data)
        if not chunk:
            return 0
        self._buffer.extend(chunk)
        while len(self._buffer) >= self._chunk_size:
            self._write_plaintext_chunk(bytes(self._buffer[: self._chunk_size]))
            del self._buffer[: self._chunk_size]
        return len(chunk)

    def flush(self) -> None:
        self._target.flush()

    def close(self) -> None:
        if not self._finished:
            self.finish()

    def abort(self) -> None:
        self._finished = True
        self._buffer.clear()

    def finish(self) -> None:
        if self._finished:
            return
        if self._buffer:
            self._write_plaintext_chunk(bytes(self._buffer))
            self._buffer.clear()
        digest_bytes = self._plaintext_digest.digest()
        trailer_meta = struct.pack(">QQ32s", self._chunk_count, self._total_plaintext_size, digest_bytes)
        trailer_cipher = AES.new(self._key, AES.MODE_GCM, nonce=derive_nonce(self._base_nonce, TRAILER_NONCE_INDEX))
        trailer_cipher.update(self._header + trailer_meta)
        trailer_tag = trailer_cipher.encrypt_and_digest(b"")[1]
        self._target.write(TRAILER_STRUCT.pack(self._chunk_count, self._total_plaintext_size, digest_bytes, trailer_tag))
        self._finished = True

    def _write_plaintext_chunk(self, plaintext: bytes) -> None:
        meta = CHUNK_HEADER_STRUCT.pack(self._chunk_count, len(plaintext))
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=derive_nonce(self._base_nonce, self._chunk_count))
        cipher.update(self._header + meta)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self._target.write(meta)
        self._target.write(tag)
        self._target.write(ciphertext)
        self._total_plaintext_size += len(plaintext)
        self._plaintext_digest.update(plaintext)
        self._chunk_count += 1
