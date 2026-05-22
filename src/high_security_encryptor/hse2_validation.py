"""Read-only validation helpers for experimental HSE2 containers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Any

from Crypto.Cipher import AES

from .hse2_header import HSE2_MAGIC
from .hse2_streaming import read_hse2_header_frame
from .kdf_profiles import derive_argon2id_key
from .key_wrapping import unwrap_data_key
from .streaming_primitives import (
    CHUNK_HEADER_STRUCT,
    MAX_CHUNK_SIZE,
    TAG_LEN,
    TRAILER_NONCE_INDEX,
    TRAILER_STRUCT,
    HeaderError,
    IntegrityError,
    derive_nonce,
)


@dataclass(frozen=True)
class HSE2ValidationReport:
    """Report for one HSE2 container validation attempt."""

    input: str
    ok: bool
    header_ok: bool
    payload_ok: bool
    file_size: int | None = None
    version: int | None = None
    content_algorithm: str | None = None
    kdf_profile: str | None = None
    chunk_size: int | None = None
    chunk_count: int | None = None
    plaintext_size: int | None = None
    plaintext_sha256: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "ok": self.ok,
            "header_ok": self.header_ok,
            "payload_ok": self.payload_ok,
            "file_size": self.file_size,
            "version": self.version,
            "content_algorithm": self.content_algorithm,
            "kdf_profile": self.kdf_profile,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "plaintext_size": self.plaintext_size,
            "plaintext_sha256": self.plaintext_sha256,
            "error": self.error,
        }


def validate_hse2_file(source: str | Path, wrapper: str) -> HSE2ValidationReport:
    """Validate an HSE2 container without writing plaintext output."""

    source_path = Path(source)
    try:
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        if not wrapper:
            raise ValueError("wrapper is required")
        file_size = source_path.stat().st_size
        min_size = len(HSE2_MAGIC) + 4 + TRAILER_STRUCT.size
        if file_size < min_size:
            raise IntegrityError("ciphertext is too short")
        with source_path.open("rb") as src:
            _header_frame, header = read_hse2_header_frame(src)
            if header.chunk_size <= 0 or header.chunk_size > MAX_CHUNK_SIZE:
                raise HeaderError("unsupported chunk size")
            payload_aad = header.associated_data()
            wrapping_key = derive_argon2id_key(wrapper, header.kdf_salt, header.kdf)
            try:
                data_key = unwrap_data_key(header.wrapped_data_key, wrapping_key)
            except ValueError as exc:
                raise IntegrityError("wrapped data key authentication failed") from exc
            payload_end = file_size - TRAILER_STRUCT.size
            chunk_index = 0
            total_plaintext_size = 0
            plaintext_digest = hashlib.sha256()
            while src.tell() < payload_end:
                meta = src.read(CHUNK_HEADER_STRUCT.size)
                if len(meta) != CHUNK_HEADER_STRUCT.size:
                    raise IntegrityError("truncated chunk metadata")
                read_index, plaintext_length = CHUNK_HEADER_STRUCT.unpack(meta)
                if read_index != chunk_index:
                    raise IntegrityError("unexpected chunk order")
                if plaintext_length == 0 or plaintext_length > header.chunk_size:
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
                cipher = AES.new(data_key, AES.MODE_GCM, nonce=derive_nonce(header.base_nonce, chunk_index))
                cipher.update(payload_aad + meta)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError as exc:
                    raise IntegrityError("chunk authentication failed") from exc
                total_plaintext_size += len(plaintext)
                plaintext_digest.update(plaintext)
                chunk_index += 1
            trailer_blob = src.read(TRAILER_STRUCT.size)
            if len(trailer_blob) != TRAILER_STRUCT.size:
                raise IntegrityError("truncated trailer")
            expected_chunk_count, expected_plaintext_size, expected_digest, trailer_tag = TRAILER_STRUCT.unpack(trailer_blob)
            trailer_meta = struct.pack(">QQ32s", expected_chunk_count, expected_plaintext_size, expected_digest)
            trailer_cipher = AES.new(data_key, AES.MODE_GCM, nonce=derive_nonce(header.base_nonce, TRAILER_NONCE_INDEX))
            trailer_cipher.update(payload_aad + trailer_meta)
            try:
                trailer_cipher.decrypt_and_verify(b"", trailer_tag)
            except ValueError as exc:
                raise IntegrityError("trailer authentication failed") from exc
            if expected_chunk_count != chunk_index:
                raise IntegrityError("chunk count mismatch")
            if expected_plaintext_size != total_plaintext_size:
                raise IntegrityError("plaintext size mismatch")
            digest_bytes = plaintext_digest.digest()
            if expected_digest != digest_bytes:
                raise IntegrityError("plaintext digest mismatch")
            return HSE2ValidationReport(
                input=str(source_path),
                ok=True,
                header_ok=True,
                payload_ok=True,
                file_size=file_size,
                version=header.version,
                content_algorithm=header.content_algorithm,
                kdf_profile=header.kdf.name,
                chunk_size=header.chunk_size,
                chunk_count=chunk_index,
                plaintext_size=total_plaintext_size,
                plaintext_sha256=digest_bytes.hex(),
            )
    except HeaderError as exc:
        return HSE2ValidationReport(input=str(source_path), ok=False, header_ok=False, payload_ok=False, error=f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 - validation reports normalize item failures.
        return HSE2ValidationReport(input=str(source_path), ok=False, header_ok=True, payload_ok=False, error=f"{type(exc).__name__}: {exc}")
