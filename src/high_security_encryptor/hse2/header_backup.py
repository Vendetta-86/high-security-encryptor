"""HSE2 header backup and restore helpers.

Header backups contain the preamble plus authenticated header frame and may append
recovery metadata. They do not include plaintext keys, decrypted manifests,
decrypted payload chunks, passwords, or user-facing GUI flows.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..atomic_io import atomic_output_path, flush_file
from .container_codec import HSE2_MAGIC, HSE2_PREAMBLE_SIZE, HSE2_PREAMBLE_STRUCT, decode_header_frame, encode_header_frame
from .container_stream import read_v3_header_frame, write_v3_header_frame
from .file_io import read_container_bytes, write_container_bytes
from .models import HSE2Header, HSE2ModelError

HEADER_BACKUP_METADATA_MARKER = b"\n--HSE2-HEADER-BACKUP-METADATA-v1--\n"
HEADER_BACKUP_METADATA_FORMAT = "HSE2-header-backup-metadata-v1"
HEADER_BACKUP_METADATA_V3_FORMAT = "HSE2-header-backup-metadata-v3"
_COPY_BUFFER_SIZE = 128 * 1024


@dataclass(frozen=True)
class HSE2HeaderBackupMetadata:
    """Non-secret recovery metadata stored after a header backup frame."""

    body_offset: int
    body_sha256: str
    body_size: int
    container_size: int
    format: str = HEADER_BACKUP_METADATA_FORMAT

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "body_offset": self.body_offset,
            "body_sha256": self.body_sha256,
            "body_size": self.body_size,
            "container_size": self.container_size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HSE2HeaderBackupMetadata":
        if not isinstance(data, dict):
            raise HSE2ModelError("header backup metadata must be a dictionary")
        fmt = data.get("format")
        if fmt not in {HEADER_BACKUP_METADATA_FORMAT, HEADER_BACKUP_METADATA_V3_FORMAT}:
            raise HSE2ModelError("unsupported header backup metadata format")
        body_offset = _required_non_negative_int(data, "body_offset")
        body_size = _required_non_negative_int(data, "body_size")
        container_size = _required_non_negative_int(data, "container_size")
        body_sha256 = data.get("body_sha256")
        if not isinstance(body_sha256, str) or len(body_sha256) != 64:
            raise HSE2ModelError("header backup metadata body_sha256 is invalid")
        return cls(
            body_offset=body_offset,
            body_sha256=body_sha256,
            body_size=body_size,
            container_size=container_size,
            format=fmt,
        )


def export_header_backup_bytes(header: HSE2Header) -> bytes:
    """Export an HSE2 header backup as preamble + authenticated header bytes."""

    if header.header_auth_tag is None:
        raise HSE2ModelError("cannot export header backup without header auth tag")
    if header.format_version == 3:
        stream = BytesIO()
        write_v3_header_frame(stream, header)
        return stream.getvalue()
    return encode_header_frame(header)


def export_header_backup_package_bytes(header: HSE2Header, metadata: HSE2HeaderBackupMetadata | None = None) -> bytes:
    """Export a header backup, optionally with non-secret recovery metadata."""

    data = export_header_backup_bytes(header)
    if metadata is None:
        return data
    return data + HEADER_BACKUP_METADATA_MARKER + _canonical_json_bytes(metadata.to_dict())


def restore_header_from_backup_bytes(data: bytes) -> HSE2Header:
    """Restore an HSE2 header from header backup bytes."""

    header, trailing, _frame = _decode_backup_frame(data)
    _metadata_from_trailing_bytes(trailing)
    if header.header_auth_tag is None:
        raise HSE2ModelError("restored header backup is missing header auth tag")
    return header


def read_header_backup_metadata_bytes(data: bytes) -> HSE2HeaderBackupMetadata | None:
    """Read optional non-secret recovery metadata from header backup bytes."""

    _header, trailing, _frame = _decode_backup_frame(data)
    return _metadata_from_trailing_bytes(trailing)


def replace_container_header_with_backup_bytes(
    container_data: bytes,
    backup_data: bytes,
    *,
    body_offset: int | None = None,
    verify_body_digest: bool = True,
) -> bytes:
    """Replace a container header frame with a backup header frame.

    If ``body_offset`` is omitted, metadata is preferred. If no metadata exists,
    this function first tries the current container preamble/header length, then
    falls back to the backup frame length. The fallback is useful when the current
    container preamble is damaged but the encrypted body still starts at the same
    offset as the original header backup frame.
    """

    backup_header = restore_header_from_backup_bytes(backup_data)
    metadata = read_header_backup_metadata_bytes(backup_data)
    chosen_offset = _select_body_offset(container_data, backup_data, body_offset=body_offset, metadata=metadata)
    body = _container_body_from_offset(container_data, chosen_offset)
    if metadata is not None:
        _validate_metadata_for_body(metadata, body_offset=chosen_offset, body=body, verify_digest=verify_body_digest)
    return export_header_backup_bytes(backup_header) + body


def write_header_backup(path: str | os.PathLike[str], header: HSE2Header, *, overwrite: bool = False) -> None:
    """Write a header backup to a filesystem path."""

    write_container_bytes(path, export_header_backup_bytes(header), overwrite=overwrite)


def read_header_backup(path: str | os.PathLike[str]) -> HSE2Header:
    """Read and restore an HSE2 header backup from a filesystem path."""

    return restore_header_from_backup_bytes(read_container_bytes(Path(path)))


def read_header_backup_metadata(path: str | os.PathLike[str]) -> HSE2HeaderBackupMetadata | None:
    """Read optional non-secret recovery metadata from a header backup path."""

    return read_header_backup_metadata_bytes(read_container_bytes(Path(path)))


def export_header_backup_from_container(
    *,
    container_path: str | os.PathLike[str],
    backup_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> tuple[HSE2Header, HSE2HeaderBackupMetadata]:
    """Export the authenticated header frame plus recovery metadata from a container."""

    source = Path(container_path)
    header, body_offset, header_frame = _read_header_frame_from_path(source)
    initial_size = source.stat().st_size
    body_size, body_digest = _hash_file_region(source, body_offset)
    if body_size == 0:
        raise HSE2ModelError("container body is missing")
    container_size = source.stat().st_size
    if initial_size != container_size or body_offset + body_size != container_size:
        raise HSE2ModelError("container changed while creating header backup")
    metadata_format = (
        HEADER_BACKUP_METADATA_V3_FORMAT if header.format_version == 3 else HEADER_BACKUP_METADATA_FORMAT
    )
    metadata = HSE2HeaderBackupMetadata(
        body_offset=body_offset,
        body_sha256=body_digest,
        body_size=body_size,
        container_size=container_size,
        format=metadata_format,
    )
    if header_frame != export_header_backup_bytes(header):
        raise HSE2ModelError("container header frame changed while creating backup")
    write_container_bytes(backup_path, export_header_backup_package_bytes(header, metadata), overwrite=overwrite)
    return header, metadata


def restore_container_header_from_backup(
    *,
    container_path: str | os.PathLike[str],
    backup_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
    body_offset: int | None = None,
    verify_body_digest: bool = True,
) -> tuple[HSE2Header, HSE2HeaderBackupMetadata | None]:
    """Write a container copy whose header frame comes from a backup file."""

    backup_data = read_container_bytes(backup_path)
    backup_header = restore_header_from_backup_bytes(backup_data)
    metadata = read_header_backup_metadata_bytes(backup_data)
    source = Path(container_path)
    target = Path(output_path)
    backup_frame = export_header_backup_bytes(backup_header)
    if body_offset is not None:
        chosen_offset = body_offset
    elif metadata is not None:
        chosen_offset = metadata.body_offset
    else:
        try:
            _current_header, chosen_offset, _current_frame = _read_header_frame_from_path(source)
        except HSE2ModelError:
            chosen_offset = len(backup_frame)
    if chosen_offset < 0:
        raise HSE2ModelError("body_offset must be non-negative")
    if target.exists() and not overwrite:
        raise HSE2ModelError(f"target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with atomic_output_path(target) as temp_path:
        digest = hashlib.sha256()
        body_size = 0
        with temp_path.open("wb") as dst:
            with source.open("rb") as src:
                src.seek(chosen_offset)
                dst.write(backup_frame)
                while True:
                    block = src.read(_COPY_BUFFER_SIZE)
                    if not block:
                        break
                    digest.update(block)
                    body_size += len(block)
                    dst.write(block)
            if body_size == 0:
                raise HSE2ModelError("container body is missing")
            if metadata is not None:
                _validate_metadata_values(
                    metadata,
                    body_offset=chosen_offset,
                    body_size=body_size,
                    body_sha256=digest.hexdigest(),
                    verify_digest=verify_body_digest,
                )
            flush_file(dst)
    return backup_header, metadata


def _metadata_from_trailing_bytes(trailing: bytes) -> HSE2HeaderBackupMetadata | None:
    if not trailing:
        return None
    if not trailing.startswith(HEADER_BACKUP_METADATA_MARKER):
        raise HSE2ModelError("header backup must not contain trailing container body data")
    metadata_bytes = trailing[len(HEADER_BACKUP_METADATA_MARKER) :]
    try:
        value = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HSE2ModelError("header backup metadata is not valid JSON") from exc
    return HSE2HeaderBackupMetadata.from_dict(value)


def _select_body_offset(
    container_data: bytes,
    backup_data: bytes,
    *,
    body_offset: int | None,
    metadata: HSE2HeaderBackupMetadata | None,
) -> int:
    if body_offset is not None:
        if body_offset < 0:
            raise HSE2ModelError("body_offset must be non-negative")
        return body_offset
    if metadata is not None:
        return metadata.body_offset
    try:
        return _declared_body_offset(container_data)
    except HSE2ModelError:
        return _backup_frame_length(backup_data)


def _declared_body_offset(data: bytes) -> int:
    _header, _trailing, frame = _decode_backup_frame(data)
    return len(frame)


def _backup_frame_length(backup_data: bytes) -> int:
    _header, _trailing, frame = _decode_backup_frame(backup_data)
    return len(frame)


def _container_body_from_offset(data: bytes, body_offset: int) -> bytes:
    if body_offset < 0:
        raise HSE2ModelError("body_offset must be non-negative")
    if len(data) <= body_offset:
        raise HSE2ModelError("container body is missing")
    return data[body_offset:]


def _validate_metadata_for_body(
    metadata: HSE2HeaderBackupMetadata,
    *,
    body_offset: int,
    body: bytes,
    verify_digest: bool,
) -> None:
    _validate_metadata_values(
        metadata,
        body_offset=body_offset,
        body_size=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        verify_digest=verify_digest,
    )


def _validate_metadata_values(
    metadata: HSE2HeaderBackupMetadata,
    *,
    body_offset: int,
    body_size: int,
    body_sha256: str,
    verify_digest: bool,
) -> None:
    if body_offset != metadata.body_offset:
        raise HSE2ModelError("body_offset does not match header backup metadata")
    if body_size != metadata.body_size:
        raise HSE2ModelError("container body size does not match header backup metadata")
    if body_offset + body_size != metadata.container_size:
        raise HSE2ModelError("container size does not match header backup metadata")
    if verify_digest and body_sha256 != metadata.body_sha256:
        raise HSE2ModelError("container body digest does not match header backup metadata")


def _decode_backup_frame(data: bytes) -> tuple[HSE2Header, bytes, bytes]:
    if len(data) < HSE2_PREAMBLE_SIZE:
        raise HSE2ModelError("data is too short to contain an HSE2 preamble")
    magic, version, _encoding, _reserved, _header_length = HSE2_PREAMBLE_STRUCT.unpack(
        data[:HSE2_PREAMBLE_SIZE]
    )
    if magic != HSE2_MAGIC:
        raise HSE2ModelError("invalid HSE2 magic")
    if version == 2:
        _preamble, header, trailing = decode_header_frame(data)
        frame = data[: len(data) - len(trailing)]
        return header, trailing, frame
    if version == 3:
        stream = BytesIO(data)
        frame, header = read_v3_header_frame(stream)
        return header, stream.read(), frame
    raise HSE2ModelError(f"unsupported HSE2 container version: {version}")


def _read_header_frame_from_path(path: str | os.PathLike[str]) -> tuple[HSE2Header, int, bytes]:
    target = Path(path)
    try:
        with target.open("rb") as stream:
            preamble = stream.read(HSE2_PREAMBLE_SIZE)
            if len(preamble) != HSE2_PREAMBLE_SIZE:
                raise HSE2ModelError("HSE2 preamble is truncated")
            magic, version, _encoding, _reserved, header_length = HSE2_PREAMBLE_STRUCT.unpack(preamble)
            if magic != HSE2_MAGIC:
                raise HSE2ModelError("invalid HSE2 magic")
            stream.seek(0)
            if version == 3:
                frame, header = read_v3_header_frame(stream)
            elif version == 2:
                frame = stream.read(HSE2_PREAMBLE_SIZE + header_length)
                _preamble, header, _trailing = decode_header_frame(frame)
            else:
                raise HSE2ModelError(f"unsupported HSE2 container version: {version}")
            return header, stream.tell(), frame
    except OSError as exc:
        raise HSE2ModelError(f"cannot read HSE2 header: {target}") from exc


def _hash_file_region(path: str | os.PathLike[str], offset: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        stream.seek(offset)
        while True:
            block = stream.read(_COPY_BUFFER_SIZE)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _required_non_negative_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or value < 0:
        raise HSE2ModelError(f"header backup metadata {key} is invalid")
    return value
