"""HSE2 header backup and restore helpers.

Header backups contain the preamble plus authenticated header frame and may append
recovery metadata. They do not include plaintext keys, decrypted manifests,
decrypted payload chunks, passwords, or user-facing GUI flows.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .container_codec import HSE2_PREAMBLE_SIZE, HSE2Preamble, decode_header_frame, encode_header_frame
from .file_io import read_container_bytes, write_container_bytes
from .models import HSE2Header, HSE2ModelError

HEADER_BACKUP_METADATA_MARKER = b"\n--HSE2-HEADER-BACKUP-METADATA-v1--\n"
HEADER_BACKUP_METADATA_FORMAT = "HSE2-header-backup-metadata-v1"


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
        if fmt != HEADER_BACKUP_METADATA_FORMAT:
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
    return encode_header_frame(header)


def export_header_backup_package_bytes(header: HSE2Header, metadata: HSE2HeaderBackupMetadata | None = None) -> bytes:
    """Export a header backup, optionally with non-secret recovery metadata."""

    data = export_header_backup_bytes(header)
    if metadata is None:
        return data
    return data + HEADER_BACKUP_METADATA_MARKER + _canonical_json_bytes(metadata.to_dict())


def restore_header_from_backup_bytes(data: bytes) -> HSE2Header:
    """Restore an HSE2 header from header backup bytes."""

    _, header, trailing = decode_header_frame(data)
    _metadata_from_trailing_bytes(trailing)
    if header.header_auth_tag is None:
        raise HSE2ModelError("restored header backup is missing header auth tag")
    return header


def read_header_backup_metadata_bytes(data: bytes) -> HSE2HeaderBackupMetadata | None:
    """Read optional non-secret recovery metadata from header backup bytes."""

    _, _, trailing = decode_header_frame(data)
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

    data = read_container_bytes(container_path)
    _, header, body = decode_header_frame(data)
    if not body:
        raise HSE2ModelError("container body is missing")
    metadata = HSE2HeaderBackupMetadata(
        body_offset=len(data) - len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_size=len(body),
        container_size=len(data),
    )
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
    restored = replace_container_header_with_backup_bytes(
        read_container_bytes(container_path),
        backup_data,
        body_offset=body_offset,
        verify_body_digest=verify_body_digest,
    )
    write_container_bytes(output_path, restored, overwrite=overwrite)
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
    if len(data) < HSE2_PREAMBLE_SIZE:
        raise HSE2ModelError("data is too short to contain an HSE2 preamble")
    preamble = HSE2Preamble.from_bytes(data[:HSE2_PREAMBLE_SIZE])
    header_end = HSE2_PREAMBLE_SIZE + preamble.header_length
    if len(data) < header_end:
        raise HSE2ModelError("data is too short to contain the declared HSE2 header")
    return header_end


def _backup_frame_length(backup_data: bytes) -> int:
    _, _, trailing = decode_header_frame(backup_data)
    return len(backup_data) - len(trailing)


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
    if body_offset != metadata.body_offset:
        raise HSE2ModelError("body_offset does not match header backup metadata")
    if len(body) != metadata.body_size:
        raise HSE2ModelError("container body size does not match header backup metadata")
    if body_offset + len(body) != metadata.container_size:
        raise HSE2ModelError("container size does not match header backup metadata")
    if verify_digest and hashlib.sha256(body).hexdigest() != metadata.body_sha256:
        raise HSE2ModelError("container body digest does not match header backup metadata")


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _required_non_negative_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or value < 0:
        raise HSE2ModelError(f"header backup metadata {key} is invalid")
    return value
