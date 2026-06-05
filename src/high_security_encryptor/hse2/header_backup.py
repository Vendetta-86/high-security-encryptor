"""HSE2 header backup and restore helpers.

Header backups contain only the preamble plus authenticated header frame. They do
not include plaintext keys, decrypted manifests, decrypted payload chunks,
passwords, or user-facing GUI flows.
"""

from __future__ import annotations

import os
from pathlib import Path

from .container_codec import HSE2_PREAMBLE_SIZE, HSE2Preamble, decode_header_frame, encode_header_frame
from .file_io import read_container_bytes, write_container_bytes
from .models import HSE2Header, HSE2ModelError


def export_header_backup_bytes(header: HSE2Header) -> bytes:
    """Export an HSE2 header backup as preamble + authenticated header bytes."""

    if header.header_auth_tag is None:
        raise HSE2ModelError("cannot export header backup without header auth tag")
    return encode_header_frame(header)


def restore_header_from_backup_bytes(data: bytes) -> HSE2Header:
    """Restore an HSE2 header from header backup bytes."""

    _, header, trailing = decode_header_frame(data)
    if trailing:
        raise HSE2ModelError("header backup must not contain trailing container body data")
    if header.header_auth_tag is None:
        raise HSE2ModelError("restored header backup is missing header auth tag")
    return header


def replace_container_header_with_backup_bytes(container_data: bytes, backup_data: bytes) -> bytes:
    """Replace a container header frame with a backup header frame.

    The current container preamble must remain readable so the existing body
    offset can be determined without parsing the possibly damaged header JSON.
    The encrypted manifest and payload body bytes are copied unchanged.
    """

    backup_header = restore_header_from_backup_bytes(backup_data)
    body = _container_body_after_declared_header(container_data)
    return export_header_backup_bytes(backup_header) + body


def write_header_backup(path: str | os.PathLike[str], header: HSE2Header, *, overwrite: bool = False) -> None:
    """Write a header backup to a filesystem path."""

    write_container_bytes(path, export_header_backup_bytes(header), overwrite=overwrite)


def read_header_backup(path: str | os.PathLike[str]) -> HSE2Header:
    """Read and restore an HSE2 header backup from a filesystem path."""

    return restore_header_from_backup_bytes(read_container_bytes(Path(path)))


def export_header_backup_from_container(
    *,
    container_path: str | os.PathLike[str],
    backup_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> HSE2Header:
    """Export only the authenticated header frame from a full HSE2 container."""

    data = read_container_bytes(container_path)
    _, header, body = decode_header_frame(data)
    if not body:
        raise HSE2ModelError("container body is missing")
    write_header_backup(backup_path, header, overwrite=overwrite)
    return header


def restore_container_header_from_backup(
    *,
    container_path: str | os.PathLike[str],
    backup_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    overwrite: bool = False,
) -> HSE2Header:
    """Write a container copy whose header frame comes from a backup file."""

    backup_data = read_container_bytes(backup_path)
    backup_header = restore_header_from_backup_bytes(backup_data)
    restored = replace_container_header_with_backup_bytes(read_container_bytes(container_path), backup_data)
    write_container_bytes(output_path, restored, overwrite=overwrite)
    return backup_header


def _container_body_after_declared_header(data: bytes) -> bytes:
    if len(data) < HSE2_PREAMBLE_SIZE:
        raise HSE2ModelError("data is too short to contain an HSE2 preamble")
    preamble = HSE2Preamble.from_bytes(data[:HSE2_PREAMBLE_SIZE])
    header_end = HSE2_PREAMBLE_SIZE + preamble.header_length
    if len(data) < header_end:
        raise HSE2ModelError("data is too short to contain the declared HSE2 header")
    body = data[header_end:]
    if not body:
        raise HSE2ModelError("container body is missing")
    return body
