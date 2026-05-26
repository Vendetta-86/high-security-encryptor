"""HSE2 header backup and restore helpers.

Header backups contain only the preamble plus authenticated header frame. They do
not include plaintext keys, decrypted manifests, decrypted payload chunks, raw
keyfile material, passwords, or user-facing CLI/GUI flows.
"""

from __future__ import annotations

import os
from pathlib import Path

from .container_codec import decode_header_frame, encode_header_frame
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


def write_header_backup(path: str | os.PathLike[str], header: HSE2Header, *, overwrite: bool = False) -> None:
    """Write a header backup to a filesystem path."""

    write_container_bytes(path, export_header_backup_bytes(header), overwrite=overwrite)


def read_header_backup(path: str | os.PathLike[str]) -> HSE2Header:
    """Read and restore an HSE2 header backup from a filesystem path."""

    return restore_header_from_backup_bytes(read_container_bytes(Path(path)))
