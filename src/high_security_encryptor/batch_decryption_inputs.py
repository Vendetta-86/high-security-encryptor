"""Input and sidecar helpers for batch decryption workflows."""

from __future__ import annotations

from pathlib import Path

from .batch_binding import BatchBinding, extract_binding
from .batch_payloads import deserialize_manifest_payload
from .metadata_crypto import read_encrypted_metadata_file


def discover_binding(manifest_path: str | Path, metadata_password: str) -> BatchBinding:
    """Read the manifest once to discover the authoritative batch binding."""

    manifest_payload = deserialize_manifest_payload(read_encrypted_metadata_file(manifest_path, metadata_password))
    return extract_binding(manifest_payload)


def build_top_level_password_mapping(
    password_table_payload: dict,
    password_overrides: dict[str, str],
) -> dict[str, str]:
    """Build the password mapping used for top-level encrypted outputs."""

    mapping = {
        str(record["encrypted_name"]): str(record["password"])
        for record in password_table_payload.get("records", [])
    }
    mapping.update({str(name): password for name, password in password_overrides.items()})
    return mapping


def derive_plain_file_output_name(encrypted_name: str) -> str:
    """Derive the plaintext output file name for a normal `.hse` file."""

    if not encrypted_name.endswith(".hse"):
        raise ValueError(f"expected .hse file name, got: {encrypted_name}")
    return encrypted_name[:-4]


def extract_manifest_entries(manifest_payload: dict) -> list[str]:
    """Extract encrypted entry names from a manifest payload."""

    return [str(entry["encrypted_name"]) for entry in manifest_payload.get("entries", [])]
