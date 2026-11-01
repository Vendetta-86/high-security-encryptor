"""Fixed-size encrypted descriptor codec for the experimental HSE2 v4 candidate."""

from __future__ import annotations

import json
import secrets
import struct
from dataclasses import dataclass

from .container_v4_crypto import (
    V4_DESCRIPTOR_SIZE,
    V4_HKDF_SALT_SIZE,
    V4_MAX_RECORDS,
    V4_RECORD_SIZE,
    V4_GCM_NONCE_SIZE,
    V4_GCM_TAG_SIZE,
    V4Sealed,
    derive_v4_key,
    open_v4,
    seal_v4,
)
from .container_v4_records import V4_RECORD_PAYLOAD_SIZE
from .models import HSE2ModelError, canonical_json_bytes

V4_DESCRIPTOR_MAGIC = b"H4VD"
V4_DESCRIPTOR_VERSION = 1
V4_DESCRIPTOR_HEADER = struct.Struct(">4sBBII")
V4_DESCRIPTOR_RECORD = struct.Struct(">II")
V4_DESCRIPTOR_PREFIX_SIZE = V4_HKDF_SALT_SIZE + V4_GCM_NONCE_SIZE
V4_DESCRIPTOR_CIPHERTEXT_SIZE = V4_DESCRIPTOR_SIZE - V4_DESCRIPTOR_PREFIX_SIZE - V4_GCM_TAG_SIZE
V4_DESCRIPTOR_MANIFEST_LIMIT = 63 * 1024 * 1024
V4_DESCRIPTOR_PLAINTEXT_HEADER_SIZE = V4_DESCRIPTOR_HEADER.size


@dataclass(frozen=True)
class V4ViewDescriptor:
    manifest: dict[str, object]
    record_lengths: dict[int, int]


def _validate_location(slot: int, capacity_records: int) -> None:
    if type(slot) is not int or slot not in (0, 1):
        raise HSE2ModelError("invalid v4 descriptor slot")
    if type(capacity_records) is not int or not 2 <= capacity_records <= V4_MAX_RECORDS or capacity_records % 2:
        raise HSE2ModelError("invalid v4 record capacity")


def _aad(slot: int, capacity_records: int) -> bytes:
    return f"HSE2:v4:descriptor:{slot}:{capacity_records}:{V4_RECORD_SIZE}:{V4_DESCRIPTOR_SIZE}:v1".encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HSE2ModelError("v4 descriptor manifest contains duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise HSE2ModelError(f"invalid JSON constant: {value}")


def seal_v4_descriptor(
    *, view_root_key: bytes, slot: int, capacity_records: int,
    manifest: dict[str, object], record_lengths: dict[int, int],
) -> bytes:
    """Encode and encrypt one fixed 64 MiB view descriptor region."""

    _validate_location(slot, capacity_records)
    if not isinstance(manifest, dict) or not isinstance(record_lengths, dict):
        raise HSE2ModelError("invalid v4 descriptor values")
    try:
        manifest_bytes = canonical_json_bytes(manifest)
        normalized_manifest = json.loads(
            manifest_bytes.decode("utf-8"), parse_constant=_reject_json_constant
        )
        if not isinstance(normalized_manifest, dict) or canonical_json_bytes(normalized_manifest) != manifest_bytes:
            raise HSE2ModelError("invalid v4 descriptor manifest")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HSE2ModelError("invalid v4 descriptor manifest") from exc
    if len(manifest_bytes) > V4_DESCRIPTOR_MANIFEST_LIMIT:
        raise HSE2ModelError("v4 descriptor manifest exceeds limit")
    if len(record_lengths) > min(capacity_records, V4_MAX_RECORDS):
        raise HSE2ModelError("v4 descriptor record count exceeds capacity")
    ordered = sorted(record_lengths.items())
    if any(
        type(index) is not int or not 0 <= index < capacity_records
        or index % 2 != slot
        or type(length) is not int or not 1 <= length <= V4_RECORD_PAYLOAD_SIZE
        for index, length in ordered
    ):
        raise HSE2ModelError("invalid v4 descriptor record map")
    body_size = V4_DESCRIPTOR_HEADER.size + len(ordered) * V4_DESCRIPTOR_RECORD.size + len(manifest_bytes)
    if body_size > V4_DESCRIPTOR_CIPHERTEXT_SIZE:
        raise HSE2ModelError("v4 descriptor exceeds fixed capacity")
    body = bytearray(V4_DESCRIPTOR_HEADER.pack(
        V4_DESCRIPTOR_MAGIC, V4_DESCRIPTOR_VERSION, slot, len(manifest_bytes), len(ordered)
    ))
    for index, length in ordered:
        body.extend(V4_DESCRIPTOR_RECORD.pack(index, length))
    body.extend(manifest_bytes)
    body.extend(secrets.token_bytes(V4_DESCRIPTOR_CIPHERTEXT_SIZE - len(body)))
    salt = secrets.token_bytes(V4_HKDF_SALT_SIZE)
    nonce = secrets.token_bytes(V4_GCM_NONCE_SIZE)
    key = derive_v4_key(
        root_key=view_root_key, salt=salt,
        info=f"HSE2:v4:view:{slot}:descriptor:v1".encode("ascii"),
    )
    encrypted = seal_v4(key=key, nonce=nonce, plaintext=bytes(body), aad=_aad(slot, capacity_records))
    region = salt + nonce + encrypted.ciphertext + encrypted.tag
    if len(region) != V4_DESCRIPTOR_SIZE:
        raise HSE2ModelError("invalid v4 descriptor output size")
    return region


def open_v4_descriptor(
    *, view_root_key: bytes, slot: int, capacity_records: int, region: bytes,
) -> V4ViewDescriptor:
    """Authenticate a complete fixed-size descriptor before parsing metadata."""

    _validate_location(slot, capacity_records)
    if not isinstance(region, bytes) or len(region) != V4_DESCRIPTOR_SIZE:
        raise HSE2ModelError("v4 descriptor authentication failed")
    salt = region[:V4_HKDF_SALT_SIZE]
    nonce_start = V4_HKDF_SALT_SIZE
    nonce = region[nonce_start:nonce_start + V4_GCM_NONCE_SIZE]
    cipher_start = V4_DESCRIPTOR_PREFIX_SIZE
    ciphertext = region[cipher_start:-V4_GCM_TAG_SIZE]
    tag = region[-V4_GCM_TAG_SIZE:]
    try:
        key = derive_v4_key(
            root_key=view_root_key, salt=salt,
            info=f"HSE2:v4:view:{slot}:descriptor:v1".encode("ascii"),
        )
        plaintext = open_v4(
            key=key, sealed=V4Sealed(nonce, ciphertext, tag), aad=_aad(slot, capacity_records)
        )
        magic, version, stored_slot, manifest_size, count = V4_DESCRIPTOR_HEADER.unpack_from(plaintext)
        if magic != V4_DESCRIPTOR_MAGIC or version != V4_DESCRIPTOR_VERSION or stored_slot != slot:
            raise HSE2ModelError("invalid v4 descriptor")
        if manifest_size > V4_DESCRIPTOR_MANIFEST_LIMIT or count > capacity_records:
            raise HSE2ModelError("invalid v4 descriptor bounds")
        map_end = V4_DESCRIPTOR_HEADER.size + count * V4_DESCRIPTOR_RECORD.size
        manifest_end = map_end + manifest_size
        if manifest_end > len(plaintext):
            raise HSE2ModelError("invalid v4 descriptor bounds")
        record_lengths: dict[int, int] = {}
        previous = -1
        for offset in range(V4_DESCRIPTOR_HEADER.size, map_end, V4_DESCRIPTOR_RECORD.size):
            index, length = V4_DESCRIPTOR_RECORD.unpack_from(plaintext, offset)
            if (index <= previous or index >= capacity_records or index % 2 != slot
                    or not 1 <= length <= V4_RECORD_PAYLOAD_SIZE):
                raise HSE2ModelError("invalid v4 descriptor record map")
            record_lengths[index] = length
            previous = index
        encoded_manifest = plaintext[map_end:manifest_end]
        manifest = json.loads(
            encoded_manifest.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(manifest, dict) or canonical_json_bytes(manifest) != encoded_manifest:
            raise HSE2ModelError("invalid v4 descriptor manifest")
        return V4ViewDescriptor(manifest=manifest, record_lengths=record_lengths)
    except (HSE2ModelError, ValueError, UnicodeError, json.JSONDecodeError, struct.error, RecursionError) as exc:
        raise HSE2ModelError("v4 descriptor authentication failed") from exc

