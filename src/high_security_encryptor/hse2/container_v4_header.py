"""Fixed public header and length checks for the experimental HSE2 v4 candidate."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .container_v4_credentials import V4_CREDENTIAL_SLOT_SIZE, V4CredentialSlot
from .container_v4_crypto import V4_DESCRIPTOR_SIZE, V4_MAX_RECORDS, V4_RECORD_SIZE, V4_VERSION
from .models import HSE2ModelError

V4_MAGIC = b"HSE2"
V4_HEADER_ENCODING = 2
V4_PUBLIC_HEADER_STRUCT = struct.Struct(">4sBBHII")
V4_PUBLIC_HEADER_SIZE = V4_PUBLIC_HEADER_STRUCT.size + 2 * V4_CREDENTIAL_SLOT_SIZE
V4_DESCRIPTOR_PAIR_SIZE = 2 * V4_DESCRIPTOR_SIZE


@dataclass(frozen=True)
class V4PublicHeader:
    capacity_records: int
    credential_slots: tuple[V4CredentialSlot, V4CredentialSlot]

    def __post_init__(self) -> None:
        if type(self.capacity_records) is not int or not 1 <= self.capacity_records <= V4_MAX_RECORDS:
            raise HSE2ModelError("invalid v4 record capacity")
        if not isinstance(self.credential_slots, tuple) or len(self.credential_slots) != 2:
            raise HSE2ModelError("v4 header requires two credential slots")
        if not all(isinstance(slot, V4CredentialSlot) for slot in self.credential_slots):
            raise HSE2ModelError("invalid v4 credential slots")
        if self.credential_slots[0].profile_id != self.credential_slots[1].profile_id:
            raise HSE2ModelError("v4 credential slots must use the same profile")

    def to_bytes(self) -> bytes:
        prefix = V4_PUBLIC_HEADER_STRUCT.pack(
            V4_MAGIC, V4_VERSION, V4_HEADER_ENCODING, 0,
            self.capacity_records, V4_DESCRIPTOR_SIZE,
        )
        data = prefix + self.credential_slots[0].to_bytes() + self.credential_slots[1].to_bytes()
        if len(data) != V4_PUBLIC_HEADER_SIZE:
            raise HSE2ModelError("invalid v4 public header size")
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "V4PublicHeader":
        if not isinstance(data, bytes) or len(data) != V4_PUBLIC_HEADER_SIZE:
            raise HSE2ModelError("invalid v4 public header length")
        magic, version, encoding, reserved, capacity, descriptor_size = V4_PUBLIC_HEADER_STRUCT.unpack_from(data)
        if (magic, version, encoding, reserved, descriptor_size) != (
            V4_MAGIC, V4_VERSION, V4_HEADER_ENCODING, 0, V4_DESCRIPTOR_SIZE
        ):
            raise HSE2ModelError("unsupported or malformed v4 public header")
        offset = V4_PUBLIC_HEADER_STRUCT.size
        slot0 = V4CredentialSlot.from_bytes(data[offset:offset + V4_CREDENTIAL_SLOT_SIZE])
        offset += V4_CREDENTIAL_SLOT_SIZE
        slot1 = V4CredentialSlot.from_bytes(data[offset:offset + V4_CREDENTIAL_SLOT_SIZE])
        return cls(capacity, (slot0, slot1))


def v4_container_size(capacity_records: int) -> int:
    """Return the exact file size, rejecting capacities outside the fixed bound."""

    if type(capacity_records) is not int or not 1 <= capacity_records <= V4_MAX_RECORDS:
        raise HSE2ModelError("invalid v4 record capacity")
    return V4_PUBLIC_HEADER_SIZE + V4_DESCRIPTOR_PAIR_SIZE + capacity_records * V4_RECORD_SIZE


def validate_v4_container_size(header: V4PublicHeader, actual_size: int) -> None:
    if type(actual_size) is not int or actual_size != v4_container_size(header.capacity_records):
        raise HSE2ModelError("invalid v4 container size")
