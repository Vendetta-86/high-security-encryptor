"""Fixed v5 header and EOF footer framing."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .container_v5_credentials import V5_CREDENTIAL_SLOT_SIZE, V5CredentialSlot
from .container_v5_crypto import V5_MAX_CONTAINER_SIZE, V5_MAX_DESCRIPTOR_SIZE, V5_VERSION
from .models import HSE2ModelError

V5_HEADER_PREFIX = struct.Struct(">4sBBH16s")
V5_HEADER_SIZE = V5_HEADER_PREFIX.size + 2 * V5_CREDENTIAL_SLOT_SIZE
V5_FOOTER_PREFIX = struct.Struct(">4sHH")
V5_FOOTER_ENTRY = struct.Struct(">QQQ")
V5_FOOTER_SIZE = V5_FOOTER_PREFIX.size + 2 * V5_FOOTER_ENTRY.size
V5_FOOTER_VERSION = 1


@dataclass(frozen=True)
class V5PublicHeader:
    archive_id: bytes
    credential_slots: tuple[V5CredentialSlot, V5CredentialSlot]

    def __post_init__(self) -> None:
        if not isinstance(self.archive_id, bytes) or len(self.archive_id) != 16:
            raise HSE2ModelError("v5 archive id must be 16 bytes")
        if (not isinstance(self.credential_slots, tuple) or len(self.credential_slots) != 2
                or not all(isinstance(slot, V5CredentialSlot) for slot in self.credential_slots)):
            raise HSE2ModelError("v5 header requires two credential slots")
        if self.credential_slots[0].profile_id != self.credential_slots[1].profile_id:
            raise HSE2ModelError("v5 credential profiles must match")

    def to_bytes(self) -> bytes:
        prefix = V5_HEADER_PREFIX.pack(b"HSE2", V5_VERSION, 2, 0, self.archive_id)
        return prefix + b"".join(slot.to_bytes() for slot in self.credential_slots)

    @classmethod
    def from_bytes(cls, data: bytes) -> "V5PublicHeader":
        if not isinstance(data, bytes) or len(data) != V5_HEADER_SIZE:
            raise HSE2ModelError("invalid v5 public header length")
        magic, version, encoding, flags, archive_id = V5_HEADER_PREFIX.unpack_from(data)
        if (magic, version, encoding, flags) != (b"HSE2", V5_VERSION, 2, 0):
            raise HSE2ModelError("unsupported or malformed v5 public header")
        offset = V5_HEADER_PREFIX.size
        first = V5CredentialSlot.from_bytes(data[offset:offset + V5_CREDENTIAL_SLOT_SIZE])
        offset += V5_CREDENTIAL_SLOT_SIZE
        second = V5CredentialSlot.from_bytes(data[offset:offset + V5_CREDENTIAL_SLOT_SIZE])
        return cls(archive_id, (first, second))


@dataclass(frozen=True)
class V5FooterEntry:
    offset: int
    length: int
    generation: int

    def __post_init__(self) -> None:
        if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF
               for value in (self.offset, self.length, self.generation)):
            raise HSE2ModelError("invalid v5 footer entry")
        if self.generation < 1 or not 60 <= self.length <= V5_MAX_DESCRIPTOR_SIZE:
            raise HSE2ModelError("invalid v5 descriptor pointer")


@dataclass(frozen=True)
class V5Footer:
    views: tuple[V5FooterEntry, V5FooterEntry]

    def __post_init__(self) -> None:
        if (not isinstance(self.views, tuple) or len(self.views) != 2
                or not all(isinstance(entry, V5FooterEntry) for entry in self.views)):
            raise HSE2ModelError("v5 footer requires two descriptors")

    def to_bytes(self) -> bytes:
        return (V5_FOOTER_PREFIX.pack(b"H5FT", V5_FOOTER_VERSION, 0)
                + b"".join(V5_FOOTER_ENTRY.pack(e.offset, e.length, e.generation) for e in self.views))

    @classmethod
    def from_bytes(cls, data: bytes, *, file_size: int) -> "V5Footer":
        if not isinstance(data, bytes) or len(data) != V5_FOOTER_SIZE:
            raise HSE2ModelError("invalid v5 footer length")
        if type(file_size) is not int or not V5_HEADER_SIZE + V5_FOOTER_SIZE <= file_size <= V5_MAX_CONTAINER_SIZE:
            raise HSE2ModelError("invalid v5 container size")
        magic, version, reserved = V5_FOOTER_PREFIX.unpack_from(data)
        if (magic, version, reserved) != (b"H5FT", V5_FOOTER_VERSION, 0):
            raise HSE2ModelError("invalid v5 footer")
        entries = []
        footer_offset = file_size - V5_FOOTER_SIZE
        cursor = V5_FOOTER_PREFIX.size
        for _slot in range(2):
            offset, length, generation = V5_FOOTER_ENTRY.unpack_from(data, cursor)
            cursor += V5_FOOTER_ENTRY.size
            entry = V5FooterEntry(offset, length, generation)
            if offset < V5_HEADER_SIZE or offset + length > footer_offset:
                raise HSE2ModelError("v5 descriptor pointer is out of bounds")
            entries.append(entry)
        first, second = entries
        if max(first.offset, second.offset) < min(first.offset + first.length, second.offset + second.length):
            raise HSE2ModelError("v5 descriptor pointers overlap")
        return cls((first, second))
