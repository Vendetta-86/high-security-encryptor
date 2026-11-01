from __future__ import annotations

import unittest
from io import BytesIO
import random

from high_security_encryptor.hse2.container_v4_credentials import V4CredentialSlot
from high_security_encryptor.hse2.container_v4_header import (
    V4_PUBLIC_HEADER_SIZE,
    V4_PUBLIC_HEADER_STRUCT,
    V4PublicHeader,
    v4_container_size,
    validate_v4_container_size,
)
from high_security_encryptor.hse2.container_codec import HSE2Preamble
from high_security_encryptor.hse2.container_stream import read_v3_header_frame
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4HeaderTests(unittest.TestCase):
    def setUp(self) -> None:
        slot0 = V4CredentialSlot(1, bytes(16), bytes(12), bytes(32), bytes(16))
        slot1 = V4CredentialSlot(1, bytes([1]) * 16, bytes([1]) * 12,
                                 bytes([1]) * 32, bytes([1]) * 16)
        self.header = V4PublicHeader(2, (slot0, slot1))

    def test_fixed_header_and_container_length(self) -> None:
        encoded = self.header.to_bytes()
        self.assertEqual(len(encoded), V4_PUBLIC_HEADER_SIZE)
        self.assertEqual(V4PublicHeader.from_bytes(encoded), self.header)
        expected = 170 + 2 * 67_108_864 + 2 * 1_048_576
        self.assertEqual(v4_container_size(2), expected)
        validate_v4_container_size(self.header, expected)
        with self.assertRaises(HSE2ModelError):
            validate_v4_container_size(self.header, expected - 1)

    def test_public_header_rejects_mutation_and_bad_length(self) -> None:
        encoded = bytearray(self.header.to_bytes())
        encoded[4] = 3
        with self.assertRaises(HSE2ModelError):
            V4PublicHeader.from_bytes(bytes(encoded))
        with self.assertRaises(HSE2ModelError):
            V4PublicHeader.from_bytes(bytes(encoded[:-1]))

    def test_public_header_rejects_malformed_fixed_fields_and_capacity_boundaries(self) -> None:
        encoded = self.header.to_bytes()
        cases = (
            (4, 3),                       # unsupported version
            (5, 1),                       # unsupported header encoding
            (6, 1),                       # nonzero reserved bytes
            (12, 1),                      # wrong descriptor size
            (8, 0),                       # zero capacity
            (8, 3),                       # odd capacity
            (8, 65537),                   # above the maximum
        )
        for offset, value in cases:
            with self.subTest(offset=offset, value=value):
                malformed = bytearray(encoded)
                if offset in (8, 12):
                    malformed[offset:offset + 4] = value.to_bytes(4, "big")
                elif offset == 6:
                    malformed[offset:offset + 2] = value.to_bytes(2, "big")
                else:
                    malformed[offset] = value
                with self.assertRaises(HSE2ModelError):
                    V4PublicHeader.from_bytes(bytes(malformed))

        maximum = V4_PUBLIC_HEADER_STRUCT.pack(b"HSE2", 4, 2, 0, 65536, 67_108_864)
        self.assertEqual(V4PublicHeader.from_bytes(maximum + encoded[V4_PUBLIC_HEADER_STRUCT.size:]),
                         V4PublicHeader(65536, self.header.credential_slots))
        with self.assertRaises(HSE2ModelError):
            v4_container_size(65538)
        with self.assertRaises(HSE2ModelError):
            v4_container_size(True)

    def test_public_header_rejects_deterministic_random_malformed_inputs(self) -> None:
        generator = random.Random(0x48325634)
        for index in range(64):
            payload = generator.randbytes(V4_PUBLIC_HEADER_SIZE)
            with self.subTest(sample=index), self.assertRaises(HSE2ModelError):
                V4PublicHeader.from_bytes(payload)

    def test_legacy_v2_and_v3_header_readers_reject_v4_marker(self) -> None:
        encoded = self.header.to_bytes()
        with self.assertRaises(HSE2ModelError):
            HSE2Preamble.from_bytes(encoded[:16])
        with self.assertRaises(HSE2ModelError):
            read_v3_header_frame(BytesIO(encoded))


if __name__ == "__main__":
    unittest.main()
