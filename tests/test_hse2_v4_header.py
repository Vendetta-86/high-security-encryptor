from __future__ import annotations

import unittest

from high_security_encryptor.hse2.container_v4_credentials import V4CredentialSlot
from high_security_encryptor.hse2.container_v4_header import (
    V4_PUBLIC_HEADER_SIZE,
    V4PublicHeader,
    v4_container_size,
    validate_v4_container_size,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4HeaderTests(unittest.TestCase):
    def setUp(self) -> None:
        slot0 = V4CredentialSlot(1, bytes(16), bytes(12), bytes(32), bytes(16))
        slot1 = V4CredentialSlot(1, bytes([1]) * 16, bytes([1]) * 12,
                                 bytes([1]) * 32, bytes([1]) * 16)
        self.header = V4PublicHeader(3, (slot0, slot1))

    def test_fixed_header_and_container_length(self) -> None:
        encoded = self.header.to_bytes()
        self.assertEqual(len(encoded), V4_PUBLIC_HEADER_SIZE)
        self.assertEqual(V4PublicHeader.from_bytes(encoded), self.header)
        expected = 170 + 2 * 67_108_864 + 3 * 1_048_576
        self.assertEqual(v4_container_size(3), expected)
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


if __name__ == "__main__":
    unittest.main()
