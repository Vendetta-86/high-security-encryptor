"""Fixed serialized fixtures for the HSE2 v5 public wire format."""

from __future__ import annotations

from pathlib import Path
import unittest

from high_security_encryptor.hse2.container_v5_credentials import V5CredentialSlot
from high_security_encryptor.hse2.container_v5_header import (
    V5_FOOTER_SIZE,
    V5_HEADER_SIZE,
    V5Footer,
    V5FooterEntry,
    V5PublicHeader,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "hse2_v5"


class HSE2V5WireFixtureTests(unittest.TestCase):
    def test_public_header_matches_frozen_wire_bytes(self) -> None:
        first = V5CredentialSlot(1, bytes(range(16)), bytes(range(12)), bytes(range(32)), bytes(range(16)))
        second = V5CredentialSlot(
            1, bytes(range(16, 32)), bytes(range(12, 24)), bytes(range(32, 64)), bytes(range(16, 32)),
        )
        fixture = bytes.fromhex((FIXTURE_DIR / "public_header.hex").read_text(encoding="ascii"))
        header = V5PublicHeader(bytes(range(16)), (first, second))

        self.assertEqual(len(fixture), V5_HEADER_SIZE)
        self.assertEqual(header.to_bytes(), fixture)
        self.assertEqual(V5PublicHeader.from_bytes(fixture), header)

    def test_footer_matches_frozen_wire_bytes_and_bounds(self) -> None:
        fixture = bytes.fromhex((FIXTURE_DIR / "footer.hex").read_text(encoding="ascii"))
        footer = V5Footer((
            V5FooterEntry(V5_HEADER_SIZE, 60, 1),
            V5FooterEntry(V5_HEADER_SIZE + 60, 60, 1),
        ))
        file_size = V5_HEADER_SIZE + 120 + V5_FOOTER_SIZE

        self.assertEqual(len(fixture), V5_FOOTER_SIZE)
        self.assertEqual(footer.to_bytes(), fixture)
        self.assertEqual(V5Footer.from_bytes(fixture, file_size=file_size), footer)


if __name__ == "__main__":
    unittest.main()
