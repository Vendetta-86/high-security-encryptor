"""Fixed serialized fixtures for the HSE2 v5 public wire format."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2.container_v5_credentials import V5CredentialSlot, unlock_v5_credentials
from high_security_encryptor.hse2.container_v5_descriptor import open_v5_descriptor
from high_security_encryptor.hse2.container_v5_file import V5ContainerReader
from high_security_encryptor.hse2.container_v5_header import (
    V5_FOOTER_SIZE,
    V5_HEADER_SIZE,
    V5Footer,
    V5FooterEntry,
    V5PublicHeader,
)
from high_security_encryptor.hse2.container_v5_workflows import restore_v5_archive, validate_v5_archive
from high_security_encryptor.hse2.models import HSE2ModelError


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "hse2_v5"
PRIMARY_FIXTURE_CREDENTIAL = "hse2-v5-fixture-primary-only"
SECONDARY_FIXTURE_CREDENTIAL = "hse2-v5-fixture-secondary-only"


class HSE2V5WireFixtureTests(unittest.TestCase):
    def _fixture_checksums(self) -> dict[str, str]:
        checksums = {}
        for line in (FIXTURE_DIR / "complete_archive.sha256").read_text(encoding="ascii").splitlines():
            digest, label = line.split("  ", 1)
            checksums[label.split("#", 1)[0].strip()] = digest
        return checksums

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

    def test_complete_frozen_archive_restores_both_views_to_hashed_expected_files(self) -> None:
        manifest = json.loads((FIXTURE_DIR / "complete_archive.json").read_text(encoding="utf-8"))
        checksums = self._fixture_checksums()
        archive = FIXTURE_DIR / manifest["archive"]["file"]
        archive_bytes = archive.read_bytes()
        self.assertEqual(len(archive_bytes), manifest["archive"]["size_bytes"])
        self.assertEqual(hashlib.sha256(archive_bytes).hexdigest(), checksums["complete_archive.hse2"])
        self.assertTrue(manifest["fixture_only"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for view, credential in zip(
                manifest["views"], (PRIMARY_FIXTURE_CREDENTIAL, SECONDARY_FIXTURE_CREDENTIAL)
            ):
                restored = restore_v5_archive(
                    input_path=archive, password=credential, output_dir=root / f"view-{view['slot']}"
                )
                expected_root = FIXTURE_DIR / "expected" / ("primary" if view["slot"] == 0 else "secondary")
                self.assertEqual(
                    sorted(path.relative_to(restored).as_posix() for path in restored.rglob("*")),
                    sorted(item["path"] for item in view["files"]),
                )
                for expected in view["files"]:
                    restored_file = restored / expected["path"]
                    self.assertEqual(restored_file.stat().st_size, expected["size_bytes"])
                    fixture_label = (
                        f"expected/{'primary' if view['slot'] == 0 else 'secondary'}/{expected['path']}"
                    )
                    self.assertEqual(hashlib.sha256(restored_file.read_bytes()).hexdigest(), checksums[fixture_label])
                    self.assertEqual(restored_file.read_bytes(), (expected_root / expected["path"]).read_bytes())

    def test_complete_frozen_archive_rejects_header_footer_descriptor_and_record_tampering(self) -> None:
        archive = FIXTURE_DIR / "complete_archive.hse2"
        original = archive.read_bytes()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            header_damage = bytearray(original)
            header_damage[8] ^= 1  # archive_id is bound to both credential wrappers.
            header_path = root / "header-damaged.hse2"
            header_path.write_bytes(header_damage)
            with self.assertRaisesRegex(HSE2ModelError, "credential authentication"):
                validate_v5_archive(input_path=header_path, password=PRIMARY_FIXTURE_CREDENTIAL)

            footer_damage = bytearray(original)
            footer_start = len(footer_damage) - V5_FOOTER_SIZE
            footer_damage[footer_start + 8:footer_start + 16] = (0).to_bytes(8, "big")
            footer_path = root / "footer-damaged.hse2"
            footer_path.write_bytes(footer_damage)
            with self.assertRaisesRegex(HSE2ModelError, "bounds"):
                with V5ContainerReader(footer_path):
                    pass

            with V5ContainerReader(archive) as reader:
                slot, root_key = unlock_v5_credentials(
                    PRIMARY_FIXTURE_CREDENTIAL, reader.header.credential_slots,
                    archive_id=reader.header.archive_id,
                )
                generation, descriptor_blob = reader.read_descriptor(slot)
                descriptor = open_v5_descriptor(
                    root_key=root_key, archive_id=reader.header.archive_id, slot=slot,
                    generation=generation, offset=reader.footer.views[slot].offset, blob=descriptor_blob,
                )
                record_offset = descriptor.files[1].chunks[0].offset
                descriptor_offset = reader.footer.views[slot].offset
                descriptor_length = reader.footer.views[slot].length

            descriptor_damage = bytearray(original)
            descriptor_damage[descriptor_offset + descriptor_length - 1] ^= 1
            descriptor_path = root / "descriptor-damaged.hse2"
            descriptor_path.write_bytes(descriptor_damage)
            with self.assertRaisesRegex(HSE2ModelError, "descriptor authentication"):
                validate_v5_archive(input_path=descriptor_path, password=PRIMARY_FIXTURE_CREDENTIAL)

            record_damage = bytearray(original)
            record_damage[record_offset + 44] ^= 1  # first ciphertext byte after salt and nonce.
            record_path = root / "record-damaged.hse2"
            record_path.write_bytes(record_damage)
            with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
                validate_v5_archive(input_path=record_path, password=PRIMARY_FIXTURE_CREDENTIAL)


if __name__ == "__main__":
    unittest.main()
