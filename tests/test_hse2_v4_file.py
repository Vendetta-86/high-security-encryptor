from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from high_security_encryptor.hse2.container_v4_credentials import V4CredentialSlot
from high_security_encryptor.hse2.container_v4_crypto import (
    V4_DESCRIPTOR_SIZE,
    V4_MAX_RECORDS,
    V4_RECORD_SIZE,
)
from high_security_encryptor.hse2.container_v4_file import (
    V4ContainerReader,
    create_v4_container,
    update_v4_view,
)
from high_security_encryptor.hse2.container_v4_header import V4PublicHeader
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4FileTests(unittest.TestCase):
    def test_reader_rejects_truncated_and_extra_container_bytes_before_region_reads(self) -> None:
        slot0 = V4CredentialSlot(1, bytes(16), bytes(12), bytes(32), bytes(16))
        slot1 = V4CredentialSlot(1, bytes([1]) * 16, bytes([1]) * 12,
                                 bytes([1]) * 32, bytes([1]) * 16)
        header = V4PublicHeader(2, (slot0, slot1)).to_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.hse2"
            for payload in (header, header + b"extra"):
                path.write_bytes(payload)
                with self.subTest(size=len(payload)):
                    with self.assertRaisesRegex(HSE2ModelError, "invalid v4 container size"):
                        with V4ContainerReader(path):
                            self.fail("reader accepted an invalid container size")

            maximum_header = V4PublicHeader(V4_MAX_RECORDS, (slot0, slot1)).to_bytes()
            path.write_bytes(maximum_header)
            with self.assertRaisesRegex(HSE2ModelError, "invalid v4 container size"):
                with V4ContainerReader(path):
                    self.fail("reader accepted a truncated maximum-capacity container")

    def test_create_and_read_fixed_regions_without_loading_record_area(self) -> None:
        slot0 = V4CredentialSlot(1, bytes(16), bytes(12), bytes(32), bytes(16))
        slot1 = V4CredentialSlot(1, bytes([1]) * 16, bytes([1]) * 12,
                                 bytes([1]) * 32, bytes([1]) * 16)
        header = V4PublicHeader(2, (slot0, slot1))
        empty_descriptor_region = bytes(V4_DESCRIPTOR_SIZE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.hse2"
            create_v4_container(
                output_path=path,
                header=header,
                descriptors=(empty_descriptor_region, empty_descriptor_region),
                record_sources={},
                view_record_indices=(set(), set()),
            )
            original_record1: bytes
            with V4ContainerReader(path) as reader:
                self.assertEqual(reader.header, header)
                self.assertEqual(len(reader.read_descriptor(1)), V4_DESCRIPTOR_SIZE)
                self.assertEqual(len(reader.read_record(slot=0, index=0)), V4_RECORD_SIZE)
                original_record1 = reader.read_record(slot=1, index=1)
                with self.assertRaises(HSE2ModelError):
                    reader.read_record(slot=0, index=1)
            with self.assertRaisesRegex(HSE2ModelError, "new output path"):
                update_v4_view(
                    input_path=path, output_path=path, slot=0,
                    new_descriptor=empty_descriptor_region,
                    previous_record_indices=set(), new_record_indices=set(),
                    new_record_sources={},
                )
            updated_path = Path(directory) / "updated.hse2"
            replacement_descriptor = bytes([2]) * V4_DESCRIPTOR_SIZE
            replacement_record = bytes(V4_RECORD_SIZE)
            update_v4_view(
                input_path=path, output_path=updated_path, slot=0,
                new_descriptor=replacement_descriptor,
                previous_record_indices=set(), new_record_indices={0},
                new_record_sources={0: lambda: replacement_record},
            )
            with V4ContainerReader(updated_path) as reader:
                self.assertEqual(reader.read_descriptor(0), replacement_descriptor)
                self.assertEqual(reader.read_descriptor(1), empty_descriptor_region)
                self.assertEqual(reader.read_record(slot=0, index=0), replacement_record)
                self.assertEqual(reader.read_record(slot=1, index=1), original_record1)
            with V4ContainerReader(path) as reader:
                self.assertEqual(reader.read_descriptor(0), empty_descriptor_region)
            failed_output = Path(directory) / "failed-update.hse2"

            def fail_record_source() -> bytes:
                raise RuntimeError("simulated source failure")

            with self.assertRaisesRegex(RuntimeError, "simulated source failure"):
                update_v4_view(
                    input_path=path, output_path=failed_output, slot=0,
                    new_descriptor=replacement_descriptor,
                    previous_record_indices=set(), new_record_indices={0},
                    new_record_sources={0: fail_record_source},
                )
            self.assertFalse(failed_output.exists())
            with V4ContainerReader(path) as reader:
                self.assertEqual(reader.read_descriptor(0), empty_descriptor_region)
            interrupted_output = Path(directory) / "interrupted-update.hse2"
            with patch("high_security_encryptor.atomic_io.os.replace", side_effect=OSError("simulated interrupted publish")):
                with self.assertRaisesRegex(OSError, "simulated interrupted publish"):
                    update_v4_view(
                        input_path=path, output_path=interrupted_output, slot=0,
                        new_descriptor=replacement_descriptor,
                        previous_record_indices=set(), new_record_indices={0},
                        new_record_sources={0: lambda: replacement_record},
                    )
            self.assertFalse(interrupted_output.exists())
            self.assertFalse(list(Path(directory).glob(".interrupted-update.hse2.*.tmp")))
            with V4ContainerReader(path) as reader:
                self.assertEqual(reader.read_descriptor(0), empty_descriptor_region)


if __name__ == "__main__":
    unittest.main()
