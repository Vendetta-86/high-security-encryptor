from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from high_security_encryptor.hse2.container_v4_descriptor import V4ViewDescriptor
from high_security_encryptor.hse2.container_v4_workflows import (
    _validate_restored_view,
    create_v4_archive,
    replace_v4_view,
    restore_v4_archive,
)
from high_security_encryptor.hse2.container_v4_crypto import V4_RECORD_SIZE
from high_security_encryptor.hse2.container_v4_file import V4_RECORD_AREA_OFFSET
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4WorkflowTests(unittest.TestCase):
    def test_manifest_validation_rejects_invalid_paths_record_maps_and_lengths(self) -> None:
        malformed = (
            V4ViewDescriptor({"unexpected": []}, {}),
            V4ViewDescriptor({"files": [{"path": "../escape", "size": 1, "records": [0]}]}, {0: 1}),
            V4ViewDescriptor({"files": [{"path": "a", "size": 0, "records": [0]}]}, {0: 1}),
            V4ViewDescriptor({"files": [{"path": "a", "size": 2, "records": [0]}]}, {0: 1}),
            V4ViewDescriptor({"files": [{"path": "a", "size": 1, "records": [1]}]}, {1: 1}),
            V4ViewDescriptor({"files": [
                {"path": "a", "size": 1, "records": [0]},
                {"path": "a/b", "size": 1, "records": [2]},
            ]}, {0: 1, 2: 1}),
        )
        for index, descriptor in enumerate(malformed):
            with self.subTest(sample=index), self.assertRaises(HSE2ModelError):
                _validate_restored_view(descriptor, 0)

    def test_two_view_create_restore_and_generic_wrong_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary_source = root / "primary-source.txt"
            secondary_source = root / "secondary-source.txt"
            primary_source.write_bytes(b"primary view data" * 23)
            secondary_source.write_bytes(b"secondary view material" * 19)
            container = root / "candidate.hse2"
            create_v4_archive(
                output_path=container,
                view_passwords=("primary credential", "secondary credential"),
                view_files=(
                    [("private/main.txt", primary_source)],
                    [("notes/secondary.txt", secondary_source)],
                ),
                capacity_records=2,
            )

            primary_output = root / "primary-output"
            restore_v4_archive(input_path=container, password="primary credential",  # pragma: allowlist secret
                               output_dir=primary_output)
            self.assertEqual(
                (primary_output / "private" / "main.txt").read_bytes(),
                primary_source.read_bytes(),
            )
            self.assertFalse((primary_output / "notes").exists())

            secondary_output = root / "secondary-output"
            restore_v4_archive(input_path=container, password="secondary credential",  # pragma: allowlist secret
                               output_dir=secondary_output)
            self.assertEqual(
                (secondary_output / "notes" / "secondary.txt").read_bytes(),
                secondary_source.read_bytes(),
            )
            self.assertFalse((secondary_output / "private").exists())

            replacement_source = root / "replacement.txt"
            replacement_source.write_bytes(b"updated primary view")
            updated_container = root / "updated.hse2"
            replace_v4_view(
                input_path=container, output_path=updated_container,
                password="primary credential",  # pragma: allowlist secret
                view_files=[("private/updated.txt", replacement_source)],
            )
            updated_primary = root / "updated-primary-output"
            restore_v4_archive(input_path=updated_container,
                               password="primary credential",  # pragma: allowlist secret
                               output_dir=updated_primary)
            self.assertEqual((updated_primary / "private" / "updated.txt").read_bytes(),
                             replacement_source.read_bytes())
            updated_secondary = root / "updated-secondary-output"
            restore_v4_archive(input_path=updated_container,
                               password="secondary credential",  # pragma: allowlist secret
                               output_dir=updated_secondary)
            self.assertEqual((updated_secondary / "notes" / "secondary.txt").read_bytes(),
                             secondary_source.read_bytes())
            self.assertTrue(container.exists())

            with self.assertRaisesRegex(HSE2ModelError, "authentication or restore failed"):
                restore_v4_archive(input_path=container, password="wrong credential",  # pragma: allowlist secret
                                   output_dir=root / "wrong-output")
            self.assertFalse((root / "wrong-output").exists())

            with container.open("r+b") as file_obj:
                file_obj.seek(V4_RECORD_AREA_OFFSET + V4_RECORD_SIZE - 1)
                last_tag_byte = file_obj.read(1)
                file_obj.seek(V4_RECORD_AREA_OFFSET + V4_RECORD_SIZE - 1)
                file_obj.write(bytes([last_tag_byte[0] ^ 1]))
            tampered_output = root / "tampered-output"
            with self.assertRaisesRegex(HSE2ModelError, "authentication or restore failed"):
                restore_v4_archive(input_path=container, password="primary credential",  # pragma: allowlist secret
                                   output_dir=tampered_output)
            self.assertFalse(tampered_output.exists())
            self.assertFalse(list(root.glob(".tampered-output.v4-restore-*")))


if __name__ == "__main__":
    unittest.main()
