from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2.models import HSE2ModelError
from high_security_encryptor.hse2.workflows import create_hse2_archive, validate_hse2_archive
from high_security_encryptor.hse2_open_cli import main as open_main


class HSE2ArchiveValidationTests(unittest.TestCase):
    def test_v2_and_v3_validate_without_writing_plaintext(self) -> None:
        for version in (2, 3):
            with self.subTest(format_version=version), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                source = base / "source"
                source.mkdir()
                (source / "small.txt").write_bytes(b"small payload")
                (source / "empty.txt").write_bytes(b"")
                keyfile = b"k" * 32
                archive = base / "archive.hse2"
                create_hse2_archive(
                    roots=(source,),
                    output_path=archive,
                    keyfile_bytes=keyfile,
                    chunk_size=8,
                    container_format_version=version,
                    pad_last_chunk=True,
                )

                result = validate_hse2_archive(input_path=archive, keyfile_bytes=keyfile)

                self.assertEqual(result.format_version, version)
                self.assertEqual(result.file_count, 2)
                self.assertEqual(result.plaintext_size, len(b"small payload"))
                self.assertEqual(result.payload_chunk_count, 2)
                self.assertFalse((base / "restored").exists())
                self.assertTrue(result.to_dict()["payload_authenticated"])
                self.assertFalse(result.to_dict()["plaintext_written"])

    def test_validation_rejects_wrong_key_and_corrupt_payload_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload bytes for authentication")
            keyfile = b"k" * 32
            keyfile_path = base / "archive.key"
            keyfile_path.write_bytes(keyfile)
            archive = base / "archive.hse2"
            create_hse2_archive(
                roots=(source,), output_path=archive, keyfile_bytes=keyfile,
                chunk_size=8, container_format_version=3,
            )

            with self.assertRaises(HSE2ModelError):
                validate_hse2_archive(input_path=archive, keyfile_bytes=b"x" * 32)

            corrupted = base / "corrupted.hse2"
            corrupted.write_bytes(archive.read_bytes()[:-1] + bytes([archive.read_bytes()[-1] ^ 1]))
            with self.assertRaisesRegex(HSE2ModelError, "authentication"):
                validate_hse2_archive(input_path=corrupted, keyfile_bytes=keyfile)

            output_dir = base / "must-not-be-created"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = open_main([
                    "--input", str(corrupted), "--output-dir", str(output_dir),
                    "--keyfile", str(keyfile_path), "--validate-before-open",
                ])
            self.assertEqual(exit_code, 2)
            self.assertFalse(output_dir.exists())
            self.assertIn("authentication", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
