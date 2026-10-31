from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.cli import main
from high_security_encryptor.hse2.keyfile_inspect import inspect_hse2_keyfile


class HSE2KeyfileInspectionTests(unittest.TestCase):
    def test_inspect_reports_compatible_file_metadata_without_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "wrapper.key"
            material = bytes(range(32))
            path.write_bytes(material)

            result = inspect_hse2_keyfile(path).to_dict()

            self.assertEqual(result["size_bytes"], len(material))
            self.assertEqual(result["minimum_size_bytes"], 32)
            self.assertTrue(result["hse2_compatible"])
            self.assertEqual(result["sha256"], hashlib.sha256(material).hexdigest())
            self.assertNotIn("keyfile_bytes", result)

    def test_inspect_marks_short_file_incompatible_without_failing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "short.key"
            path.write_bytes(b"short")

            result = inspect_hse2_keyfile(path)

            self.assertFalse(result.hse2_compatible)
            self.assertEqual(result.size_bytes, 5)

    def test_nested_cli_outputs_keyfile_inspection_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "wrapper.key"
            path.write_bytes(b"k" * 32)
            stdout, stderr = io.StringIO(), io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["hse2", "keyfile", "inspect", "--input", str(path)])

            self.assertEqual(exit_code, 0, stderr.getvalue())
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["command"], "hse2-keyfile-inspect")
            self.assertTrue(summary["hse2_compatible"])
            self.assertEqual(stderr.getvalue(), "")

    def test_inspect_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.key"
            with self.assertRaises(FileNotFoundError):
                inspect_hse2_keyfile(missing)


if __name__ == "__main__":
    unittest.main()
