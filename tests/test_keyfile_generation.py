"""Tests for keyfile generation helpers and CLI."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.cli import main
from high_security_encryptor.keyfile_generation import generate_keyfile


class KeyfileGenerationTests(unittest.TestCase):
    def test_generate_keyfile_helper_creates_random_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "wrapper.key"

            result = generate_keyfile(output, size_bytes=32)

            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_size, 32)
            self.assertEqual(result.output, str(output))
            self.assertEqual(result.size_bytes, 32)
            self.assertFalse(result.overwritten)

    def test_generate_keyfile_helper_refuses_existing_file_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "wrapper.key"
            output.write_bytes(b"existing-keyfile-bytes")

            with self.assertRaises(FileExistsError):
                generate_keyfile(output, size_bytes=32)

            self.assertEqual(output.read_bytes(), b"existing-keyfile-bytes")

    def test_generate_keyfile_helper_force_overwrites_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "wrapper.key"
            output.write_bytes(b"existing-keyfile-bytes")

            result = generate_keyfile(output, size_bytes=32, force=True)

            self.assertTrue(result.overwritten)
            self.assertEqual(output.stat().st_size, 32)
            self.assertNotEqual(output.read_bytes(), b"existing-keyfile-bytes")

    def test_generate_keyfile_helper_rejects_too_small_size(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "wrapper.key"

            with self.assertRaisesRegex(ValueError, "at least"):
                generate_keyfile(output, size_bytes=15)

            self.assertFalse(output.exists())

    def test_generate_keyfile_cli_creates_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "nested" / "wrapper.key"

            summary = _run_cli_json(["generate-keyfile", "--output", str(output), "--size", "32"])

            self.assertEqual(summary["command"], "generate-keyfile")
            self.assertEqual(summary["output"], str(output))
            self.assertEqual(summary["size_bytes"], 32)
            self.assertFalse(summary["overwritten"])
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_size, 32)
            self.assertNotIn("items", summary)

    def test_generate_keyfile_cli_refuses_existing_file_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "wrapper.key"
            output.write_bytes(b"existing-keyfile-bytes")

            exit_code, stdout, stderr = _run_cli_capture(["generate-keyfile", "--output", str(output)])

            self.assertNotEqual(exit_code, 0)
            self.assertEqual(stdout, "")
            self.assertIn("already exists", stderr)
            self.assertEqual(output.read_bytes(), b"existing-keyfile-bytes")

    def test_generate_keyfile_cli_force_overwrites_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "wrapper.key"
            output.write_bytes(b"existing-keyfile-bytes")

            summary = _run_cli_json(["generate-keyfile", "--output", str(output), "--force", "--size", "32"])

            self.assertTrue(summary["overwritten"])
            self.assertEqual(output.stat().st_size, 32)
            self.assertNotEqual(output.read_bytes(), b"existing-keyfile-bytes")


def _run_cli_json(argv: list[str]) -> dict:
    exit_code, stdout, stderr = _run_cli_capture(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}: {stderr}")
    return json.loads(stdout)


def _run_cli_capture(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = main(argv)
    return exit_code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
