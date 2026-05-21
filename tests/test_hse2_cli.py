"""Tests for experimental HSE2 CLI commands."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from high_security_encryptor.cli import main
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE

TEST_PHRASE = "unit test phrase"
NEW_TEST_PHRASE = "replacement unit test phrase"


class HSE2CliTests(unittest.TestCase):
    def test_hse2_encrypt_decrypt_round_trip_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            plain.write_bytes((b"payload" * 100) + b"tail")

            encrypt_summary = _run_cli_json(
                [
                    "hse2-encrypt",
                    "--input",
                    str(plain),
                    "--output",
                    str(encrypted),
                    "--secret",
                    TEST_PHRASE,
                    "--kdf-profile",
                    KDF_PROFILE_COMPATIBLE,
                    "--chunk-size",
                    "64",
                ]
            )
            decrypt_summary = _run_cli_json(
                [
                    "hse2-decrypt",
                    "--input",
                    str(encrypted),
                    "--output",
                    str(restored),
                    "--secret",
                    TEST_PHRASE,
                ]
            )

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(encrypt_summary["command"], "hse2-encrypt")
            self.assertEqual(decrypt_summary["command"], "hse2-decrypt")
            self.assertEqual(encrypt_summary["wrapper_source"], "literal")
            self.assertEqual(decrypt_summary["wrapper_source"], "literal")
            self.assertTrue(encrypt_summary["experimental"])
            self.assertTrue(decrypt_summary["experimental"])

    def test_hse2_encrypt_decrypt_with_env_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            plain.write_bytes(b"payload" * 20)

            with mock.patch.dict(os.environ, {"HSE2_TEST_WRAPPER": TEST_PHRASE}):
                encrypt_summary = _run_cli_json(
                    [
                        "hse2-encrypt",
                        "--input",
                        str(plain),
                        "--output",
                        str(encrypted),
                        "--secret-env",
                        "HSE2_TEST_WRAPPER",
                        "--kdf-profile",
                        KDF_PROFILE_COMPATIBLE,
                        "--chunk-size",
                        "64",
                    ]
                )
                decrypt_summary = _run_cli_json(
                    [
                        "hse2-decrypt",
                        "--input",
                        str(encrypted),
                        "--output",
                        str(restored),
                        "--secret-env",
                        "HSE2_TEST_WRAPPER",
                    ]
                )

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(encrypt_summary["wrapper_source"], "env")
            self.assertEqual(decrypt_summary["wrapper_source"], "env")

    def test_hse2_decrypt_with_file_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            wrapper_file = root / "wrapper.txt"
            plain.write_bytes(b"payload" * 20)
            wrapper_file.write_text(TEST_PHRASE + "\n", encoding="utf-8")

            _run_cli_json(
                [
                    "hse2-encrypt",
                    "--input",
                    str(plain),
                    "--output",
                    str(encrypted),
                    "--secret-file",
                    str(wrapper_file),
                    "--kdf-profile",
                    KDF_PROFILE_COMPATIBLE,
                    "--chunk-size",
                    "64",
                ]
            )
            decrypt_summary = _run_cli_json(
                [
                    "hse2-decrypt",
                    "--input",
                    str(encrypted),
                    "--output",
                    str(restored),
                    "--secret-file",
                    str(wrapper_file),
                ]
            )

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(decrypt_summary["wrapper_source"], "file")

    def test_hse2_rewrap_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            restored = root / "restored.bin"
            plain.write_bytes(b"payload" * 100)

            _run_cli_json(
                [
                    "hse2-encrypt",
                    "--input",
                    str(plain),
                    "--output",
                    str(encrypted),
                    "--secret",
                    TEST_PHRASE,
                    "--kdf-profile",
                    KDF_PROFILE_COMPATIBLE,
                    "--chunk-size",
                    "64",
                ]
            )
            rewrap_summary = _run_cli_json(
                [
                    "hse2-rewrap",
                    "--input",
                    str(encrypted),
                    "--output",
                    str(rewrapped),
                    "--old-secret",
                    TEST_PHRASE,
                    "--new-secret",
                    NEW_TEST_PHRASE,
                    "--new-kdf-profile",
                    KDF_PROFILE_COMPATIBLE,
                ]
            )
            _run_cli_json(
                [
                    "hse2-decrypt",
                    "--input",
                    str(rewrapped),
                    "--output",
                    str(restored),
                    "--secret",
                    NEW_TEST_PHRASE,
                ]
            )

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(rewrap_summary["command"], "hse2-rewrap")
            self.assertEqual(rewrap_summary["old_wrapper_source"], "literal")
            self.assertEqual(rewrap_summary["new_wrapper_source"], "literal")
            self.assertTrue(rewrap_summary["experimental"])

    def test_hse2_wrapper_source_conflict_returns_password_source_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            plain.write_bytes(b"payload")

            exit_code, _stdout, stderr = _run_cli_capture(
                [
                    "hse2-encrypt",
                    "--input",
                    str(plain),
                    "--output",
                    str(encrypted),
                    "--secret",
                    TEST_PHRASE,
                    "--secret-env",
                    "HSE2_TEST_WRAPPER",
                    "--kdf-profile",
                    KDF_PROFILE_COMPATIBLE,
                ]
            )

            self.assertEqual(exit_code, 4)
            self.assertIn("specify exactly one wrapper input source", stderr)

    def test_hse2_commands_are_visible_in_help(self) -> None:
        stdout = io.StringIO()
        with self.assertRaises(SystemExit):
            with redirect_stdout(stdout):
                main(["--help"])

        help_text = stdout.getvalue()

        self.assertIn("hse2-encrypt", help_text)
        self.assertIn("hse2-decrypt", help_text)
        self.assertIn("hse2-rewrap", help_text)


def _run_cli_json(argv: list[str]) -> dict:
    exit_code, stdout, _stderr = _run_cli_capture(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout)


def _run_cli_capture(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = main(argv)
    return exit_code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
