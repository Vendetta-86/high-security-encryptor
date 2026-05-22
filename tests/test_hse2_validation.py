"""Tests for read-only HSE2 validation reports."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from high_security_encryptor.cli import main
from high_security_encryptor.hse2_streaming import encrypt_streaming_hse2
from high_security_encryptor.hse2_validation import validate_hse2_file
from high_security_encryptor.hse2_validation_config import HSE2ValidationConfig
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE

WRAPPER_VALUE = "hse2 validation wrapper"
OTHER_WRAPPER_VALUE = "different hse2 validation wrapper"


class HSE2ValidationTests(unittest.TestCase):
    def test_validate_file_success_without_plaintext_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            plain.write_bytes((b"payload" * 100) + b"tail")
            encrypt_streaming_hse2(
                plain,
                encrypted,
                WRAPPER_VALUE,
                kdf_profile_name=KDF_PROFILE_COMPATIBLE,
                chunk_size=64,
            )

            report = validate_hse2_file(encrypted, WRAPPER_VALUE)

            self.assertTrue(report.ok)
            self.assertTrue(report.header_ok)
            self.assertTrue(report.payload_ok)
            self.assertEqual(report.chunk_size, 64)
            self.assertEqual(report.plaintext_size, plain.stat().st_size)
            self.assertEqual(report.error, None)
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["cipher.hse2", "plain.bin"])

    def test_validate_file_reports_wrong_wrapper_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            plain.write_bytes(b"payload")
            encrypt_streaming_hse2(
                plain,
                encrypted,
                WRAPPER_VALUE,
                kdf_profile_name=KDF_PROFILE_COMPATIBLE,
                chunk_size=64,
            )

            report = validate_hse2_file(encrypted, OTHER_WRAPPER_VALUE)

            self.assertFalse(report.ok)
            self.assertTrue(report.header_ok)
            self.assertFalse(report.payload_ok)
            self.assertIn("wrapped data key authentication failed", report.error or "")

    def test_validation_config_requires_wrapper(self) -> None:
        with self.assertRaises(ValueError):
            HSE2ValidationConfig.from_dict({"items": [{"input": "cipher.hse2"}]})

    def test_hse2_validate_cli_reports_success_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            good = root / "good.hse2"
            missing = root / "missing.hse2"
            config_path = root / "validate.json"
            plain.write_bytes(b"payload" * 20)
            encrypt_streaming_hse2(
                plain,
                good,
                WRAPPER_VALUE,
                kdf_profile_name=KDF_PROFILE_COMPATIBLE,
                chunk_size=64,
            )
            config_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(good)},
                            {"input": str(missing)},
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_VALIDATION_WRAPPER"},
                        "continue_on_error": True,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {"HSE2_VALIDATION_WRAPPER": WRAPPER_VALUE}):
                summary = _run_cli_json(["hse2-validate", "--config", str(config_path)])

            self.assertEqual(summary["command"], "hse2-validate")
            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertTrue(summary["items"][0]["ok"])
            self.assertFalse(summary["items"][1]["ok"])

    def test_hse2_validate_cli_stops_on_first_failure_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            good = root / "good.hse2"
            missing = root / "missing.hse2"
            config_path = root / "validate.json"
            plain.write_bytes(b"payload" * 20)
            encrypt_streaming_hse2(
                plain,
                good,
                WRAPPER_VALUE,
                kdf_profile_name=KDF_PROFILE_COMPATIBLE,
                chunk_size=64,
            )
            config_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(missing)},
                            {"input": str(good)},
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_VALIDATION_WRAPPER"},
                        "continue_on_error": False,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {"HSE2_VALIDATION_WRAPPER": WRAPPER_VALUE}):
                summary = _run_cli_json(["hse2-validate", "--config", str(config_path)])

            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["succeeded"], 0)
            self.assertEqual(summary["failed"], 1)


def _run_cli_json(argv: list[str]) -> dict:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
