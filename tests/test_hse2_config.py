"""Tests for HSE2 single-file config objects and config-driven CLI commands."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from high_security_encryptor.cli import main
from high_security_encryptor.hse2_config import HSE2EncryptConfig, HSE2RewrapConfig
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE

TEST_WRAPPER = "unit test wrapper"
NEW_TEST_WRAPPER = "replacement unit test wrapper"


class HSE2ConfigTests(unittest.TestCase):
    def test_encrypt_config_parses_and_validates(self) -> None:
        config = HSE2EncryptConfig.from_dict(
            {
                "input": "plain.bin",
                "output": "cipher.hse2",
                "wrapper": {"type": "env", "name": "HSE2_WRAPPER"},
                "kdf_profile": KDF_PROFILE_COMPATIBLE,
                "chunk_size": 64,
            }
        )

        self.assertEqual(config.input, "plain.bin")
        self.assertEqual(config.output, "cipher.hse2")
        self.assertEqual(config.wrapper["type"], "env")
        self.assertEqual(config.kdf_profile, KDF_PROFILE_COMPATIBLE)
        self.assertEqual(config.chunk_size, 64)

    def test_encrypt_config_rejects_bad_chunk_size(self) -> None:
        with self.assertRaises(ValueError):
            HSE2EncryptConfig.from_dict(
                {
                    "input": "plain.bin",
                    "output": "cipher.hse2",
                    "wrapper": {"type": "env", "name": "HSE2_WRAPPER"},
                    "chunk_size": 0,
                }
            )

    def test_rewrap_config_rejects_unknown_profile(self) -> None:
        with self.assertRaises(ValueError):
            HSE2RewrapConfig.from_dict(
                {
                    "input": "cipher.hse2",
                    "output": "rewrapped.hse2",
                    "old_wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                    "new_wrapper": {"type": "env", "name": "NEW_HSE2_WRAPPER"},
                    "new_kdf_profile": "unknown",
                }
            )

    def test_hse2_encrypt_decrypt_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            encrypt_config = root / "encrypt.json"
            decrypt_config = root / "decrypt.json"
            plain.write_bytes((b"payload" * 100) + b"tail")
            encrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(plain),
                        "output": str(encrypted),
                        "wrapper": {"type": "env", "name": "HSE2_TEST_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(encrypted),
                        "output": str(restored),
                        "wrapper": {"type": "env", "name": "HSE2_TEST_WRAPPER"},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {"HSE2_TEST_WRAPPER": TEST_WRAPPER}):
                encrypt_summary = _run_cli_json(["hse2-encrypt-config", "--config", str(encrypt_config)])
                decrypt_summary = _run_cli_json(["hse2-decrypt-config", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(encrypt_summary["command"], "hse2-encrypt-config")
            self.assertEqual(decrypt_summary["command"], "hse2-decrypt-config")
            self.assertEqual(encrypt_summary["wrapper_source"], "env")
            self.assertEqual(decrypt_summary["wrapper_source"], "env")

    def test_hse2_rewrap_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            restored = root / "restored.bin"
            encrypt_config = root / "encrypt.json"
            rewrap_config = root / "rewrap.json"
            decrypt_config = root / "decrypt.json"
            plain.write_bytes(b"payload" * 100)
            encrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(plain),
                        "output": str(encrypted),
                        "wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            rewrap_config.write_text(
                json.dumps(
                    {
                        "input": str(encrypted),
                        "output": str(rewrapped),
                        "old_wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                        "new_wrapper": {"type": "env", "name": "NEW_HSE2_WRAPPER"},
                        "new_kdf_profile": KDF_PROFILE_COMPATIBLE,
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(rewrapped),
                        "output": str(restored),
                        "wrapper": {"type": "env", "name": "NEW_HSE2_WRAPPER"},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {
                    "OLD_HSE2_WRAPPER": TEST_WRAPPER,
                    "NEW_HSE2_WRAPPER": NEW_TEST_WRAPPER,
                },
            ):
                _run_cli_json(["hse2-encrypt-config", "--config", str(encrypt_config)])
                rewrap_summary = _run_cli_json(["hse2-rewrap-config", "--config", str(rewrap_config)])
                _run_cli_json(["hse2-decrypt-config", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(rewrap_summary["command"], "hse2-rewrap-config")
            self.assertEqual(rewrap_summary["old_wrapper_source"], "env")
            self.assertEqual(rewrap_summary["new_wrapper_source"], "env")


def _run_cli_json(argv: list[str]) -> dict:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
