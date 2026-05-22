"""Tests for explicit HSE1 to HSE2 migration workflows."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from high_security_encryptor.api import encrypt_file_streaming
from high_security_encryptor.cli import main
from high_security_encryptor.hse1_to_hse2_config import HSE1ToHSE2MigrationConfig
from high_security_encryptor.hse2_streaming import decrypt_streaming_hse2
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE

HSE1_PASSWORD = "hse1 migration password"
HSE2_WRAPPER = "hse2 migration wrapper"
ITEM_HSE2_WRAPPER = "item hse2 migration wrapper"


class HSE1ToHSE2MigrationTests(unittest.TestCase):
    def test_migration_config_parses_batch_providers(self) -> None:
        config = HSE1ToHSE2MigrationConfig.from_dict(
            {
                "items": [
                    {"input": "a.hse", "output": "a.hse2"},
                    {"input": "b.hse", "output": "b.hse2"},
                ],
                "hse1_password": {"type": "env", "name": "HSE1_PASSWORD"},
                "hse2_wrapper": {"type": "env", "name": "HSE2_WRAPPER"},
                "kdf_profile": KDF_PROFILE_COMPATIBLE,
                "chunk_size": 64,
            }
        )

        self.assertEqual(len(config.items), 2)
        self.assertEqual(config.hse1_password["type"], "env")
        self.assertEqual(config.hse2_wrapper["type"], "env")
        self.assertEqual(config.kdf_profile, KDF_PROFILE_COMPATIBLE)
        self.assertEqual(config.chunk_size, 64)

    def test_migration_config_requires_hse1_and_hse2_sources(self) -> None:
        with self.assertRaises(ValueError):
            HSE1ToHSE2MigrationConfig.from_dict(
                {
                    "items": [{"input": "a.hse", "output": "a.hse2"}],
                    "hse1_password": {"type": "env", "name": "HSE1_PASSWORD"},
                }
            )

    def test_hse1_to_hse2_migration_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            hse1_file = root / "plain.bin.hse"
            hse2_file = root / "plain.bin.hse2"
            restored = root / "restored.bin"
            config_path = root / "migrate.json"
            plain.write_bytes((b"payload" * 100) + b"tail")
            encrypt_file_streaming(plain, hse1_file, HSE1_PASSWORD)
            config_path.write_text(
                json.dumps(
                    {
                        "items": [{"input": str(hse1_file), "output": str(hse2_file)}],
                        "hse1_password": {"type": "env", "name": "HSE1_PASSWORD"},
                        "hse2_wrapper": {"type": "env", "name": "HSE2_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {"HSE1_PASSWORD": HSE1_PASSWORD, "HSE2_WRAPPER": HSE2_WRAPPER},
            ):
                summary = _run_cli_json(["hse1-to-hse2", "--config", str(config_path)])
            decrypt_streaming_hse2(hse2_file, restored, HSE2_WRAPPER)

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(summary["command"], "hse1-to-hse2")
            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 0)
            self.assertTrue(hse1_file.is_file())
            self.assertTrue(hse2_file.is_file())

    def test_item_hse2_wrapper_overrides_batch_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            hse1_file = root / "plain.bin.hse"
            hse2_file = root / "plain.bin.hse2"
            restored = root / "restored.bin"
            config_path = root / "migrate.json"
            plain.write_bytes(b"payload" * 20)
            encrypt_file_streaming(plain, hse1_file, HSE1_PASSWORD)
            config_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "input": str(hse1_file),
                                "output": str(hse2_file),
                                "hse2_wrapper": {"type": "env", "name": "ITEM_HSE2_WRAPPER"},
                            }
                        ],
                        "hse1_password": {"type": "env", "name": "HSE1_PASSWORD"},
                        "hse2_wrapper": {"type": "env", "name": "GLOBAL_HSE2_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {
                    "HSE1_PASSWORD": HSE1_PASSWORD,
                    "GLOBAL_HSE2_WRAPPER": HSE2_WRAPPER,
                    "ITEM_HSE2_WRAPPER": ITEM_HSE2_WRAPPER,
                },
            ):
                _run_cli_json(["hse1-to-hse2", "--config", str(config_path)])
            decrypt_streaming_hse2(hse2_file, restored, ITEM_HSE2_WRAPPER)

            self.assertEqual(restored.read_bytes(), plain.read_bytes())

    def test_continue_on_error_records_later_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing = root / "missing.hse"
            plain = root / "plain.bin"
            hse1_file = root / "plain.bin.hse"
            hse2_file = root / "plain.bin.hse2"
            config_path = root / "migrate.json"
            plain.write_bytes(b"payload")
            encrypt_file_streaming(plain, hse1_file, HSE1_PASSWORD)
            config_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(missing), "output": str(root / "missing.hse2")},
                            {"input": str(hse1_file), "output": str(hse2_file)},
                        ],
                        "hse1_password": {"type": "env", "name": "HSE1_PASSWORD"},
                        "hse2_wrapper": {"type": "env", "name": "HSE2_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                        "continue_on_error": True,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {"HSE1_PASSWORD": HSE1_PASSWORD, "HSE2_WRAPPER": HSE2_WRAPPER},
            ):
                summary = _run_cli_json(["hse1-to-hse2", "--config", str(config_path)])

            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertFalse(summary["items"][0]["ok"])
            self.assertTrue(summary["items"][1]["ok"])
            self.assertTrue(hse2_file.is_file())


def _run_cli_json(argv: list[str]) -> dict:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
