"""Tests for experimental HSE2 batch config workflows."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from high_security_encryptor.cli import main
from high_security_encryptor.hse2_batch_config import HSE2BatchEncryptConfig
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE

TEST_WRAPPER = "unit test wrapper"
ITEM_WRAPPER = "item unit test wrapper"


class HSE2BatchTests(unittest.TestCase):
    def test_batch_config_parses_global_wrapper(self) -> None:
        config = HSE2BatchEncryptConfig.from_dict(
            {
                "items": [
                    {"input": "a.txt", "output": "a.txt.hse2"},
                    {"input": "b.txt", "output": "b.txt.hse2"},
                ],
                "wrapper": {"type": "env", "name": "HSE2_WRAPPER"},
                "kdf_profile": KDF_PROFILE_COMPATIBLE,
                "chunk_size": 64,
            }
        )

        self.assertEqual(len(config.items), 2)
        self.assertEqual(config.wrapper["type"], "env")
        self.assertEqual(config.kdf_profile, KDF_PROFILE_COMPATIBLE)
        self.assertEqual(config.chunk_size, 64)

    def test_batch_config_requires_item_or_global_wrapper(self) -> None:
        with self.assertRaises(ValueError):
            HSE2BatchEncryptConfig.from_dict(
                {
                    "items": [{"input": "a.txt", "output": "a.txt.hse2"}],
                    "kdf_profile": KDF_PROFILE_COMPATIBLE,
                }
            )

    def test_hse2_batch_encrypt_decrypt_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain_a = root / "a.bin"
            plain_b = root / "b.bin"
            enc_a = root / "a.hse2"
            enc_b = root / "b.hse2"
            out_a = root / "a.out"
            out_b = root / "b.out"
            encrypt_config = root / "batch_encrypt.json"
            decrypt_config = root / "batch_decrypt.json"
            plain_a.write_bytes(b"alpha" * 100)
            plain_b.write_bytes(b"bravo" * 100)
            encrypt_config.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(plain_a), "output": str(enc_a)},
                            {"input": str(plain_b), "output": str(enc_b)},
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_BATCH_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(enc_a), "output": str(out_a)},
                            {"input": str(enc_b), "output": str(out_b)},
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_BATCH_WRAPPER"},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {"HSE2_BATCH_WRAPPER": TEST_WRAPPER}):
                encrypt_summary = _run_cli_json(["hse2-batch-encrypt", "--config", str(encrypt_config)])
                decrypt_summary = _run_cli_json(["hse2-batch-decrypt", "--config", str(decrypt_config)])

            self.assertEqual(out_a.read_bytes(), plain_a.read_bytes())
            self.assertEqual(out_b.read_bytes(), plain_b.read_bytes())
            self.assertEqual(encrypt_summary["command"], "hse2-batch-encrypt")
            self.assertEqual(decrypt_summary["command"], "hse2-batch-decrypt")
            self.assertEqual(encrypt_summary["total"], 2)
            self.assertEqual(encrypt_summary["succeeded"], 2)
            self.assertEqual(encrypt_summary["failed"], 0)
            self.assertEqual(decrypt_summary["succeeded"], 2)

    def test_item_wrapper_overrides_global_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "item.bin"
            encrypted = root / "item.hse2"
            restored = root / "restored.bin"
            encrypt_config = root / "batch_encrypt.json"
            decrypt_config = root / "batch_decrypt.json"
            plain.write_bytes(b"payload" * 20)
            encrypt_config.write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "input": str(plain),
                                "output": str(encrypted),
                                "wrapper": {"type": "env", "name": "HSE2_ITEM_WRAPPER"},
                            }
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_GLOBAL_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "items": [
                            {
                                "input": str(encrypted),
                                "output": str(restored),
                                "wrapper": {"type": "env", "name": "HSE2_ITEM_WRAPPER"},
                            }
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_GLOBAL_WRAPPER"},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {
                    "HSE2_GLOBAL_WRAPPER": TEST_WRAPPER,
                    "HSE2_ITEM_WRAPPER": ITEM_WRAPPER,
                },
            ):
                _run_cli_json(["hse2-batch-encrypt", "--config", str(encrypt_config)])
                _run_cli_json(["hse2-batch-decrypt", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())

    def test_continue_on_error_records_later_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing = root / "missing.bin"
            plain = root / "ok.bin"
            encrypted = root / "ok.hse2"
            config_path = root / "batch_encrypt.json"
            plain.write_bytes(b"ok")
            config_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(missing), "output": str(root / "missing.hse2")},
                            {"input": str(plain), "output": str(encrypted)},
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_BATCH_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                        "continue_on_error": True,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {"HSE2_BATCH_WRAPPER": TEST_WRAPPER}):
                summary = _run_cli_json(["hse2-batch-encrypt", "--config", str(config_path)])

            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertFalse(summary["items"][0]["ok"])
            self.assertTrue(summary["items"][1]["ok"])
            self.assertTrue(encrypted.is_file())

    def test_stop_on_first_error_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing = root / "missing.bin"
            plain = root / "ok.bin"
            encrypted = root / "ok.hse2"
            config_path = root / "batch_encrypt.json"
            plain.write_bytes(b"ok")
            config_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(missing), "output": str(root / "missing.hse2")},
                            {"input": str(plain), "output": str(encrypted)},
                        ],
                        "wrapper": {"type": "env", "name": "HSE2_BATCH_WRAPPER"},
                        "kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict("os.environ", {"HSE2_BATCH_WRAPPER": TEST_WRAPPER}):
                summary = _run_cli_json(["hse2-batch-encrypt", "--config", str(config_path)])

            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["succeeded"], 0)
            self.assertEqual(summary["failed"], 1)
            self.assertFalse(encrypted.exists())


def _run_cli_json(argv: list[str]) -> dict:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
