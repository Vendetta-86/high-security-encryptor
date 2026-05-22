"""Tests for experimental HSE2 batch rewrap workflows."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from high_security_encryptor.cli import main
from high_security_encryptor.hse2_batch_config import HSE2BatchRewrapConfig
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE

OLD_WRAPPER = "old batch wrapper"
NEW_WRAPPER = "new batch wrapper"
ITEM_NEW_WRAPPER = "item replacement wrapper"


class HSE2BatchRewrapTests(unittest.TestCase):
    def test_batch_rewrap_config_parses_global_wrappers(self) -> None:
        config = HSE2BatchRewrapConfig.from_dict(
            {
                "items": [
                    {"input": "a.hse2", "output": "a.rewrapped.hse2"},
                    {"input": "b.hse2", "output": "b.rewrapped.hse2"},
                ],
                "old_wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                "new_wrapper": {"type": "env", "name": "NEW_HSE2_WRAPPER"},
                "new_kdf_profile": KDF_PROFILE_COMPATIBLE,
            }
        )

        self.assertEqual(len(config.items), 2)
        self.assertEqual(config.old_wrapper["type"], "env")
        self.assertEqual(config.new_wrapper["type"], "env")
        self.assertEqual(config.new_kdf_profile, KDF_PROFILE_COMPATIBLE)

    def test_batch_rewrap_requires_old_and_new_wrappers(self) -> None:
        with self.assertRaises(ValueError):
            HSE2BatchRewrapConfig.from_dict(
                {
                    "items": [{"input": "a.hse2", "output": "a.rewrapped.hse2"}],
                    "old_wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                }
            )

    def test_batch_rewrap_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain_a = root / "a.bin"
            plain_b = root / "b.bin"
            enc_a = root / "a.hse2"
            enc_b = root / "b.hse2"
            rew_a = root / "a.rewrapped.hse2"
            rew_b = root / "b.rewrapped.hse2"
            out_a = root / "a.out"
            out_b = root / "b.out"
            plain_a.write_bytes(b"alpha" * 100)
            plain_b.write_bytes(b"bravo" * 100)

            encrypt_config = root / "encrypt.json"
            rewrap_config = root / "rewrap.json"
            decrypt_config = root / "decrypt.json"
            encrypt_config.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(plain_a), "output": str(enc_a)},
                            {"input": str(plain_b), "output": str(enc_b)},
                        ],
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
                        "items": [
                            {"input": str(enc_a), "output": str(rew_a)},
                            {"input": str(enc_b), "output": str(rew_b)},
                        ],
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
                        "items": [
                            {"input": str(rew_a), "output": str(out_a)},
                            {"input": str(rew_b), "output": str(out_b)},
                        ],
                        "wrapper": {"type": "env", "name": "NEW_HSE2_WRAPPER"},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {"OLD_HSE2_WRAPPER": OLD_WRAPPER, "NEW_HSE2_WRAPPER": NEW_WRAPPER},
            ):
                _run_cli_json(["hse2-batch-encrypt", "--config", str(encrypt_config)])
                rewrap_summary = _run_cli_json(["hse2-batch-rewrap", "--config", str(rewrap_config)])
                _run_cli_json(["hse2-batch-decrypt", "--config", str(decrypt_config)])

            self.assertEqual(out_a.read_bytes(), plain_a.read_bytes())
            self.assertEqual(out_b.read_bytes(), plain_b.read_bytes())
            self.assertEqual(rewrap_summary["command"], "hse2-batch-rewrap")
            self.assertEqual(rewrap_summary["total"], 2)
            self.assertEqual(rewrap_summary["succeeded"], 2)
            self.assertEqual(rewrap_summary["failed"], 0)

    def test_item_new_wrapper_overrides_global_new_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            restored = root / "restored.bin"
            plain.write_bytes(b"payload" * 20)

            encrypt_config = root / "encrypt.json"
            rewrap_config = root / "rewrap.json"
            decrypt_config = root / "decrypt.json"
            encrypt_config.write_text(
                json.dumps(
                    {
                        "items": [{"input": str(plain), "output": str(encrypted)}],
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
                        "items": [
                            {
                                "input": str(encrypted),
                                "output": str(rewrapped),
                                "new_wrapper": {"type": "env", "name": "ITEM_NEW_HSE2_WRAPPER"},
                            }
                        ],
                        "old_wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                        "new_wrapper": {"type": "env", "name": "GLOBAL_NEW_HSE2_WRAPPER"},
                        "new_kdf_profile": KDF_PROFILE_COMPATIBLE,
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "items": [{"input": str(rewrapped), "output": str(restored)}],
                        "wrapper": {"type": "env", "name": "ITEM_NEW_HSE2_WRAPPER"},
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {
                    "OLD_HSE2_WRAPPER": OLD_WRAPPER,
                    "GLOBAL_NEW_HSE2_WRAPPER": NEW_WRAPPER,
                    "ITEM_NEW_HSE2_WRAPPER": ITEM_NEW_WRAPPER,
                },
            ):
                _run_cli_json(["hse2-batch-encrypt", "--config", str(encrypt_config)])
                _run_cli_json(["hse2-batch-rewrap", "--config", str(rewrap_config)])
                _run_cli_json(["hse2-batch-decrypt", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())

    def test_continue_on_error_records_later_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing = root / "missing.hse2"
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            plain.write_bytes(b"payload")

            encrypt_config = root / "encrypt.json"
            rewrap_config = root / "rewrap.json"
            encrypt_config.write_text(
                json.dumps(
                    {
                        "items": [{"input": str(plain), "output": str(encrypted)}],
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
                        "items": [
                            {"input": str(missing), "output": str(root / "missing.rewrapped.hse2")},
                            {"input": str(encrypted), "output": str(rewrapped)},
                        ],
                        "old_wrapper": {"type": "env", "name": "OLD_HSE2_WRAPPER"},
                        "new_wrapper": {"type": "env", "name": "NEW_HSE2_WRAPPER"},
                        "new_kdf_profile": KDF_PROFILE_COMPATIBLE,
                        "continue_on_error": True,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(
                "os.environ",
                {"OLD_HSE2_WRAPPER": OLD_WRAPPER, "NEW_HSE2_WRAPPER": NEW_WRAPPER},
            ):
                _run_cli_json(["hse2-batch-encrypt", "--config", str(encrypt_config)])
                summary = _run_cli_json(["hse2-batch-rewrap", "--config", str(rewrap_config)])

            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["succeeded"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertFalse(summary["items"][0]["ok"])
            self.assertTrue(summary["items"][1]["ok"])
            self.assertTrue(rewrapped.is_file())


def _run_cli_json(argv: list[str]) -> dict:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
