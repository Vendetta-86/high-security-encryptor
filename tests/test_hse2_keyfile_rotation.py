"""Tests for explicit HSE2 keyfile rotation workflow."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.cli import main
from high_security_encryptor.hse2_keyfile_rotation_config import HSE2KeyfileRotationConfig


class HSE2KeyfileRotationTests(unittest.TestCase):
    def test_keyfile_rotation_config_parses(self) -> None:
        config = HSE2KeyfileRotationConfig.from_dict(
            {
                "items": [
                    {"input": "a.hse2", "output": "a.rotated.hse2"},
                    {"input": "b.hse2", "output": "b.rotated.hse2"},
                ],
                "old_keyfile": "old.key",
                "new_keyfile": "new.key",
                "new_kdf_profile": "compatible",
                "continue_on_error": True,
            }
        )

        self.assertEqual(len(config.items), 2)
        self.assertEqual(config.old_keyfile, "old.key")
        self.assertEqual(config.new_keyfile, "new.key")
        self.assertEqual(config.new_kdf_profile, "compatible")
        self.assertTrue(config.continue_on_error)

    def test_keyfile_rotation_config_rejects_same_keyfile(self) -> None:
        with self.assertRaises(ValueError):
            HSE2KeyfileRotationConfig.from_dict(
                {
                    "items": [{"input": "a.hse2", "output": "a.rotated.hse2"}],
                    "old_keyfile": "same.key",
                    "new_keyfile": "same.key",
                }
            )

    def test_hse2_rotate_keyfile_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_keyfile = root / "old.key"
            new_keyfile = root / "new.key"
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rotated = root / "cipher.rotated.hse2"
            restored = root / "restored.bin"
            encrypt_config = root / "encrypt.json"
            rotate_config = root / "rotate.json"
            decrypt_config = root / "decrypt.json"
            old_keyfile.write_bytes(bytes(range(32)))
            new_keyfile.write_bytes(bytes(range(32, 64)))
            plain.write_bytes((b"payload" * 100) + b"tail")
            encrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(plain),
                        "output": str(encrypted),
                        "wrapper": {"type": "keyfile", "path": str(old_keyfile)},
                        "kdf_profile": "compatible",
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            rotate_config.write_text(
                json.dumps(
                    {
                        "items": [{"input": str(encrypted), "output": str(rotated)}],
                        "old_keyfile": str(old_keyfile),
                        "new_keyfile": str(new_keyfile),
                        "new_kdf_profile": "compatible",
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(rotated),
                        "output": str(restored),
                        "wrapper": {"type": "keyfile", "path": str(new_keyfile)},
                    }
                ),
                encoding="utf-8",
            )

            _run_cli_json(["hse2-encrypt-config", "--config", str(encrypt_config)])
            rotate_summary = _run_cli_json(["hse2-rotate-keyfile", "--config", str(rotate_config)])
            _run_cli_json(["hse2-decrypt-config", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(rotate_summary["command"], "hse2-rotate-keyfile")
            self.assertEqual(rotate_summary["total"], 1)
            self.assertEqual(rotate_summary["succeeded"], 1)
            self.assertEqual(rotate_summary["failed"], 0)
            self.assertTrue(encrypted.is_file())
            self.assertTrue(rotated.is_file())
            self.assertTrue(old_keyfile.is_file())
            self.assertTrue(new_keyfile.is_file())

    def test_hse2_rotate_keyfile_continue_on_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_keyfile = root / "old.key"
            new_keyfile = root / "new.key"
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rotated = root / "cipher.rotated.hse2"
            missing = root / "missing.hse2"
            encrypt_config = root / "encrypt.json"
            rotate_config = root / "rotate.json"
            old_keyfile.write_bytes(bytes(range(32)))
            new_keyfile.write_bytes(bytes(range(32, 64)))
            plain.write_bytes(b"payload")
            encrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(plain),
                        "output": str(encrypted),
                        "wrapper": {"type": "keyfile", "path": str(old_keyfile)},
                        "kdf_profile": "compatible",
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            rotate_config.write_text(
                json.dumps(
                    {
                        "items": [
                            {"input": str(missing), "output": str(root / "missing.rotated.hse2")},
                            {"input": str(encrypted), "output": str(rotated)},
                        ],
                        "old_keyfile": str(old_keyfile),
                        "new_keyfile": str(new_keyfile),
                        "new_kdf_profile": "compatible",
                        "continue_on_error": True,
                    }
                ),
                encoding="utf-8",
            )

            _run_cli_json(["hse2-encrypt-config", "--config", str(encrypt_config)])
            rotate_summary = _run_cli_json(["hse2-rotate-keyfile", "--config", str(rotate_config)])

            self.assertEqual(rotate_summary["total"], 2)
            self.assertEqual(rotate_summary["succeeded"], 1)
            self.assertEqual(rotate_summary["failed"], 1)
            self.assertFalse(rotate_summary["items"][0]["ok"])
            self.assertTrue(rotate_summary["items"][1]["ok"])
            self.assertTrue(rotated.is_file())


def _run_cli_json(argv: list[str]) -> dict:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
