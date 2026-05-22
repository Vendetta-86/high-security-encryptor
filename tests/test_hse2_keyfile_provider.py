"""Integration tests for keyfile providers in HSE2 workflows."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.cli import main


class HSE2KeyfileProviderTests(unittest.TestCase):
    def test_hse2_config_encrypt_validate_decrypt_with_keyfile_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            keyfile = root / "wrapper.key"
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            encrypt_config = root / "encrypt.json"
            validate_config = root / "validate.json"
            decrypt_config = root / "decrypt.json"
            keyfile.write_bytes(bytes(range(32)))
            plain.write_bytes((b"payload" * 100) + b"tail")
            wrapper_spec = {"type": "keyfile", "path": str(keyfile)}
            encrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(plain),
                        "output": str(encrypted),
                        "wrapper": wrapper_spec,
                        "kdf_profile": "compatible",
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )
            validate_config.write_text(
                json.dumps(
                    {
                        "items": [{"input": str(encrypted)}],
                        "wrapper": wrapper_spec,
                    }
                ),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(encrypted),
                        "output": str(restored),
                        "wrapper": wrapper_spec,
                    }
                ),
                encoding="utf-8",
            )

            encrypt_summary = _run_cli_json(["hse2-encrypt-config", "--config", str(encrypt_config)])
            validate_summary = _run_cli_json(["hse2-validate", "--config", str(validate_config)])
            decrypt_summary = _run_cli_json(["hse2-decrypt-config", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(encrypt_summary["wrapper_source"], "keyfile")
            self.assertEqual(decrypt_summary["wrapper_source"], "keyfile")
            self.assertEqual(validate_summary["succeeded"], 1)
            self.assertEqual(validate_summary["failed"], 0)

    def test_hse2_keyfile_provider_rejects_short_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            keyfile = root / "short.key"
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            encrypt_config = root / "encrypt.json"
            keyfile.write_bytes(b"too-short")
            plain.write_bytes(b"payload")
            encrypt_config.write_text(
                json.dumps(
                    {
                        "input": str(plain),
                        "output": str(encrypted),
                        "wrapper": {"type": "keyfile", "path": str(keyfile)},
                        "kdf_profile": "compatible",
                        "chunk_size": 64,
                    }
                ),
                encoding="utf-8",
            )

            exit_code, payload = _run_cli_capture_json(["hse2-encrypt-config", "--config", str(encrypt_config)])

            self.assertNotEqual(exit_code, 0)
            self.assertIn("keyfile", payload["error"])
            self.assertIn("at least", payload["error"])
            self.assertFalse(encrypted.exists())


def _run_cli_json(argv: list[str]) -> dict:
    exit_code, payload = _run_cli_capture_json(argv)
    if exit_code != 0:
        raise AssertionError(f"CLI exited with {exit_code}: {argv}: {payload}")
    return payload


def _run_cli_capture_json(argv: list[str]) -> tuple[int, dict]:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(argv)
    return exit_code, json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
