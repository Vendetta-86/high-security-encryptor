"""Tests for Windows DPAPI helpers and provider integration."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.cli import main
from high_security_encryptor.password_sources import PasswordResolver, PasswordSourceError
from high_security_encryptor.windows_dpapi import (
    DPAPIError,
    DPAPI_WRAPPER_PREFIX,
    is_windows,
    protect_file_with_dpapi,
    unprotect_dpapi_file,
)


class WindowsDPAPITests(unittest.TestCase):
    def test_dpapi_helper_round_trip_on_windows(self) -> None:
        if not is_windows():
            self.skipTest("Windows DPAPI is only available on Windows")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "material.bin"
            blob = root / "material.dpapi"
            source.write_bytes(bytes(range(32)))

            result = protect_file_with_dpapi(source, blob)
            restored = unprotect_dpapi_file(blob)

            self.assertEqual(restored, source.read_bytes())
            self.assertEqual(result.output, str(blob))
            self.assertEqual(result.input_size_bytes, 32)
            self.assertEqual(result.scope, "current_user")
            self.assertFalse(result.overwritten)
            self.assertTrue(blob.read_text(encoding="utf-8").startswith(DPAPI_WRAPPER_PREFIX))

    def test_dpapi_protect_cli_round_trip_on_windows(self) -> None:
        if not is_windows():
            self.skipTest("Windows DPAPI is only available on Windows")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "material.bin"
            blob = root / "material.dpapi"
            source.write_bytes(bytes(range(32, 64)))

            summary = _run_cli_json(["dpapi-protect", "--input", str(source), "--output", str(blob)])
            restored = unprotect_dpapi_file(blob)

            self.assertEqual(restored, source.read_bytes())
            self.assertEqual(summary["command"], "dpapi-protect")
            self.assertEqual(summary["output"], str(blob))
            self.assertEqual(summary["input_size_bytes"], 32)
            self.assertEqual(summary["scope"], "current_user")
            self.assertFalse(summary["overwritten"])
            self.assertNotIn("items", summary)

    def test_dpapi_provider_resolves_blob_on_windows(self) -> None:
        if not is_windows():
            self.skipTest("Windows DPAPI is only available on Windows")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "material.bin"
            blob = root / "material.dpapi"
            source.write_bytes(bytes(range(64, 96)))
            protect_file_with_dpapi(source, blob)
            resolver = PasswordResolver(
                environment={},
                prompt_callback=lambda prompt: "unused",
                file_reader=lambda path: "unused",
                binary_file_reader=lambda path: b"unused",
                command_runner=lambda argv: "unused",
            )

            value = resolver.resolve({"type": "dpapi", "path": str(blob)}, "test-context")

            self.assertTrue(value.startswith(DPAPI_WRAPPER_PREFIX))
            self.assertNotIn("\n", value)

    def test_hse2_dpapi_encrypt_validate_decrypt_round_trip_on_windows(self) -> None:
        if not is_windows():
            self.skipTest("Windows DPAPI is only available on Windows")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            material = root / "material.bin"
            blob = root / "wrapper.dpapi"
            plain = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            encrypt_config = root / "encrypt.json"
            validate_config = root / "validate.json"
            decrypt_config = root / "decrypt.json"
            material.write_bytes(bytes(range(96, 128)))
            plain.write_bytes((b"payload" * 100) + b"tail")
            protect_file_with_dpapi(material, blob)
            wrapper_spec = {"type": "dpapi", "path": str(blob)}
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
                json.dumps({"items": [{"input": str(encrypted)}], "wrapper": wrapper_spec}),
                encoding="utf-8",
            )
            decrypt_config.write_text(
                json.dumps({"input": str(encrypted), "output": str(restored), "wrapper": wrapper_spec}),
                encoding="utf-8",
            )

            encrypt_summary = _run_cli_json(["hse2-encrypt-config", "--config", str(encrypt_config)])
            validate_summary = _run_cli_json(["hse2-validate", "--config", str(validate_config)])
            decrypt_summary = _run_cli_json(["hse2-decrypt-config", "--config", str(decrypt_config)])

            self.assertEqual(restored.read_bytes(), plain.read_bytes())
            self.assertEqual(encrypt_summary["wrapper_source"], "dpapi")
            self.assertEqual(decrypt_summary["wrapper_source"], "dpapi")
            self.assertEqual(validate_summary["succeeded"], 1)
            self.assertEqual(validate_summary["failed"], 0)
            self.assertTrue(encrypted.is_file())

    def test_dpapi_unavailable_error_on_non_windows(self) -> None:
        if is_windows():
            self.skipTest("Non-Windows behavior only")
        with self.assertRaisesRegex(DPAPIError, "only available on Windows"):
            unprotect_dpapi_file("missing.dpapi")

    def test_dpapi_provider_reports_unavailable_on_non_windows(self) -> None:
        if is_windows():
            self.skipTest("Non-Windows behavior only")
        resolver = PasswordResolver(
            environment={},
            prompt_callback=lambda prompt: "unused",
            file_reader=lambda path: "unused",
            binary_file_reader=lambda path: b"unused",
            command_runner=lambda argv: "unused",
        )
        with self.assertRaisesRegex(PasswordSourceError, "dpapi source could not unprotect"):
            resolver.resolve({"type": "dpapi", "path": "missing.dpapi"}, "test-context")

    def test_dpapi_protect_refuses_overwrite_on_windows(self) -> None:
        if not is_windows():
            self.skipTest("Windows DPAPI is only available on Windows")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "material.bin"
            blob = root / "material.dpapi"
            source.write_bytes(bytes(range(32)))
            blob.write_text("existing", encoding="utf-8")

            exit_code, stdout, stderr = _run_cli_capture(["dpapi-protect", "--input", str(source), "--output", str(blob)])

            self.assertNotEqual(exit_code, 0)
            self.assertEqual(stdout, "")
            self.assertIn("already exists", stderr)
            self.assertEqual(blob.read_text(encoding="utf-8"), "existing")


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
