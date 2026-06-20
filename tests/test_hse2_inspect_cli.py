import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_inspect_cli import main as inspect_main


class HSE2InspectCliTests(unittest.TestCase):
    def test_inspect_reports_safe_container_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = _create_fixture(Path(temp_dir))

            payload = _inspect_container(fixture.container)

            self.assertEqual(payload["command"], "hse2-inspect")
            self.assertTrue(payload["experimental"])
            self.assertEqual(payload["format"], "HSE2")
            self.assertEqual(payload["format_version"], 2)
            self.assertEqual(payload["preamble"]["magic"], "HSE2")
            self.assertEqual(payload["preamble"]["format_version"], 2)
            self.assertEqual(payload["preamble"]["header_encoding"], 1)
            self.assertGreater(payload["preamble"]["header_length"], 0)
            self.assertTrue(payload["header_auth"]["tag_present"])
            self.assertEqual(payload["header_auth"]["algorithm"], "HMAC-SHA256")
            self.assertFalse(payload["access_destroyed"])
            self.assertTrue(payload["manifest_encrypted"])
            self.assertEqual(payload["wrapper_count"], 1)
            self.assertEqual(payload["wrapper_types"], ["keyfile"])
            self.assertEqual(payload["wrappers"][0]["id"], "keyfile-1")
            self.assertEqual(payload["wrappers"][0]["type"], "keyfile")
            self.assertEqual(payload["payload_chunk_count"], 2)
            self.assertEqual(payload["payload_layout"]["chunk_count"], 2)
            self.assertTrue(payload["payload_chunk_count_matches_header"])

            serialized = json.dumps(payload, sort_keys=True)
            self.assertNotIn("ciphertext", serialized)
            self.assertNotIn("wrapped_keys", serialized)
            self.assertNotIn("protected_kek", serialized)
            self.assertNotIn("auth_tag", serialized)
            self.assertNotIn("nonce", serialized)

    def test_inspect_supports_compact_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = _create_fixture(Path(temp_dir))
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = inspect_main(["--input", str(fixture.container), "--compact"])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue().count("\n"), 1)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-inspect")

    def test_inspect_rejects_non_hse2_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_path = Path(temp_dir) / "archive.txt"
            bad_path.write_text("not an hse2 container", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = inspect_main(["--input", str(bad_path)])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("input path must use the .hse2 suffix", stderr.getvalue())


class _Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "root"
        self.keyfile = base / "archive.key"
        self.container = base / "archive.hse2"


def _create_fixture(base: Path) -> _Fixture:
    fixture = _Fixture(base)
    fixture.root.mkdir()
    (fixture.root / "a.txt").write_bytes(b"abcdef")
    fixture.keyfile.write_bytes(b"k" * 32)

    with contextlib.redirect_stdout(io.StringIO()):
        create_exit = create_main([
            "--root",
            str(fixture.root),
            "--output",
            str(fixture.container),
            "--keyfile",
            str(fixture.keyfile),
            "--chunk-size",
            "4",
        ])
    if create_exit != 0:
        raise AssertionError(f"fixture create failed: {create_exit}")
    return fixture


def _inspect_container(container: Path) -> dict[str, object]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = inspect_main(["--input", str(container)])
    if exit_code != 0:
        raise AssertionError(f"inspect failed: {exit_code}")
    return json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
