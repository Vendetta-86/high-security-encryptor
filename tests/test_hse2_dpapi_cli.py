import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import is_dpapi_available
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_open_cli import main as open_main


@unittest.skipUnless(is_dpapi_available(), "Windows DPAPI is only available on Windows")
class HSE2DpapiCliTests(unittest.TestCase):
    def test_dpapi_create_open_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"abc")
            (nested / "b.bin").write_bytes(b"0123456789")
            container = base / "archive.hse2"
            restored = base / "restored"

            create_stdout = io.StringIO()
            with contextlib.redirect_stdout(create_stdout):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--dpapi",
                    "--chunk-size",
                    "4",
                ])
            self.assertEqual(create_exit, 0)
            create_payload = json.loads(create_stdout.getvalue())
            self.assertTrue(create_payload["container_written"])
            self.assertEqual(create_payload["wrapper_type"], "dpapi")

            open_stdout = io.StringIO()
            with contextlib.redirect_stdout(open_stdout):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--dpapi",
                ])
            self.assertEqual(open_exit, 0)
            open_payload = json.loads(open_stdout.getvalue())
            self.assertTrue(open_payload["container_opened"])
            self.assertEqual(open_payload["wrapper_type"], "dpapi")
            self.assertEqual((restored / "root" / "a.txt").read_bytes(), b"abc")
            self.assertEqual((restored / "root" / "nested" / "b.bin").read_bytes(), b"0123456789")

    def test_dpapi_container_requires_dpapi_open_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            container = base / "archive.hse2"

            with contextlib.redirect_stdout(io.StringIO()):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--dpapi",
                ])
            self.assertEqual(create_exit, 0)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(base / "restored"),
                ])

            self.assertEqual(open_exit, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-open:", stderr.getvalue())
            self.assertIn("--dpapi", stderr.getvalue())

    def test_create_rejects_dpapi_combined_with_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(base / "archive.hse2"),
                    "--dpapi",
                    "--keyfile",
                    str(keyfile),
                ])

            self.assertEqual(create_exit, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("cannot be combined", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
