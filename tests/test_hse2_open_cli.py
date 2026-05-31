import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_open_cli import main as open_main


class HSE2OpenCliTests(unittest.TestCase):
    def test_open_cli_restores_keyfile_only_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"abc")
            (nested / "b.bin").write_bytes(b"0123456789")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            restored = base / "restored"

            create_stdout = io.StringIO()
            with contextlib.redirect_stdout(create_stdout):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--keyfile",
                    str(keyfile),
                    "--chunk-size",
                    "4",
                ])
            self.assertEqual(create_exit, 0)

            open_stdout = io.StringIO()
            with contextlib.redirect_stdout(open_stdout):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(keyfile),
                ])

            self.assertEqual(open_exit, 0)
            payload = json.loads(open_stdout.getvalue())
            self.assertTrue(payload["container_opened"])
            self.assertEqual(payload["wrapper_type"], "keyfile")
            self.assertEqual((restored / "root" / "a.txt").read_bytes(), b"abc")
            self.assertEqual((restored / "root" / "nested" / "b.bin").read_bytes(), b"0123456789")

    def test_open_cli_rejects_wrong_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            wrong_keyfile = base / "wrong.key"
            wrong_keyfile.write_bytes(b"w" * 32)
            container = base / "archive.hse2"
            restored = base / "restored"

            with contextlib.redirect_stdout(io.StringIO()):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--keyfile",
                    str(keyfile),
                ])
            self.assertEqual(create_exit, 0)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(wrong_keyfile),
                ])

            self.assertEqual(open_exit, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-open:", stderr.getvalue())
            self.assertFalse((restored / "root" / "a.txt").exists())

    def test_open_cli_refuses_existing_file_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            restored = base / "restored"
            existing = restored / "root" / "a.txt"
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b"existing")

            with contextlib.redirect_stdout(io.StringIO()):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--keyfile",
                    str(keyfile),
                ])
            self.assertEqual(create_exit, 0)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(keyfile),
                ])

            self.assertEqual(open_exit, 2)
            self.assertEqual(existing.read_bytes(), b"existing")
            self.assertIn("target already exists", stderr.getvalue())

            with contextlib.redirect_stdout(io.StringIO()):
                overwrite_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(keyfile),
                    "--overwrite",
                ])
            self.assertEqual(overwrite_exit, 0)
            self.assertEqual(existing.read_bytes(), b"abc")

    def test_open_cli_requires_unlock_material(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            container = base / "archive.hse2"
            container.write_bytes(b"not-a-container")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = open_main(["--input", str(container), "--output-dir", str(base / "out")])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-open:", stderr.getvalue())
            self.assertIn("requires --password-file, --keyfile, or both", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
