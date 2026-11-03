import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import is_dpapi_available
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_open_cli import main as open_main
from high_security_encryptor.hse2_wrapper_cli import main as wrapper_main
from high_security_encryptor.hse2.access_management import list_hse2_wrappers
from high_security_encryptor.windows_dpapi import protect_file_with_dpapi


@unittest.skipUnless(is_dpapi_available(), "Windows DPAPI is only available on Windows")
class HSE2DpapiCliTests(unittest.TestCase):
    def test_keyfile_blob_and_archive_dpapi_calls_share_process_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            material = base / "material.key"
            blob = base / "material.dpapi"
            root = base / "root"
            root.mkdir()
            (root / "payload.txt").write_bytes(b"DPAPI mixed API order payload")
            archive = base / "archive.hse2"
            restored = base / "restored"
            material.write_bytes(b"m" * 32)

            # Both helpers configure process-global CryptProtectData with
            # different ctypes DATA_BLOB classes. The file helper runs first.
            protect_file_with_dpapi(material, blob)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                create_exit = create_main([
                    "--root", str(root), "--output", str(archive), "--dpapi",
                ])
            self.assertEqual(create_exit, 0)

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                open_exit = open_main([
                    "--input", str(archive), "--output-dir", str(restored), "--dpapi",
                ])
            self.assertEqual(open_exit, 0)
            self.assertEqual((restored / "root" / "payload.txt").read_bytes(), b"DPAPI mixed API order payload")

            # Exercise the reverse transition after HSE2 used its own signature.
            second_blob = base / "second.dpapi"
            protect_file_with_dpapi(material, second_blob)
            self.assertTrue(second_blob.is_file())

    def test_dpapi_wrapper_add_keeps_independent_password_wrapper_on_windows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "payload.txt").write_bytes(b"DPAPI wrapper integration payload")
            password_file = base / "password.txt"
            password_file.write_text("independent recovery password\n", encoding="utf-8")
            archive = base / "archive.hse2"
            added = base / "added.hse2"

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(create_main([
                    "--root", str(root), "--output", str(archive),
                    "--password-file", str(password_file), "--profile", "compatible",
                ]), 0)
            add_stdout = io.StringIO()
            add_stderr = io.StringIO()
            with contextlib.redirect_stdout(add_stdout), contextlib.redirect_stderr(add_stderr):
                self.assertEqual(wrapper_main([
                    "add", "--input", str(archive), "--output", str(added),
                    "--wrapper-id", "dpapi-recovery", "--new-dpapi",
                    "--password-file", str(password_file), "--compact",
                ]), 0)
            self.assertIn("DPAPI recovery warning", add_stderr.getvalue())
            add_summary = json.loads(add_stdout.getvalue())
            self.assertIn("DPAPI wrapper is tied", add_summary["dpapi_recovery_warning"])
            self.assertEqual({wrapper.type for wrapper in list_hse2_wrappers(added).wrappers}, {"password", "dpapi"})

            dpapi_open = base / "opened-dpapi"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(open_main([
                    "--input", str(added), "--output-dir", str(dpapi_open), "--dpapi",
                ]), 0)
            self.assertEqual((dpapi_open / "root" / "payload.txt").read_bytes(), b"DPAPI wrapper integration payload")

            removed = base / "removed.hse2"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(wrapper_main([
                    "remove", "--input", str(added), "--output", str(removed),
                    "--wrapper-id", "dpapi-recovery", "--password-file", str(password_file),
                ]), 0)
            self.assertEqual({wrapper.type for wrapper in list_hse2_wrappers(removed).wrappers}, {"password"})

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
            create_stderr = io.StringIO()
            with contextlib.redirect_stdout(create_stdout), contextlib.redirect_stderr(create_stderr):
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
            self.assertIn("Keep an independent password or keyfile wrapper", create_payload["dpapi_recovery_warning"])
            self.assertIn("DPAPI recovery warning", create_stderr.getvalue())

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
