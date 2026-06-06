import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import HSE2_PREAMBLE_SIZE
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_header_backup_cli import main as header_backup_main
from high_security_encryptor.hse2_open_cli import main as open_main


class HSE2HeaderBackupCliTests(unittest.TestCase):
    def test_header_backup_cli_restores_damaged_header_container(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            backup = base / "archive.hse2.header"
            damaged = base / "damaged.hse2"
            restored_container = base / "restored.hse2"
            restored_dir = base / "restored"

            with contextlib.redirect_stdout(io.StringIO()):
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

            export_stdout = io.StringIO()
            with contextlib.redirect_stdout(export_stdout):
                export_exit = header_backup_main([
                    "export",
                    "--input",
                    str(container),
                    "--output",
                    str(backup),
                ])
            self.assertEqual(export_exit, 0)
            export_payload = json.loads(export_stdout.getvalue())
            self.assertTrue(export_payload["header_backup_written"])
            self.assertEqual(export_payload["wrapper_count"], 1)
            self.assertTrue(backup.exists())
            self.assertLess(backup.stat().st_size, container.stat().st_size)

            damaged.write_bytes(_damage_header_json(container.read_bytes()))
            with contextlib.redirect_stderr(io.StringIO()):
                open_damaged_exit = open_main([
                    "--input",
                    str(damaged),
                    "--output-dir",
                    str(base / "damaged-open"),
                    "--keyfile",
                    str(keyfile),
                ])
            self.assertEqual(open_damaged_exit, 2)

            restore_stdout = io.StringIO()
            with contextlib.redirect_stdout(restore_stdout):
                restore_exit = header_backup_main([
                    "restore",
                    "--input",
                    str(damaged),
                    "--backup",
                    str(backup),
                    "--output",
                    str(restored_container),
                ])
            self.assertEqual(restore_exit, 0)
            restore_payload = json.loads(restore_stdout.getvalue())
            self.assertTrue(restore_payload["container_written"])
            self.assertEqual(restore_payload["wrapper_count"], 1)

            open_stdout = io.StringIO()
            with contextlib.redirect_stdout(open_stdout):
                open_restored_exit = open_main([
                    "--input",
                    str(restored_container),
                    "--output-dir",
                    str(restored_dir),
                    "--keyfile",
                    str(keyfile),
                ])
            self.assertEqual(open_restored_exit, 0)
            open_payload = json.loads(open_stdout.getvalue())
            self.assertTrue(open_payload["container_opened"])
            self.assertEqual((restored_dir / "root" / "a.txt").read_bytes(), b"abc")

    def test_header_backup_cli_refuses_existing_output_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            backup = base / "archive.hse2.header"
            backup.write_bytes(b"existing")

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
                exit_code = header_backup_main([
                    "export",
                    "--input",
                    str(container),
                    "--output",
                    str(backup),
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-header-backup:", stderr.getvalue())
            self.assertEqual(backup.read_bytes(), b"existing")


def _damage_header_json(data: bytes) -> bytes:
    damaged = bytearray(data)
    if len(damaged) <= HSE2_PREAMBLE_SIZE:
        raise AssertionError("container is too short to damage its header")
    damaged[HSE2_PREAMBLE_SIZE] ^= 0xFF
    return bytes(damaged)


if __name__ == "__main__":
    unittest.main()
