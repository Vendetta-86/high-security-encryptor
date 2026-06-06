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
            fixture = _create_fixture(base)

            export_payload = _export_backup(fixture.container, fixture.backup)
            self.assertTrue(export_payload["header_backup_written"])
            self.assertEqual(export_payload["wrapper_count"], 1)
            self.assertTrue(export_payload["metadata_written"])
            self.assertGreater(export_payload["body_offset"], HSE2_PREAMBLE_SIZE)
            self.assertTrue(fixture.backup.exists())
            self.assertLess(fixture.backup.stat().st_size, fixture.container.stat().st_size)

            fixture.damaged.write_bytes(_damage_header_json(fixture.container.read_bytes()))
            self.assertEqual(_open_container(fixture.damaged, fixture.keyfile, base / "damaged-open"), 2)

            restore_payload = _restore_backup(fixture.damaged, fixture.backup, fixture.restored_container)
            self.assertTrue(restore_payload["container_written"])
            self.assertEqual(restore_payload["wrapper_count"], 1)
            self.assertTrue(restore_payload["metadata_used"])
            self.assertTrue(restore_payload["body_digest_verified"])

            self.assertEqual(_open_container(fixture.restored_container, fixture.keyfile, fixture.restored_dir), 0)
            self.assertEqual((fixture.restored_dir / "root" / "a.txt").read_bytes(), b"abc")

    def test_header_backup_cli_restores_damaged_preamble_from_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            fixture = _create_fixture(base)
            export_payload = _export_backup(fixture.container, fixture.backup)
            body_offset = export_payload["body_offset"]

            fixture.damaged.write_bytes(_damage_preamble(fixture.container.read_bytes()))
            self.assertEqual(_open_container(fixture.damaged, fixture.keyfile, base / "damaged-preamble-open"), 2)

            restore_payload = _restore_backup(fixture.damaged, fixture.backup, fixture.restored_container)
            self.assertEqual(restore_payload["body_offset"], body_offset)
            self.assertTrue(restore_payload["metadata_used"])
            self.assertTrue(restore_payload["body_digest_verified"])

            self.assertEqual(_open_container(fixture.restored_container, fixture.keyfile, fixture.restored_dir), 0)
            self.assertEqual((fixture.restored_dir / "root" / "a.txt").read_bytes(), b"abc")

    def test_header_backup_cli_accepts_manual_body_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            fixture = _create_fixture(base)
            export_payload = _export_backup(fixture.container, fixture.backup)
            body_offset = export_payload["body_offset"]

            fixture.damaged.write_bytes(_damage_preamble(fixture.container.read_bytes()))
            restore_payload = _restore_backup(
                fixture.damaged,
                fixture.backup,
                fixture.restored_container,
                extra_args=["--body-offset", str(body_offset)],
            )
            self.assertEqual(restore_payload["manual_body_offset"], body_offset)
            self.assertEqual(_open_container(fixture.restored_container, fixture.keyfile, fixture.restored_dir), 0)
            self.assertEqual((fixture.restored_dir / "root" / "a.txt").read_bytes(), b"abc")

    def test_header_backup_cli_rejects_body_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            fixture = _create_fixture(base)
            export_payload = _export_backup(fixture.container, fixture.backup)

            tampered = bytearray(fixture.container.read_bytes())
            tampered[export_payload["body_offset"]] ^= 0xFF
            fixture.damaged.write_bytes(bytes(tampered))

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = header_backup_main([
                    "restore",
                    "--input",
                    str(fixture.damaged),
                    "--backup",
                    str(fixture.backup),
                    "--output",
                    str(fixture.restored_container),
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("body digest", stderr.getvalue())
            self.assertFalse(fixture.restored_container.exists())

    def test_header_backup_cli_refuses_existing_output_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            fixture = _create_fixture(base)
            fixture.backup.write_bytes(b"existing")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = header_backup_main([
                    "export",
                    "--input",
                    str(fixture.container),
                    "--output",
                    str(fixture.backup),
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-header-backup:", stderr.getvalue())
            self.assertEqual(fixture.backup.read_bytes(), b"existing")


class _Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "root"
        self.keyfile = base / "archive.key"
        self.container = base / "archive.hse2"
        self.backup = base / "archive.hse2.header"
        self.damaged = base / "damaged.hse2"
        self.restored_container = base / "restored.hse2"
        self.restored_dir = base / "restored"


def _create_fixture(base: Path) -> _Fixture:
    fixture = _Fixture(base)
    fixture.root.mkdir()
    (fixture.root / "a.txt").write_bytes(b"abc")
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


def _export_backup(container: Path, backup: Path) -> dict[str, object]:
    export_stdout = io.StringIO()
    with contextlib.redirect_stdout(export_stdout):
        export_exit = header_backup_main([
            "export",
            "--input",
            str(container),
            "--output",
            str(backup),
        ])
    if export_exit != 0:
        raise AssertionError(f"backup export failed: {export_exit}")
    return json.loads(export_stdout.getvalue())


def _restore_backup(input_path: Path, backup: Path, output_path: Path, extra_args: list[str] | None = None) -> dict[str, object]:
    restore_stdout = io.StringIO()
    args = [
        "restore",
        "--input",
        str(input_path),
        "--backup",
        str(backup),
        "--output",
        str(output_path),
    ]
    if extra_args:
        args.extend(extra_args)
    with contextlib.redirect_stdout(restore_stdout):
        restore_exit = header_backup_main(args)
    if restore_exit != 0:
        raise AssertionError(f"backup restore failed: {restore_exit}")
    return json.loads(restore_stdout.getvalue())


def _open_container(container: Path, keyfile: Path, output_dir: Path) -> int:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        return open_main([
            "--input",
            str(container),
            "--output-dir",
            str(output_dir),
            "--keyfile",
            str(keyfile),
        ])


def _damage_header_json(data: bytes) -> bytes:
    damaged = bytearray(data)
    if len(damaged) <= HSE2_PREAMBLE_SIZE:
        raise AssertionError("container is too short to damage its header")
    damaged[HSE2_PREAMBLE_SIZE] ^= 0xFF
    return bytes(damaged)


def _damage_preamble(data: bytes) -> bytes:
    damaged = bytearray(data)
    if len(damaged) < 1:
        raise AssertionError("container is too short to damage its preamble")
    damaged[0] ^= 0xFF
    return bytes(damaged)


if __name__ == "__main__":
    unittest.main()
