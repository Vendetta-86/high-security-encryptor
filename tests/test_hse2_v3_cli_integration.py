from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path
import tomllib
import unittest

from high_security_encryptor.hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE, list_hse2_wrappers
from high_security_encryptor.hse2.container_codec import HSE2_PREAMBLE_STRUCT, decode_header_frame
from high_security_encryptor.hse2.container_stream import read_v3_header_frame
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_open_cli import main as open_main
from high_security_encryptor.hse2_wrapper_cli import main as wrapper_main
from high_security_encryptor.hse2_access_cli import main as access_main
from high_security_encryptor.hse2_header_backup_cli import main as backup_main
from high_security_encryptor.hse2_gui_actions import HSE2_GUI_ACTIONS


class HSE2V3CliIntegrationTests(unittest.TestCase):
    def _capture(self, call, args: list[str]) -> tuple[int, dict[str, object], str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = call(args)
        payload = json.loads(stdout.getvalue()) if stdout.getvalue() else {}
        return code, payload, stderr.getvalue()

    def _container_body(self, archive: Path) -> bytes:
        data = archive.read_bytes()
        _magic, version, _encoding, _reserved, _header_length = HSE2_PREAMBLE_STRUCT.unpack(data[:HSE2_PREAMBLE_STRUCT.size])
        if version == 2:
            _preamble, _header, body = decode_header_frame(data)
            return body
        with io.BytesIO(data) as stream:
            read_v3_header_frame(stream)
            return data[stream.tell():]

    def _create(self, base: Path, *, version: int | None) -> tuple[Path, Path, Path, dict[str, object]]:
        source_root = base / "source"
        source_root.mkdir(parents=True)
        (source_root / "payload.bin").write_bytes(b"M1.6 CLI archive payload" * 8)
        keyfile = base / "archive.key"
        keyfile.write_bytes(b"k" * 32)
        archive = base / ("archive-v3.hse2" if version == 3 else "archive-v2.hse2")
        args = [
            "--root", str(source_root),
            "--output", str(archive),
            "--keyfile", str(keyfile),
            "--chunk-size", "32",
            "--compact",
        ]
        if version is not None:
            args.extend(["--format-version", str(version)])
        code, payload, stderr = self._capture(create_main, args)
        self.assertEqual(code, 0, stderr)
        return source_root, keyfile, archive, payload

    def test_create_cli_defaults_to_v2_and_can_create_v3_then_open_auto_detects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _source_root, keyfile, archive_v2, summary_v2 = self._create(base / "v2", version=None)
            self.assertEqual(summary_v2["format_version"], 2)

            v3_base = base / "v3"
            v3_base.mkdir()
            _source_root, v3_keyfile, archive_v3, summary_v3 = self._create(v3_base, version=3)
            self.assertEqual(summary_v3["format_version"], 3)
            self.assertEqual(summary_v3["payload_chunk_count"], 6)

            for archive, key, name in (
                (archive_v2, keyfile, "restored-v2"),
                (archive_v3, v3_keyfile, "restored-v3"),
            ):
                output_dir = base / name
                code, opened, stderr = self._capture(
                    open_main,
                    ["--input", str(archive), "--output-dir", str(output_dir), "--keyfile", str(key), "--compact"],
                )
                self.assertEqual(code, 0, stderr)
                self.assertTrue(opened["container_opened"])
                self.assertEqual((output_dir / "source" / "payload.bin").read_bytes(), b"M1.6 CLI archive payload" * 8)

    def test_wrapper_cli_add_list_and_remove_v3_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, keyfile, archive, _summary = self._create(base, version=3)
            password_file = base / "new-password.txt"
            password_file.write_text("added wrapper password\n", encoding="utf-8")
            added = base / "added.hse2"
            code, added_summary, stderr = self._capture(
                wrapper_main,
                [
                    "add", "--input", str(archive), "--output", str(added),
                    "--wrapper-id", "password-2", "--new-password-file", str(password_file),
                    "--keyfile", str(keyfile), "--compact",
                ],
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(added_summary["format_version"], 3)
            self.assertEqual(len(list_hse2_wrappers(added).wrappers), 2)

            restored = base / "opened-with-new-password"
            code, opened, stderr = self._capture(
                open_main,
                ["--input", str(added), "--output-dir", str(restored), "--password-file", str(password_file), "--compact"],
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(opened["container_opened"])

            removed = base / "removed.hse2"
            code, removed_summary, stderr = self._capture(
                wrapper_main,
                [
                    "remove", "--input", str(added), "--output", str(removed),
                    "--wrapper-id", "password-2", "--keyfile", str(keyfile), "--compact",
                ],
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(removed_summary["remaining_wrapper_count"], 1)
            self.assertEqual(len(list_hse2_wrappers(removed).wrappers), 1)

    def test_wrapper_cli_rewrap_atomically_changes_v3_unlock_factor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, old_keyfile, archive, _summary = self._create(base, version=3)
            old_wrapper_id = list_hse2_wrappers(archive).wrappers[0].id
            new_password_file = base / "replacement-password.txt"
            new_password_file.write_text("replacement password\n", encoding="utf-8")
            rewrapped = base / "rewrapped.hse2"
            old_body = self._container_body(archive)

            code, summary, stderr = self._capture(
                wrapper_main,
                [
                    "rewrap", "--input", str(archive), "--output", str(rewrapped),
                    "--wrapper-id", old_wrapper_id, "--new-wrapper-id", old_wrapper_id,
                    "--new-password-file", str(new_password_file), "--keyfile", str(old_keyfile), "--compact",
                ],
            )

            self.assertEqual(code, 0, stderr)
            self.assertEqual(summary["format_version"], 3)
            self.assertEqual(summary["resulting_wrapper_count"], 1)
            self.assertEqual(self._container_body(rewrapped), old_body)
            opened_dir = base / "opened-with-replacement"
            code, opened, stderr = self._capture(
                open_main,
                ["--input", str(rewrapped), "--output-dir", str(opened_dir), "--password-file", str(new_password_file), "--compact"],
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(opened["container_opened"])
            self.assertEqual((opened_dir / "source" / "payload.bin").read_bytes(), b"M1.6 CLI archive payload" * 8)
            code, _failed, _stderr = self._capture(
                open_main,
                ["--input", str(rewrapped), "--output-dir", str(base / "old-factor-fails"), "--keyfile", str(old_keyfile), "--compact"],
            )
            self.assertEqual(code, 2)

    def test_wrapper_cli_rewrap_preserves_v2_json_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, old_keyfile, archive, _summary = self._create(base, version=2)
            wrapper_id = list_hse2_wrappers(archive).wrappers[0].id
            password_file = base / "new-password.txt"
            password_file.write_text("v2 replacement password\n", encoding="utf-8")
            rewrapped = base / "rewrapped-v2.hse2"
            body = self._container_body(archive)
            code, summary, stderr = self._capture(
                wrapper_main,
                [
                    "rewrap", "--input", str(archive), "--output", str(rewrapped),
                    "--wrapper-id", wrapper_id, "--new-password-file", str(password_file),
                    "--keyfile", str(old_keyfile), "--compact",
                ],
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(summary["format_version"], 2)
            self.assertEqual(self._container_body(rewrapped), body)
            output_dir = base / "opened-v2"
            code, opened, stderr = self._capture(
                open_main,
                ["--input", str(rewrapped), "--output-dir", str(output_dir), "--password-file", str(password_file), "--compact"],
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(opened["container_opened"])
            self.assertEqual((output_dir / "source" / "payload.bin").read_bytes(), b"M1.6 CLI archive payload" * 8)

    def test_v3_access_destroy_cli_authenticates_and_marks_access_destroyed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, keyfile, archive, _summary = self._create(base, version=3)
            output = base / "destroyed.hse2"
            code, summary, stderr = self._capture(
                access_main,
                [
                    "destroy", "--input", str(archive), "--output", str(output),
                    "--confirm", DESTROY_ACCESS_CONFIRMATION_PHRASE,
                    "--keyfile", str(keyfile), "--compact",
                ],
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(summary["access_destroyed"])
            listed = list_hse2_wrappers(output)
            self.assertTrue(listed.access_destroyed)
            self.assertEqual(listed.wrappers, ())

    def test_header_backup_restores_wrapper_region_after_access_destroy_v2_and_v3(self) -> None:
        for version in (2, 3):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, keyfile, archive, create_summary = self._create(base, version=version)
                backup = Path(str(create_summary["header_backup_path"]))
                code, _backup_summary, stderr = self._capture(
                    backup_main,
                    create_summary["header_backup_export_argv"][1:],
                )
                self.assertEqual(code, 0, stderr)

                destroyed = base / "destroyed.hse2"
                code, destroy_summary, stderr = self._capture(
                    access_main,
                    [
                        "destroy", "--input", str(archive), "--output", str(destroyed),
                        "--confirm", DESTROY_ACCESS_CONFIRMATION_PHRASE,
                        "--keyfile", str(keyfile), "--compact",
                    ],
                )
                self.assertEqual(code, 0, stderr)
                self.assertTrue(destroy_summary["access_destroyed"])
                self.assertEqual(self._container_body(archive), self._container_body(destroyed))
                self.assertNotEqual(archive.stat().st_size, destroyed.stat().st_size)

                restored = base / "recovered.hse2"
                code, restore_summary, stderr = self._capture(
                    backup_main,
                    [
                        "restore", "--input", str(destroyed), "--backup", str(backup),
                        "--output", str(restored), "--compact",
                    ],
                )
                self.assertEqual(code, 0, stderr)
                self.assertTrue(restore_summary["body_digest_verified"])

                output_dir = base / "opened"
                code, open_summary, stderr = self._capture(
                    open_main,
                    ["--input", str(restored), "--output-dir", str(output_dir), "--keyfile", str(keyfile), "--compact"],
                )
                self.assertEqual(code, 0, stderr)
                self.assertTrue(open_summary["container_opened"])
                self.assertEqual(
                    (output_dir / "source" / "payload.bin").read_bytes(),
                    b"M1.6 CLI archive payload" * 8,
                )

    def test_v3_header_backup_cli_export_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, keyfile, archive, _summary = self._create(base, version=3)
            backup = base / "archive.hse2.header"
            code, metadata, stderr = self._capture(
                backup_main,
                ["export", "--input", str(archive), "--output", str(backup), "--compact"],
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(metadata["body_sha256"].__len__(), 64)

            damaged = base / "damaged.hse2"
            data = bytearray(archive.read_bytes())
            data[20] ^= 1
            damaged.write_bytes(data)
            restored = base / "restored.hse2"
            code, restored_summary, stderr = self._capture(
                backup_main,
                [
                    "restore", "--input", str(damaged), "--backup", str(backup),
                    "--output", str(restored), "--compact",
                ],
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(restored_summary["body_digest_verified"])
            output_dir = base / "opened"
            code, opened, stderr = self._capture(
                open_main,
                ["--input", str(restored), "--output-dir", str(output_dir), "--keyfile", str(keyfile), "--compact"],
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(opened["container_opened"])

    def test_entrypoints_and_gui_do_not_advertise_unimplemented_archive_controls(self) -> None:
        pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        scripts = pyproject["project"]["scripts"]
        for command in (
            "high-security-encryptor-hse2-create",
            "high-security-encryptor-hse2-open",
            "high-security-encryptor-hse2-wrapper",
            "high-security-encryptor-hse2-access",
            "high-security-encryptor-hse2-header-backup",
        ):
            self.assertIn(command, scripts)
        self.assertNotIn("archive-create", HSE2_GUI_ACTIONS)
        self.assertNotIn("archive-open", HSE2_GUI_ACTIONS)
        self.assertIn("wrapper-add", HSE2_GUI_ACTIONS)
        self.assertIn("wrapper-rewrap", HSE2_GUI_ACTIONS)
        self.assertNotIn("header-backup", HSE2_GUI_ACTIONS)


if __name__ == "__main__":
    unittest.main()
