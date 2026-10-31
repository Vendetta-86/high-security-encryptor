from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from high_security_encryptor.hse2.keyfile_safety import keyfile_colocation_warning
from high_security_encryptor.hse2_create_cli import main as create_cli_main
from high_security_encryptor.hse2_open_cli import main as open_cli_main
from high_security_encryptor.hse2_wrapper_cli import _keyfile_colocation_warning_for_args


FIXTURE_ARCHIVE = Path(__file__).parent / "fixtures" / "hse2" / "archive-v3.hse2"
FIXTURE_KEY = b"HSE2-FIXTURE-KEY-MATERIAL-000000"


class HSE2KeyfileSafetyTests(unittest.TestCase):
    def test_colocation_helper_warns_for_same_resolved_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            warning = keyfile_colocation_warning((root / "wrapper.key",), (root / "archive.hse2",))
            self.assertIsNotNone(warning)
            self.assertIn("share a directory", warning)

    def test_colocation_helper_is_silent_for_separate_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            warning = keyfile_colocation_warning(
                (root / "keys" / "wrapper.key",), (root / "archives" / "archive.hse2",)
            )
            self.assertIsNone(warning)

    def test_create_dry_run_emits_warning_on_stderr_without_corrupting_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.txt"
            source.write_text("sample", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = [
                "--root", str(source), "--output", str(root / "archive.hse2"),
                "--keyfile", str(root / "wrapper.key"), "--dry-run", "--compact",
            ]

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = create_cli_main(argv)

            self.assertEqual(exit_code, 0, stderr.getvalue())
            self.assertTrue(json.loads(stdout.getvalue())["dry_run"])
            self.assertIn("share a directory", stderr.getvalue())

    def test_open_cli_warns_and_still_restores_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "archive.hse2"
            keyfile = root / "wrapper.key"
            output = root / "restored"
            shutil.copyfile(FIXTURE_ARCHIVE, archive)
            keyfile.write_bytes(FIXTURE_KEY)
            stdout, stderr = io.StringIO(), io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = open_cli_main([
                    "--input", str(archive), "--output-dir", str(output), "--keyfile", str(keyfile), "--compact",
                ])

            self.assertEqual(exit_code, 0, stderr.getvalue())
            self.assertIn("share a directory", stderr.getvalue())
            self.assertEqual((output / "fixture-payload.txt").read_bytes(),
                             b"Codex HSE2 compatibility fixture v1\n")

    def test_wrapper_cli_checks_old_and_new_keyfile_locations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = argparse.Namespace(
                command="add", input=str(root / "source.hse2"), output=str(root / "target.hse2"),
                keyfile=str(root / "unlock.key"), new_keyfile=str(root / "new.key"),
            )
            warning = _keyfile_colocation_warning_for_args(args)
            self.assertIsNotNone(warning)
            self.assertIn("share a directory", warning)


if __name__ == "__main__":
    unittest.main()
