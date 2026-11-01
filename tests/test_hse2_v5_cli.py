from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from high_security_encryptor.cli import build_parser, main


class HSE2V5CliTests(unittest.TestCase):
    def test_v5_commands_are_registered_and_mappings_repeat(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "hse2", "v5-create", "--output", "archive.hse2",
            "--primary-file", "a.txt=C:/input/a.txt",
            "--primary-file", "b.txt=C:/input/b.txt",
        ])
        self.assertEqual(args.hse2_command, "v5-create")
        self.assertEqual(args.primary_file, ["a.txt=C:/input/a.txt", "b.txt=C:/input/b.txt"])
        self.assertEqual(args.profile, "compatible")
        empty_replace = parser.parse_args([
            "hse2", "v5-replace", "--input", "old.hse2", "--output", "new.hse2",
        ])
        self.assertEqual(empty_replace.file, [])
        opened = parser.parse_args([
            "hse2", "v5-open", "--input", "archive.hse2", "--output-dir", "restore",
        ])
        self.assertEqual(opened.hse2_command, "v5-open")
        compact = parser.parse_args([
            "hse2", "v5-compact", "--input", "old.hse2", "--output", "compact.hse2",
        ])
        self.assertEqual(compact.hse2_command, "v5-compact")
        exported = parser.parse_args([
            "hse2", "v4-to-v5", "--input", "old-v4.hse2", "--output", "new-v5.hse2",
        ])
        self.assertEqual(exported.hse2_command, "v4-to-v5")

    def test_v5_create_uses_password_confirmation_and_does_not_print_secrets(self) -> None:
        passwords = ["primary view secret", "primary view secret", "secondary view secret", "secondary view secret"]
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "archive.hse2"
            with patch("high_security_encryptor.cli.getpass.getpass", side_effect=passwords), \
                    patch("high_security_encryptor.cli.create_v5_archive", return_value=output) as create, \
                    contextlib.redirect_stdout(stdout):
                result = main([
                    "hse2", "v5-create", "--output", str(output),
                    "--primary-file", "main.txt=C:/input/main.txt",
                    "--secondary-file", "notes.txt=C:/input/notes.txt",
                ])
        self.assertEqual(result, 0)
        report = stdout.getvalue()
        self.assertNotIn("primary view secret", report)
        self.assertNotIn("secondary view secret", report)
        self.assertEqual(json.loads(report)["format_version"], 5)
        self.assertEqual(create.call_args.kwargs["view_passwords"],
                         ("primary view secret", "secondary view secret"))
        self.assertEqual(create.call_args.kwargs["view_files"][0][0][0], "main.txt")

    def test_v5_compact_reads_both_passwords_from_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "compact.hse2"
            with patch("sys.stdin", io.StringIO("primary secret\nsecondary secret\n")), \
                    patch("high_security_encryptor.cli.compact_v5_archive", return_value=output) as compact, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = main([
                    "hse2", "v5-compact", "--input", "old.hse2", "--output", str(output),
                    "--passwords-stdin",
                ])
        self.assertEqual(result, 0)
        self.assertEqual(compact.call_args.kwargs["view_passwords"], ("primary secret", "secondary secret"))

    def test_v4_to_v5_uses_both_passwords_and_keeps_the_input_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "exported.hse2"
            with patch("high_security_encryptor.cli.getpass.getpass",
                       side_effect=("primary secret", "secondary secret")), \
                    patch("high_security_encryptor.cli.export_v4_to_v5", return_value=output) as export, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = main(["hse2", "v4-to-v5", "--input", "old-v4.hse2", "--output", str(output)])
        self.assertEqual(result, 0)
        self.assertEqual(export.call_args.kwargs["view_passwords"], ("primary secret", "secondary secret"))


if __name__ == "__main__":
    unittest.main()
