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
        verified = parser.parse_args(["hse2", "v5-verify", "--input", "archive.hse2", "--password-stdin"])
        self.assertEqual(verified.hse2_command, "v5-verify")
        self.assertTrue(verified.password_stdin)
        preview = parser.parse_args([
            "hse2", "v5-preview", "--input", "archive.hse2", "--output-dir", "restore",
        ])
        self.assertEqual(preview.hse2_command, "v5-preview")
        self.assertEqual(preview.output_dir, "restore")
        update = parser.parse_args([
            "hse2", "v5-password-update", "--input", "archive.hse2", "--output", "updated.hse2",
        ])
        self.assertEqual(update.hse2_command, "v5-password-update")
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

    def test_v5_password_update_reads_and_confirms_secrets_without_printing_them(self) -> None:
        passwords = ("old primary secret", "new primary secret", "new primary secret")
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO("\n".join(passwords) + "\n")), \
                patch("high_security_encryptor.cli.update_v5_view_password", return_value=Path("updated.hse2")) as update, \
                contextlib.redirect_stdout(stdout):
            result = main([
                "hse2", "v5-password-update", "--input", "archive.hse2", "--output", "updated.hse2",
                "--passwords-stdin",
            ])
        self.assertEqual(result, 0)
        report = stdout.getvalue()
        for secret in passwords:
            self.assertNotIn(secret, report)
        self.assertEqual(update.call_args.kwargs["current_password"], passwords[0])
        self.assertEqual(update.call_args.kwargs["new_password"], passwords[1])

    def test_v5_password_update_rejects_confirmation_mismatch_before_workflow(self) -> None:
        with patch("sys.stdin", io.StringIO("old\nnew\nwrong\n")), \
                patch("high_security_encryptor.cli.update_v5_view_password") as update, \
                contextlib.redirect_stderr(io.StringIO()):
            result = main([
                "hse2", "v5-password-update", "--input", "archive.hse2", "--output", "updated.hse2",
                "--passwords-stdin",
            ])
        self.assertNotEqual(result, 0)
        update.assert_not_called()

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
