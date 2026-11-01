from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from high_security_encryptor.cli import build_parser, main


class HSE2V4CliTests(unittest.TestCase):
    def test_v4_commands_are_registered_under_unified_hse2(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "hse2", "v4-create", "--output", "container.hse2",
            "--capacity-records", "2", "--primary-file", "a.txt=C:/data/a.txt",
        ])
        self.assertEqual(args.hse2_command, "v4-create")
        self.assertEqual(args.primary_file, ["a.txt=C:/data/a.txt"])
        self.assertEqual(args.profile, "compatible")

    def test_v4_create_prompts_without_echoing_passwords(self) -> None:
        passwords = ["primary secret", "primary secret", "secondary secret", "secondary secret"]
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate.hse2"
            with patch("high_security_encryptor.cli.getpass.getpass", side_effect=passwords), \
                    patch("high_security_encryptor.cli.create_v4_archive", return_value=output) as create, \
                    contextlib.redirect_stdout(stdout):
                result = main([
                    "hse2", "v4-create", "--output", str(output),
                    "--capacity-records", "2", "--primary-file", "main.txt=C:/input/main.txt",
                    "--secondary-file", "notes.txt=C:/input/notes.txt",
                ])
        self.assertEqual(result, 0)
        report = stdout.getvalue()
        self.assertNotIn("primary secret", report)
        self.assertNotIn("secondary secret", report)
        summary = json.loads(report)
        self.assertEqual(summary["format_version"], 4)
        self.assertEqual(summary["records_per_view"], 1)
        kwargs = create.call_args.kwargs
        self.assertEqual(kwargs["view_passwords"], ("primary secret", "secondary secret"))
        self.assertEqual(kwargs["view_files"][0][0][0], "main.txt")
        self.assertEqual(kwargs["view_files"][1][0][0], "notes.txt")


if __name__ == "__main__":
    unittest.main()
