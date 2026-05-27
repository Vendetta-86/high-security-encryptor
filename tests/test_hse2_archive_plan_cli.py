import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_archive_plan_cli import main


class HSE2ArchivePlanCliTests(unittest.TestCase):
    def test_archive_plan_cli_reports_metadata_only_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"a")
            (nested / "b.txt").write_bytes(b"bb")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-plan-archive")
            self.assertTrue(payload["experimental"])
            self.assertEqual(payload["root_count"], 1)
            self.assertEqual(payload["entry_count"], 4)
            self.assertEqual(payload["file_count"], 2)
            self.assertEqual(payload["directory_count"], 2)
            self.assertEqual(payload["total_file_size"], 3)
            self.assertEqual([entry["path"] for entry in payload["entries"]], ["root", "root/a.txt", "root/nested", "root/nested/b.txt"])


if __name__ == "__main__":
    unittest.main()
