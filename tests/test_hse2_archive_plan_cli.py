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
                exit_code = main(["--root", str(root), "--chunk-size", "2"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-plan-archive")
            self.assertTrue(payload["experimental"])
            self.assertEqual(payload["format"], "HSE2-archive-assembly-plan-v1")
            self.assertEqual(payload["root_count"], 1)
            self.assertEqual(payload["entry_count"], 4)
            self.assertEqual(payload["file_count"], 2)
            self.assertEqual(payload["chunk_size"], 2)
            self.assertEqual(payload["payload_chunk_count"], 2)
            self.assertIsNone(payload["output_path"])
            self.assertEqual(
                [entry["path"] for entry in payload["entries"]],
                ["root", "root/a.txt", "root/nested", "root/nested/b.txt"],
            )
            self.assertEqual(payload["payload_ranges"], [
                {"path": "root/a.txt", "size": 1, "start_chunk": 0, "chunk_count": 1},
                {"path": "root/nested/b.txt", "size": 2, "start_chunk": 1, "chunk_count": 1},
            ])

    def test_archive_plan_cli_can_write_metadata_only_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            output = Path(temp_dir) / "reports" / "plan.json"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--output",
                    str(output),
                ])

            self.assertEqual(exit_code, 0)
            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(stdout_payload, file_payload)
            self.assertEqual(file_payload["output_path"], str(output))
            self.assertEqual(file_payload["payload_ranges"], [
                {"path": "root/a.txt", "size": 3, "start_chunk": 0, "chunk_count": 2},
            ])


if __name__ == "__main__":
    unittest.main()
