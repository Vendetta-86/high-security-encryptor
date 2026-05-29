import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_create_cli import main


class HSE2CreateCliTests(unittest.TestCase):
    def test_create_cli_dry_run_outputs_metadata_only_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            output = Path(temp_dir) / "out.hse2"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "--root",
                    str(root),
                    "--output",
                    str(output),
                    "--dry-run",
                    "--chunk-size",
                    "2",
                ])

            self.assertEqual(exit_code, 0)
            self.assertFalse(output.exists())
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-create")
            self.assertTrue(payload["experimental"])
            self.assertTrue(payload["dry_run"])
            self.assertFalse(payload["container_written"])
            self.assertEqual(payload["output_path"], str(output))
            self.assertEqual(payload["root_count"], 1)
            self.assertEqual(payload["file_count"], 1)
            self.assertEqual(payload["chunk_size"], 2)
            self.assertEqual(payload["payload_ranges"], [
                {"path": "root/a.txt", "size": 3, "start_chunk": 0, "chunk_count": 2},
            ])

    def test_create_cli_compact_dry_run_outputs_single_line_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            output = Path(temp_dir) / "out.hse2"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "--root",
                    str(root),
                    "--output",
                    str(output),
                    "--dry-run",
                    "--compact",
                ])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue().count("\n"), 1)
            self.assertNotIn("\n  ", stdout.getvalue())
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-create")
            self.assertTrue(payload["dry_run"])
            self.assertFalse(output.exists())

    def test_create_cli_requires_dry_run_before_container_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            output = Path(temp_dir) / "out.hse2"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main(["--root", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(output.exists())
            self.assertIn("hse2-create:", stderr.getvalue())
            self.assertIn("requires --dry-run", stderr.getvalue())

    def test_create_cli_rejects_missing_root_on_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing"
            output = Path(temp_dir) / "out.hse2"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main([
                    "--root",
                    str(missing),
                    "--output",
                    str(output),
                    "--dry-run",
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(output.exists())
            self.assertIn("hse2-create:", stderr.getvalue())
            self.assertIn("archive root does not exist", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
