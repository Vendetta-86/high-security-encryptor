import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_create_cli import main


class HSE2CreateCliEmptyFileTests(unittest.TestCase):
    def test_create_cli_dry_run_reports_empty_file_without_payload_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "empty.txt"
            root.write_bytes(b"")
            output = Path(temp_dir) / "out.hse2"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "--root",
                    str(root),
                    "--output",
                    str(output),
                    "--dry-run",
                ])

            self.assertEqual(exit_code, 0)
            self.assertFalse(output.exists())
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-create")
            self.assertTrue(payload["dry_run"])
            self.assertFalse(payload["container_written"])
            self.assertEqual(payload["file_count"], 1)
            self.assertEqual(payload["payload_chunk_count"], 0)
            self.assertEqual(payload["payload_ranges"], [
                {"path": "empty.txt", "size": 0, "start_chunk": 0, "chunk_count": 0},
            ])


if __name__ == "__main__":
    unittest.main()
