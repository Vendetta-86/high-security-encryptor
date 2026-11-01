"""Durability boundaries for staged file replacement."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from high_security_encryptor.atomic_io import atomic_output_path, flush_file


class AtomicIOTests(unittest.TestCase):
    def test_flush_file_calls_fsync_only_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "payload.bin"
            with target.open("wb") as output:
                with patch.dict(os.environ, {}, clear=True), patch("high_security_encryptor.atomic_io.os.fsync") as fsync:
                    flush_file(output)
                    fsync.assert_not_called()
                with patch.dict(os.environ, {"HSE_FSYNC": "1"}), patch(
                    "high_security_encryptor.atomic_io.os.fsync"
                ) as fsync:
                    flush_file(output)
                    fsync.assert_called_once_with(output.fileno())

    def test_failed_atomic_replace_keeps_old_target_and_removes_staging_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "archive.hse2"
            target.write_bytes(b"old authenticated container")

            with patch("high_security_encryptor.atomic_io.os.replace",
                       side_effect=OSError("injected atomic replace failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    with atomic_output_path(target) as staged:
                        staged.write_bytes(b"new container")

            self.assertEqual(target.read_bytes(), b"old authenticated container")
            self.assertEqual(list(root.glob(f".{target.name}.*.tmp")), [])

    def test_terminated_writer_never_publishes_its_staged_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "archive.hse2"
            marker = root / "staged.marker"
            target.write_bytes(b"old authenticated container")
            child_script = """
from pathlib import Path
import sys
import time
from high_security_encryptor.atomic_io import atomic_output_path

target, marker = map(Path, sys.argv[1:])
with atomic_output_path(target) as staged:
    staged.write_bytes(b"partial replacement")
    marker.write_text("ready", encoding="ascii")
    time.sleep(60)
"""
            process = subprocess.Popen(
                [sys.executable, "-c", child_script, str(target), str(marker)],
                cwd=Path.cwd(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 15
                while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not marker.exists():
                    self.fail(f"child did not reach the staged-write boundary; exit code={process.poll()}")
                process.terminate()
                process.wait(timeout=5)

                self.assertEqual(target.read_bytes(), b"old authenticated container")
                staged_files = list(root.glob(f".{target.name}.*.tmp"))
                self.assertEqual(len(staged_files), 1)
                self.assertEqual(staged_files[0].read_bytes(), b"partial replacement")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                for staged_file in root.glob(f".{target.name}.*.tmp"):
                    staged_file.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
