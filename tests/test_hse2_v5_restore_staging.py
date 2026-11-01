"""Cross-process ownership and stale-directory cleanup for v5 restores."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from high_security_encryptor.hse2.restore_staging import (
    _remove_stage_with_windows_retry,
    cleanup_stale_restore_stages,
)


class HSE2V5RestoreStagingTests(unittest.TestCase):
    def test_unleased_legacy_stage_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "restored"
            legacy_stage = root / ".restored.v5-restore-legacy-token"
            legacy_stage.mkdir()
            (legacy_stage / "partial.txt").write_bytes(b"legacy staging data")

            cleanup_stale_restore_stages(target)

            self.assertEqual((legacy_stage / "partial.txt").read_bytes(), b"legacy staging data")

    def test_abandoned_versioned_stage_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "restored"
            stale_stage = root / ".restored.v5-restore-lease1-dead-worker"
            stale_stage.mkdir()
            (stale_stage / "partial.txt").write_bytes(b"stale staging data")

            cleanup_stale_restore_stages(target)

            self.assertFalse(stale_stage.exists())

    def test_transient_windows_sharing_violation_retries_stale_stage_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "stale-stage"
            stage.mkdir()
            (stage / "partial.txt").write_bytes(b"stale staging data")
            sharing_violation = PermissionError("file is temporarily in use")
            sharing_violation.winerror = 32
            real_rmtree = __import__("shutil").rmtree
            attempts = 0

            def transient_rmtree(path: Path) -> None:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise sharing_violation
                real_rmtree(path)

            with patch(
                "high_security_encryptor.hse2.restore_staging.shutil.rmtree",
                side_effect=transient_rmtree,
            ) as remove:
                _remove_stage_with_windows_retry(stage)

            self.assertEqual(remove.call_count, 2)
            self.assertEqual(attempts, 2)
            self.assertFalse(stage.exists())


if __name__ == "__main__":
    unittest.main()
