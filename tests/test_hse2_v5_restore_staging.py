"""Cross-process ownership and stale-directory cleanup for v5 restores."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2.restore_staging import cleanup_stale_restore_stages


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


if __name__ == "__main__":
    unittest.main()
