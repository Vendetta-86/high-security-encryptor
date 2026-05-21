"""Tests for local brute-force throttling."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.brute_force_guard import (
    BruteForceBlockedError,
    BruteForceGuard,
    BruteForceGuardConfig,
    build_decryption_subject,
    hash_subject,
)


class BruteForceGuardTests(unittest.TestCase):
    def test_blocks_after_configured_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "guard.json"
            guard = BruteForceGuard(
                BruteForceGuardConfig(
                    max_failures=2,
                    window_seconds=60,
                    lock_seconds=300,
                    state_path=state_path,
                )
            )

            guard.check_allowed("subject-a")
            guard.record_failure("subject-a")
            guard.check_allowed("subject-a")
            guard.record_failure("subject-a")

            with self.assertRaises(BruteForceBlockedError) as raised:
                guard.check_allowed("subject-a")
            self.assertGreaterEqual(raised.exception.retry_after_seconds, 1)

    def test_success_clears_failure_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "guard.json"
            guard = BruteForceGuard(
                BruteForceGuardConfig(
                    max_failures=2,
                    window_seconds=60,
                    lock_seconds=300,
                    state_path=state_path,
                )
            )

            guard.record_failure("subject-a")
            guard.record_success("subject-a")
            guard.record_failure("subject-a")
            guard.check_allowed("subject-a")

    def test_disabled_guard_never_writes_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "guard.json"
            guard = BruteForceGuard(
                BruteForceGuardConfig(
                    enabled=False,
                    max_failures=1,
                    window_seconds=60,
                    lock_seconds=300,
                    state_path=state_path,
                )
            )

            guard.record_failure("subject-a")
            guard.check_allowed("subject-a")

            self.assertFalse(state_path.exists())

    def test_subject_uses_hashed_path_details(self) -> None:
        subject = build_decryption_subject(
            encrypted_files=["b.hse", "a.hse"],
            manifest_path="manifest.hse.json",
            template_path="template.hse.json",
            password_table_path=None,
        )

        digest = hash_subject(subject)

        self.assertEqual(len(digest), 64)
        self.assertIn("encrypted=", subject)
        self.assertNotEqual(digest, subject)


if __name__ == "__main__":
    unittest.main()
