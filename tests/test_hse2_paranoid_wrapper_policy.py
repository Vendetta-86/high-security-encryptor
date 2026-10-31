from __future__ import annotations

from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2.models import HSE2ModelError
from high_security_encryptor.hse2.workflows import create_hse2_archive, validate_hse2_wrapper_policy
from high_security_encryptor.hse2_create_cli import main as create_cli_main


class HSE2ParanoidWrapperPolicyTests(unittest.TestCase):
    def test_paranoid_password_only_policy_is_rejected(self) -> None:
        with self.assertRaisesRegex(HSE2ModelError, "require --keyfile"):
            validate_hse2_wrapper_policy(
                profile_name="paranoid", has_password=True, has_keyfile=False, use_dpapi=False
            )

    def test_paranoid_password_and_keyfile_policy_is_allowed(self) -> None:
        validate_hse2_wrapper_policy(
            profile_name="paranoid", has_password=True, has_keyfile=True, use_dpapi=False
        )

    def test_keyfile_only_and_dpapi_are_allowed_with_paranoid_profile(self) -> None:
        validate_hse2_wrapper_policy(
            profile_name="paranoid", has_password=False, has_keyfile=True, use_dpapi=False
        )
        validate_hse2_wrapper_policy(
            profile_name="paranoid", has_password=False, has_keyfile=False, use_dpapi=True
        )

    def test_archive_workflow_rejects_policy_before_touching_sources_or_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "archive.hse2"
            with self.assertRaisesRegex(HSE2ModelError, "require --keyfile"):
                create_hse2_archive(
                    roots=(Path(temp) / "missing-source",), output_path=target,
                    password="password", profile_name="paranoid",
                )
            self.assertFalse(target.exists())

    def test_create_dry_run_rejects_password_only_paranoid_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source.txt"
            root.write_text("data", encoding="utf-8")
            password_file = Path(temp) / "password.txt"
            password_file.write_text("unused by dry-run", encoding="utf-8")
            stderr = io.StringIO()
            argv = [
                "--root", str(root), "--output", str(Path(temp) / "archive.hse2"),
                "--dry-run", "--password-file", str(password_file), "--profile", "paranoid",
            ]

            with redirect_stderr(stderr):
                exit_code = create_cli_main(argv)

            self.assertEqual(exit_code, 2)
            self.assertIn("require --keyfile", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
