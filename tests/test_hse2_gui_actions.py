"""Tests for GUI-facing HSE2 command builders."""

from __future__ import annotations

import unittest

from high_security_encryptor.hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE
from high_security_encryptor.hse2_gui_actions import build_hse2_gui_command


class HSE2GuiActionTests(unittest.TestCase):
    def test_encrypt_config_action(self) -> None:
        plan = build_hse2_gui_command(action="encrypt-config", config_path="encrypt.json")
        self.assertEqual(plan.argv, ("hse2-encrypt-config", "--config", "encrypt.json"))
        self.assertTrue(plan.experimental)

    def test_decrypt_config_action(self) -> None:
        plan = build_hse2_gui_command(action="decrypt-config", config_path="decrypt.json")
        self.assertEqual(plan.argv, ("hse2-decrypt-config", "--config", "decrypt.json"))

    def test_archive_create_action_uses_secret_files_and_explicit_archive_options(self) -> None:
        plan = build_hse2_gui_command(
            action="archive-create",
            root_path="source",
            output_path="archive.hse2",
            keyfile_path="recovery.key",
            archive_format_version=3,
            archive_chunk_size=4096,
            archive_pad_last_chunk=True,
            archive_validate_after_create=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-create", "--root", "source", "--output", "archive.hse2",
                "--format-version", "3", "--chunk-size", "4096", "--keyfile", "recovery.key",
                "--pad-last-chunk", "--validate-after-create",
            ),
        )

    def test_archive_create_rejects_password_only_paranoid_profile(self) -> None:
        with self.assertRaisesRegex(ValueError, "需要同时提供 keyfile"):
            build_hse2_gui_command(
                action="archive-create",
                root_path="source",
                output_path="archive.hse2",
                password_file="secret.txt",
                archive_profile="paranoid",
            )

    def test_archive_open_action_keeps_factors_out_of_argv_and_requires_unlock_method(self) -> None:
        plan = build_hse2_gui_command(
            action="archive-open", input_path="archive.hse2", output_path="restored",
            password_file="secret.txt", keyfile_path="recovery.key", allow_dpapi=True, force=True,
            archive_validate_before_open=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-open", "--input", "archive.hse2", "--output-dir", "restored",
                "--password-file", "secret.txt", "--keyfile", "recovery.key", "--dpapi", "--overwrite",
                "--validate-before-open",
            ),
        )
        with self.assertRaisesRegex(ValueError, "请选择密码文件"):
            build_hse2_gui_command(action="archive-open", input_path="archive.hse2", output_path="restored")

    def test_archive_validate_action_requires_unlock_material(self) -> None:
        plan = build_hse2_gui_command(
            action="archive-validate", input_path="archive.hse2", keyfile_path="recovery.key"
        )
        self.assertEqual(plan.argv, ("hse2-archive-validate", "--input", "archive.hse2", "--keyfile", "recovery.key"))
        with self.assertRaisesRegex(ValueError, "请选择密码文件"):
            build_hse2_gui_command(action="archive-validate", input_path="archive.hse2")

    def test_validate_action_with_options(self) -> None:
        plan = build_hse2_gui_command(
            action="validate",
            config_path="validate.json",
            validation_report_output="report.json",
            validation_summary_only=True,
            validation_exit_code_on_failure=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-validate",
                "--config",
                "validate.json",
                "--output",
                "report.json",
                "--summary-only",
                "--exit-code-on-failure",
            ),
        )

    def test_inspect_action(self) -> None:
        plan = build_hse2_gui_command(action="inspect", input_path="archive.hse2")
        self.assertEqual(plan.argv, ("hse2-inspect", "--input", "archive.hse2"))

    def test_header_backup_export_action(self) -> None:
        plan = build_hse2_gui_command(
            action="header-backup-export",
            input_path="archive.hse2",
            output_path="archive.hse2.header",
            force=True,
        )
        self.assertEqual(
            plan.argv,
            ("hse2-header-backup", "export", "--input", "archive.hse2", "--output", "archive.hse2.header", "--overwrite"),
        )

    def test_rotate_keyfile_action(self) -> None:
        plan = build_hse2_gui_command(action="rotate-keyfile", config_path="rotate.json")
        self.assertEqual(plan.argv, ("hse2-rotate-keyfile", "--config", "rotate.json"))

    def test_generate_keyfile_action(self) -> None:
        plan = build_hse2_gui_command(action="generate-keyfile", output_path="wrapper.key", size=64, force=True)
        self.assertEqual(plan.argv, ("generate-keyfile", "--output", "wrapper.key", "--size", "64", "--force"))

    def test_dpapi_protect_action(self) -> None:
        plan = build_hse2_gui_command(
            action="dpapi-protect",
            input_path="wrapper.key",
            output_path="wrapper.dpapi",
            scope="local_machine",
            force=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "dpapi-protect",
                "--input",
                "wrapper.key",
                "--output",
                "wrapper.dpapi",
                "--scope",
                "local_machine",
                "--force",
            ),
        )

    def test_wrapper_list_action(self) -> None:
        plan = build_hse2_gui_command(action="wrapper-list", input_path="archive.hse2")
        self.assertEqual(plan.argv, ("hse2-wrapper", "list", "--input", "archive.hse2"))

    def test_wrapper_remove_action_with_unlock_options(self) -> None:
        factor_word = "pass" + "word"
        factor_file_flag = "--" + factor_word + "-file"
        factor_file_name = factor_word + ".txt"
        plan = build_hse2_gui_command(
            action="wrapper-remove",
            input_path="archive.hse2",
            output_path="removed.hse2",
            wrapper_id=factor_word + "-2",
            password_file=factor_file_name,
            keyfile_path="archive.key",
            allow_dpapi=True,
            force=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-wrapper",
                "remove",
                "--input",
                "archive.hse2",
                "--output",
                "removed.hse2",
                "--wrapper-id",
                factor_word + "-2",
                factor_file_flag,
                factor_file_name,
                "--keyfile",
                "archive.key",
                "--dpapi",
                "--overwrite",
            ),
        )

    def test_access_destroy_action_requires_exact_phrase(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(
                action="access-destroy",
                input_path="archive.hse2",
                output_path="disabled.hse2",
                access_confirmation_phrase="wrong phrase",
            )

    def test_access_destroy_action(self) -> None:
        plan = build_hse2_gui_command(
            action="access-destroy",
            input_path="archive.hse2",
            output_path="disabled.hse2",
            access_confirmation_phrase=DESTROY_ACCESS_CONFIRMATION_PHRASE,
            password_file="unlock.txt",
            keyfile_path="unlock.key",
            allow_dpapi=True,
            force=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-access", "destroy", "--input", "archive.hse2", "--output", "disabled.hse2",
                "--confirm", DESTROY_ACCESS_CONFIRMATION_PHRASE, "--password-file", "unlock.txt",
                "--keyfile", "unlock.key", "--dpapi", "--overwrite",
            ),
        )

    def test_wrapper_rewrap_action_builds_localized_profiled_cli_command(self) -> None:
        plan = build_hse2_gui_command(
            action="wrapper-rewrap",
            input_path="archive.hse2",
            output_path="rotated.hse2",
            wrapper_id="old-id",
            new_wrapper_id="new-id",
            password_file="old-password.txt",
            keyfile_path="old.key",
            new_password_file="new-password.txt",
            new_keyfile_path="new.key",
            new_profile_name="paranoid",
            new_label="recovery",
            force=True,
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-wrapper", "rewrap", "--input", "archive.hse2", "--output", "rotated.hse2",
                "--wrapper-id", "old-id", "--new-wrapper-id", "new-id",
                "--new-password-file", "new-password.txt", "--new-keyfile", "new.key",
                "--new-profile", "paranoid", "--new-label", "recovery",
                "--password-file", "old-password.txt", "--keyfile", "old.key", "--overwrite",
            ),
        )

    def test_wrapper_add_action_builds_profiled_cli_command(self) -> None:
        plan = build_hse2_gui_command(
            action="wrapper-add",
            input_path="archive.hse2",
            output_path="with-recovery.hse2",
            wrapper_id="recovery-password",
            password_file="unlock.txt",
            new_password_file="recovery.txt",
            new_profile_name="hardened",
            new_label="recovery",
        )
        self.assertEqual(
            plan.argv,
            (
                "hse2-wrapper", "add", "--input", "archive.hse2", "--output", "with-recovery.hse2",
                "--wrapper-id", "recovery-password", "--new-password-file", "recovery.txt",
                "--new-profile", "hardened", "--new-label", "recovery", "--password-file", "unlock.txt",
            ),
        )
    def test_missing_required_config_path_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(action="encrypt-config", config_path="")

    def test_missing_required_inspect_input_path_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(action="inspect", input_path="")

    def test_invalid_action_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(action="unknown")

    def test_too_small_keyfile_size_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(action="generate-keyfile", output_path="wrapper.key", size=15)

    def test_invalid_dpapi_scope_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(
                action="dpapi-protect",
                input_path="wrapper.key",
                output_path="wrapper.dpapi",
                scope="bad-scope",
            )

    def test_wrapper_remove_requires_wrapper_id(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(
                action="wrapper-remove",
                input_path="archive.hse2",
                output_path="removed.hse2",
                wrapper_id="",
            )


if __name__ == "__main__":
    unittest.main()
