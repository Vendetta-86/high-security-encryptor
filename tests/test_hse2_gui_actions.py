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

    def test_typed_archive_password_is_kept_out_of_argv_and_repr(self) -> None:
        secret = "not-in-argv-or-repr"
        plan = build_hse2_gui_command(
            action="archive-create", root_path="source", output_path="archive.hse2",
            archive_password=secret, archive_password_confirmation=secret,
        )
        self.assertEqual(plan.secret_input, secret)
        self.assertNotIn(secret, " ".join(plan.argv))
        self.assertNotIn(secret, repr(plan))

    def test_v4_gui_creation_keeps_both_passwords_out_of_argv_and_repr(self) -> None:
        secret0, secret1 = "primary-secret", "secondary-secret"
        plan = build_hse2_gui_command(
            action="v4-create", output_path="archive.v4",
            primary_file_spec="a.txt=C:/source/a.txt", secondary_file_spec="b.txt=C:/source/b.txt",
            primary_password=secret0, primary_password_confirmation=secret0,
            secondary_password=secret1, secondary_password_confirmation=secret1,
        )
        self.assertEqual(plan.secret_inputs, (secret0, secret0, secret1, secret1))
        self.assertNotIn(secret0, repr(plan) + " ".join(plan.argv))
        self.assertNotIn(secret1, repr(plan) + " ".join(plan.argv))
        self.assertEqual(plan.argv[0:2], ("hse2", "v4-create"))

    def test_v4_gui_creation_requires_distinct_passwords_and_bounded_capacity(self) -> None:
        kwargs = dict(
            action="v4-create", output_path="archive.v4",
            primary_file_spec="a.txt=a.txt", secondary_file_spec="b.txt=b.txt",
            primary_password="same", primary_password_confirmation="same",
            secondary_password="same", secondary_password_confirmation="same",
        )
        with self.assertRaisesRegex(ValueError, "必须不同"):
            build_hse2_gui_command(**kwargs)
        kwargs["secondary_password"] = kwargs["secondary_password_confirmation"] = "different"
        kwargs["capacity_records"] = 3
        with self.assertRaisesRegex(ValueError, "偶数"):
            build_hse2_gui_command(**kwargs)

    def test_v5_gui_actions_keep_passwords_out_of_argv(self) -> None:
        create = build_hse2_gui_command(
            action="v5-create", output_path="new.hse2", primary_file_spec="a.txt=a.txt",
            secondary_file_spec="b.txt=b.txt", primary_password="GUI-PASSWORD-ALPHA", primary_password_confirmation="GUI-PASSWORD-ALPHA",
            secondary_password="GUI-PASSWORD-BETA", secondary_password_confirmation="GUI-PASSWORD-BETA",
        )
        self.assertEqual(create.argv[:2], ("hse2", "v5-create"))
        self.assertEqual(create.secret_inputs, ("GUI-PASSWORD-ALPHA", "GUI-PASSWORD-ALPHA", "GUI-PASSWORD-BETA", "GUI-PASSWORD-BETA"))
        self.assertNotIn("GUI-PASSWORD-ALPHA", repr(create) + " ".join(create.argv))
        self.assertNotIn("GUI-PASSWORD-BETA", repr(create) + " ".join(create.argv))

        opened = build_hse2_gui_command(
            action="v5-open", input_path="archive.hse2", output_path="restored", archive_password="view-pass",
        )
        verified = build_hse2_gui_command(
            action="v5-verify", input_path="archive.hse2", archive_password="view-pass",
        )
        previewed = build_hse2_gui_command(
            action="v5-preview", input_path="archive.hse2", output_path="restored", archive_password="view-pass",
        )
        replaced = build_hse2_gui_command(
            action="v5-replace", input_path="archive.hse2", output_path="updated.hse2",
            archive_password="view-pass",
        )
        compacted = build_hse2_gui_command(
            action="v5-compact", input_path="archive.hse2", output_path="compact.hse2",
            primary_password="first", secondary_password="second",
        )
        exported = build_hse2_gui_command(
            action="v4-to-v5", input_path="old-v4.hse2", output_path="new-v5.hse2",
            primary_password="first", secondary_password="second",
        )
        self.assertEqual(opened.secret_inputs, ("view-pass",))
        self.assertEqual(verified.argv, ("hse2", "v5-verify", "--input", "archive.hse2"))
        self.assertEqual(previewed.argv, (
            "hse2", "v5-preview", "--input", "archive.hse2", "--output-dir", "restored",
        ))
        self.assertEqual(verified.secret_inputs, ("view-pass",))
        self.assertEqual(previewed.secret_inputs, ("view-pass",))
        for plan in (verified, previewed):
            self.assertNotIn("view-pass", repr(plan) + " ".join(plan.argv))
        self.assertEqual(replaced.secret_inputs, ("view-pass",))
        self.assertEqual(compacted.secret_inputs, ("first", "second"))
        self.assertEqual(exported.secret_inputs, ("first", "second"))

    def test_v5_creation_requires_distinct_confirmed_view_passwords(self) -> None:
        kwargs = dict(
            action="v5-create", output_path="new.hse2", primary_file_spec="a=a", secondary_file_spec="b=b",
            primary_password="first", primary_password_confirmation="first",
            secondary_password="first", secondary_password_confirmation="first",
        )
        with self.assertRaisesRegex(ValueError, "必须不同"):
            build_hse2_gui_command(**kwargs)
        kwargs["secondary_password"] = kwargs["secondary_password_confirmation"] = "second"
        kwargs["primary_password_confirmation"] = "mismatch"
        with self.assertRaisesRegex(ValueError, "确认"):
            build_hse2_gui_command(**kwargs)

    def test_typed_archive_password_requires_matching_confirmation(self) -> None:
        with self.assertRaisesRegex(ValueError, "两次输入"):
            build_hse2_gui_command(
                action="archive-create", root_path="source", output_path="archive.hse2",
                archive_password="first", archive_password_confirmation="second",
            )

    def test_typed_archive_password_conflicts_with_password_file_and_dpapi(self) -> None:
        with self.assertRaisesRegex(ValueError, "密码输入框或密码文件"):
            build_hse2_gui_command(
                action="archive-create", root_path="source", output_path="archive.hse2",
                password_file="password.txt", archive_password="secret",
                archive_password_confirmation="secret",
            )
        with self.assertRaisesRegex(ValueError, "DPAPI wrapper"):
            build_hse2_gui_command(
                action="archive-create", root_path="source", output_path="archive.hse2",
                new_wrapper_dpapi=True, archive_password="secret",
                archive_password_confirmation="secret",
            )

    def test_typed_paranoid_password_requires_keyfile(self) -> None:
        with self.assertRaisesRegex(ValueError, "需要同时提供 keyfile"):
            build_hse2_gui_command(
                action="archive-create", root_path="source", output_path="archive.hse2",
                archive_profile="paranoid", archive_password="secret",
                archive_password_confirmation="secret",
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

    def test_archive_open_accepts_typed_password_without_putting_it_in_argv(self) -> None:
        password = "typed-open-password"
        plan = build_hse2_gui_command(
            action="archive-open", input_path="archive.hse2", output_path="restored",
            archive_password=password,
        )
        self.assertEqual(plan.secret_input, password)
        self.assertNotIn(password, " ".join(plan.argv))
        with self.assertRaisesRegex(ValueError, "密码输入框或密码文件"):
            build_hse2_gui_command(
                action="archive-open", input_path="archive.hse2", output_path="restored",
                password_file="password.txt", archive_password=password,
            )

    def test_archive_validate_action_requires_unlock_material(self) -> None:
        plan = build_hse2_gui_command(
            action="archive-validate", input_path="archive.hse2", keyfile_path="recovery.key"
        )
        self.assertEqual(plan.argv, ("hse2-archive-validate", "--input", "archive.hse2", "--keyfile", "recovery.key"))
        with self.assertRaisesRegex(ValueError, "请选择密码文件"):
            build_hse2_gui_command(action="archive-validate", input_path="archive.hse2")

    def test_archive_validate_accepts_typed_password_without_putting_it_in_argv(self) -> None:
        password = "typed-validate-password"
        plan = build_hse2_gui_command(
            action="archive-validate", input_path="archive.hse2", archive_password=password,
        )
        self.assertEqual(plan.secret_input, password)
        self.assertNotIn(password, " ".join(plan.argv))

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
