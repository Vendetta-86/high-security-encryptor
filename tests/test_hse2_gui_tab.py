"""Tests for the reusable HSE2 experimental GUI tab component."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from high_security_encryptor.hse2_gui_tab import (
    HEADER_BACKUP_RECOVERY_WARNING,
    HSE2ExperimentalTab,
    HSE2GuiTabState,
    build_hse2_command_from_tab_state,
    dpapi_warning_for_state,
    hse2_gui_action_display_label,
    hse2_gui_action_display_values,
    hse2_gui_action_key_from_display,
    hse2_kdf_profile_display_values,
    hse2_kdf_profile_key_from_display,
    should_show_paranoid_profile_warning,
    visible_hse2_gui_field_keys,
)


class HSE2GuiTabTests(unittest.TestCase):
    def test_run_selected_action_reports_plan_validation_errors(self) -> None:
        class Variable:
            def __init__(self, value: str) -> None:
                self.value = value

            def set(self, value: str) -> None:
                self.value = value

        def build_invalid_plan() -> None:
            raise ValueError("永久禁用访问确认短语不匹配。")

        tab = SimpleNamespace(
            _confirm_destructive_action=lambda: True,
            build_plan=build_invalid_plan,
            _run_command=lambda _plan: self.fail("runner must not run when plan validation fails"),
            archive_password=Variable("secret"),
            archive_password_confirmation=Variable("secret"),
        )

        with patch("high_security_encryptor.hse2_gui_tab.messagebox.showerror") as showerror:
            HSE2ExperimentalTab.run_selected_action(tab)

        showerror.assert_called_once_with("输入无效", "永久禁用访问确认短语不匹配。")
        self.assertEqual(tab.archive_password.value, "")
        self.assertEqual(tab.archive_password_confirmation.value, "")

    def test_header_backup_warning_says_it_cannot_replace_unlock_factors(self) -> None:
        self.assertIn("不能恢复或替代", HEADER_BACKUP_RECOVERY_WARNING)
        self.assertIn("密码、keyfile 或 DPAPI", HEADER_BACKUP_RECOVERY_WARNING)
        self.assertIn("创建归档后立即导出", HEADER_BACKUP_RECOVERY_WARNING)

    def test_archive_create_warnings_cover_paranoid_factor_and_dpapi_scope(self) -> None:
        self.assertTrue(should_show_paranoid_profile_warning("archive-create", "paranoid", "password.txt"))
        self.assertTrue(should_show_paranoid_profile_warning("archive-create", "paranoid", "", has_typed_password=True))
        self.assertFalse(should_show_paranoid_profile_warning("archive-create", "hardened", "password.txt"))
        warning = dpapi_warning_for_state("archive-create", "current_user", True)
        self.assertIsNotNone(warning)
        self.assertIn("Keep an independent password or keyfile wrapper", warning)

    def test_dpapi_warnings_cover_machine_scope_and_wrapper_portability(self) -> None:
        machine_warning = dpapi_warning_for_state("dpapi-protect", "local_machine", False)
        self.assertIsNotNone(machine_warning)
        self.assertIn("任何用户都可能解密", machine_warning)
        self.assertIsNone(dpapi_warning_for_state("dpapi-protect", "current_user", False))

        wrapper_warning = dpapi_warning_for_state("wrapper-add", "current_user", True)
        self.assertIsNotNone(wrapper_warning)
        self.assertIn("Keep an independent password or keyfile wrapper", wrapper_warning)
        self.assertIsNone(dpapi_warning_for_state("wrapper-add", "current_user", False))

    def test_build_encrypt_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(HSE2GuiTabState(action="encrypt-config", config_path="encrypt.json"))
        self.assertEqual(argv, ["hse2-encrypt-config", "--config", "encrypt.json"])

    def test_build_archive_create_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(
                action="archive-create",
                root_path="source",
                output_path="archive.hse2",
                keyfile_path="recovery.key",
                archive_format_version="3",
                archive_chunk_size=4096,
                archive_pad_last_chunk=True,
                archive_validate_after_create=True,
            )
        )
        self.assertEqual(
            argv,
            [
                "hse2-create", "--root", "source", "--output", "archive.hse2",
                "--format-version", "3", "--chunk-size", "4096", "--keyfile", "recovery.key",
                "--pad-last-chunk", "--validate-after-create",
            ],
        )

    def test_build_archive_open_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(
                action="archive-open", input_path="archive.hse2", output_path="restored",
                keyfile_path="recovery.key", force=True, archive_validate_before_open=True,
            )
        )
        self.assertEqual(
            argv,
            [
                "hse2-open", "--input", "archive.hse2", "--output-dir", "restored",
                "--keyfile", "recovery.key", "--overwrite", "--validate-before-open",
            ],
        )

    def test_build_archive_validate_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(action="archive-validate", input_path="archive.hse2", keyfile_path="recovery.key")
        )
        self.assertEqual(argv, ["hse2-archive-validate", "--input", "archive.hse2", "--keyfile", "recovery.key"])

    def test_build_validate_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(
                action="validate",
                config_path="validate.json",
                validation_report_output="report.json",
                validation_summary_only=True,
                validation_exit_code_on_failure=True,
            )
        )
        self.assertEqual(
            argv,
            [
                "hse2-validate",
                "--config",
                "validate.json",
                "--output",
                "report.json",
                "--summary-only",
                "--exit-code-on-failure",
            ],
        )

    def test_build_inspect_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(HSE2GuiTabState(action="inspect", input_path="archive.hse2"))
        self.assertEqual(argv, ["hse2-inspect", "--input", "archive.hse2"])

    def test_build_inspect_command_from_localized_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(HSE2GuiTabState(action="检查 HSE2 元数据", input_path="archive.hse2"))
        self.assertEqual(argv, ["hse2-inspect", "--input", "archive.hse2"])

    def test_build_generate_keyfile_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(action="generate-keyfile", output_path="wrapper.key", size=64, force=True)
        )
        self.assertEqual(argv, ["generate-keyfile", "--output", "wrapper.key", "--size", "64", "--force"])

    def test_build_dpapi_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(
                action="dpapi-protect",
                input_path="wrapper.key",
                output_path="wrapper.dpapi",
                scope="local_machine",
                force=True,
            )
        )
        self.assertEqual(
            argv,
            [
                "dpapi-protect",
                "--input",
                "wrapper.key",
                "--output",
                "wrapper.dpapi",
                "--scope",
                "local_machine",
                "--force",
            ],
        )

    def test_action_display_values_are_localized(self) -> None:
        values = hse2_gui_action_display_values()
        self.assertIn("检查 HSE2 元数据", values)
        self.assertIn("HSE2 加密配置", values)
        self.assertNotIn("inspect", values)
        self.assertNotIn("encrypt-config", values)

    def test_action_display_label_maps_internal_action(self) -> None:
        self.assertEqual(hse2_gui_action_display_label("inspect"), "检查 HSE2 元数据")

    def test_action_key_from_display_accepts_localized_label(self) -> None:
        self.assertEqual(hse2_gui_action_key_from_display("检查 HSE2 元数据"), "inspect")

    def test_action_key_from_display_keeps_internal_action_for_compatibility(self) -> None:
        self.assertEqual(hse2_gui_action_key_from_display("inspect"), "inspect")

    def test_visible_fields_for_config_actions(self) -> None:
        self.assertEqual(visible_hse2_gui_field_keys("encrypt-config"), frozenset({"config_path"}))
        self.assertEqual(visible_hse2_gui_field_keys("decrypt-config"), frozenset({"config_path"}))
        self.assertEqual(visible_hse2_gui_field_keys("rotate-keyfile"), frozenset({"config_path"}))

    def test_archive_create_shows_all_archive_and_factor_controls(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("archive-create"),
            frozenset({
                "root_path", "output_path", "password_file", "keyfile_path", "archive_profile",
                "archive_format_version", "archive_chunk_size", "new_wrapper_dpapi", "force",
                "archive_pad_last_chunk", "archive_validate_after_create", "paranoid_warning", "dpapi_warning",
                "archive_password", "archive_password_confirmation",
            }),
        )

    def test_archive_open_shows_restore_and_unlock_controls(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("archive-open"),
            frozenset({
                "input_path", "output_path", "password_file", "keyfile_path", "allow_dpapi", "force",
                "archive_validate_before_open", "dpapi_warning", "archive_password",
            }),
        )

    def test_v4_actions_expose_only_their_required_controls(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("v4-create"),
            frozenset({"output_path", "primary_file_spec", "secondary_file_spec", "capacity_records",
                       "primary_password", "primary_password_confirmation", "secondary_password",
                       "secondary_password_confirmation", "force", "v4_warning"}),
        )
        self.assertEqual(visible_hse2_gui_field_keys("v4-open"),
                         frozenset({"input_path", "output_path", "archive_password", "v4_warning"}))

    def test_archive_validate_shows_input_and_unlock_controls(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("archive-validate"),
            frozenset({"input_path", "password_file", "keyfile_path", "allow_dpapi", "dpapi_warning", "archive_password"}),
        )

    def test_visible_fields_for_validate_action(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("validate"),
            frozenset(
                {
                    "config_path",
                    "validation_report_output",
                    "validation_summary_only",
                    "validation_exit_code_on_failure",
                }
            ),
        )

    def test_visible_fields_for_inspect_action(self) -> None:
        self.assertEqual(visible_hse2_gui_field_keys("inspect"), frozenset({"input_path"}))

    def test_header_backup_export_shows_input_output_and_overwrite(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("header-backup-export"),
            frozenset({"input_path", "output_path", "force"}),
        )
        self.assertEqual(
            build_hse2_command_from_tab_state(
                HSE2GuiTabState(
                    action="header-backup-export",
                    input_path="archive.hse2",
                    output_path="archive.hse2.header",
                )
            ),
            ["hse2-header-backup", "export", "--input", "archive.hse2", "--output", "archive.hse2.header"],
        )

    def test_visible_fields_accepts_localized_inspect_label(self) -> None:
        self.assertEqual(visible_hse2_gui_field_keys("检查 HSE2 元数据"), frozenset({"input_path"}))

    def test_visible_fields_for_keyfile_generation(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("generate-keyfile"),
            frozenset({"output_path", "size", "force", "paranoid_warning"}),
        )

    def test_visible_fields_for_dpapi_protect(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("dpapi-protect"),
            frozenset({"input_path", "output_path", "scope", "force", "dpapi_warning"}),
        )

    def test_visible_fields_for_wrapper_remove(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("wrapper-remove"),
            frozenset(
                {"input_path", "output_path", "wrapper_id", "password_file", "keyfile_path", "allow_dpapi", "force", "paranoid_warning"}
            ),
        )

    def test_visible_fields_for_access_destroy(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("access-destroy"),
            frozenset({"input_path", "output_path", "password_file", "keyfile_path", "allow_dpapi", "access_confirmation_phrase", "danger_text", "force", "paranoid_warning"}),
        )

    def test_wrapper_rewrap_uses_chinese_kdf_profiles_and_paranoid_warning(self) -> None:
        self.assertEqual(hse2_kdf_profile_display_values(), ("兼容旧设备", "推荐高安全", "极高安全"))
        self.assertEqual(hse2_kdf_profile_key_from_display("极高安全"), "paranoid")
        self.assertEqual(hse2_kdf_profile_key_from_display("hardened"), "hardened")
        self.assertTrue(should_show_paranoid_profile_warning("wrapper-rewrap", "paranoid", "new-password.txt"))
        self.assertTrue(should_show_paranoid_profile_warning("wrapper-add", "paranoid", "new-password.txt"))
        self.assertFalse(should_show_paranoid_profile_warning("wrapper-rewrap", "paranoid", ""))
        self.assertFalse(should_show_paranoid_profile_warning("wrapper-rewrap", "hardened", "new-password.txt"))

    def test_wrapper_add_visibility_and_state_use_profiled_factors(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("wrapper-add"),
            frozenset({
                "input_path", "output_path", "wrapper_id", "password_file", "keyfile_path", "new_password_file",
                "new_keyfile_path", "new_kdf_profile", "new_label", "allow_dpapi", "new_wrapper_dpapi", "force",
                "paranoid_warning", "dpapi_warning",
            }),
        )
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(
                action="wrapper-add",
                input_path="source.hse2",
                output_path="added.hse2",
                wrapper_id="recovery",
                password_file="unlock.txt",
                new_password_file="recovery.txt",
                new_kdf_profile="极高安全",
            )
        )
        self.assertEqual(argv[1], "add")
        self.assertEqual(argv[argv.index("--new-profile") + 1], "paranoid")

    def test_wrapper_rewrap_tab_state_maps_localized_profile_to_cli(self) -> None:
        argv = build_hse2_command_from_tab_state(
            HSE2GuiTabState(
                action="wrapper-rewrap",
                input_path="source.hse2",
                output_path="rotated.hse2",
                wrapper_id="primary",
                password_file="old.txt",
                new_password_file="new.txt",
                new_kdf_profile="极高安全",
            )
        )
        self.assertIn("--new-profile", argv)
        self.assertEqual(argv[argv.index("--new-profile") + 1], "paranoid")

    def test_visible_fields_for_wrapper_rewrap_include_profile_warning(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("wrapper-rewrap"),
            frozenset({
                "input_path", "output_path", "wrapper_id", "new_wrapper_id", "password_file", "keyfile_path",
                "new_password_file", "new_keyfile_path", "new_kdf_profile", "new_label", "allow_dpapi",
                "new_wrapper_dpapi", "force", "paranoid_warning",
                "dpapi_warning",
            }),
        )

    def test_unknown_action_visibility_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            visible_hse2_gui_field_keys("unknown")

    def test_unknown_action_display_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            hse2_gui_action_key_from_display("unknown")

    def test_missing_required_field_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_command_from_tab_state(HSE2GuiTabState(action="encrypt-config"))

    def test_typed_password_plan_keeps_secret_separate_from_argv_and_repr(self) -> None:
        from high_security_encryptor.hse2_gui_tab import build_hse2_plan_from_tab_state

        secret = "tab-secret-value"
        plan = build_hse2_plan_from_tab_state(
            HSE2GuiTabState(
                action="archive-create", root_path="source", output_path="archive.hse2",
                archive_password=secret, archive_password_confirmation=secret,
            )
        )
        self.assertEqual(plan.secret_input, secret)
        self.assertNotIn(secret, " ".join(plan.argv))
        self.assertNotIn(secret, repr(plan))
        self.assertNotIn(secret, repr(HSE2GuiTabState(
            action="archive-create", archive_password=secret, archive_password_confirmation=secret,
        )))

    def test_prepare_archive_open_carries_path_and_only_enables_dpapi_when_needed(self) -> None:
        class Variable:
            def __init__(self, value: str = "stale") -> None:
                self.value = value

            def set(self, value: str) -> None:
                self.value = value

        tab = SimpleNamespace(
            action=Variable(), input_path=Variable(), output_path=Variable("old-output"),
            allow_dpapi=Variable("old-dpapi"), archive_password=Variable("old-password"),
            archive_password_confirmation=Variable("old-confirmation"),
        )
        HSE2ExperimentalTab.prepare_archive_open(tab, "new-archive.hse2", "dpapi")
        self.assertEqual(tab.action.value, "archive-open")
        self.assertEqual(tab.input_path.value, "new-archive.hse2")
        self.assertEqual(tab.output_path.value, "")
        self.assertTrue(tab.allow_dpapi.value)
        self.assertEqual(tab.archive_password.value, "")
        self.assertEqual(tab.archive_password_confirmation.value, "")

        HSE2ExperimentalTab.prepare_archive_open(tab, "keyfile-archive.hse2", "keyfile")
        self.assertFalse(tab.allow_dpapi.value)


if __name__ == "__main__":
    unittest.main()
