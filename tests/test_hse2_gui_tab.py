"""Tests for the reusable HSE2 experimental GUI tab component."""

from __future__ import annotations

import unittest

from high_security_encryptor.hse2_gui_tab import (
    HSE2GuiTabState,
    build_hse2_command_from_tab_state,
    hse2_gui_action_display_label,
    hse2_gui_action_display_values,
    hse2_gui_action_key_from_display,
    visible_hse2_gui_field_keys,
)


class HSE2GuiTabTests(unittest.TestCase):
    def test_build_encrypt_command_from_tab_state(self) -> None:
        argv = build_hse2_command_from_tab_state(HSE2GuiTabState(action="encrypt-config", config_path="encrypt.json"))
        self.assertEqual(argv, ["hse2-encrypt-config", "--config", "encrypt.json"])

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

    def test_visible_fields_accepts_localized_inspect_label(self) -> None:
        self.assertEqual(visible_hse2_gui_field_keys("检查 HSE2 元数据"), frozenset({"input_path"}))

    def test_visible_fields_for_keyfile_generation(self) -> None:
        self.assertEqual(visible_hse2_gui_field_keys("generate-keyfile"), frozenset({"output_path", "size", "force"}))

    def test_visible_fields_for_dpapi_protect(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("dpapi-protect"),
            frozenset({"input_path", "output_path", "scope", "force"}),
        )

    def test_visible_fields_for_wrapper_remove(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("wrapper-remove"),
            frozenset(
                {"input_path", "output_path", "wrapper_id", "password_file", "keyfile_path", "allow_dpapi", "force"}
            ),
        )

    def test_visible_fields_for_access_destroy(self) -> None:
        self.assertEqual(
            visible_hse2_gui_field_keys("access-destroy"),
            frozenset({"input_path", "output_path", "access_confirmation_phrase", "danger_text", "force"}),
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


if __name__ == "__main__":
    unittest.main()
