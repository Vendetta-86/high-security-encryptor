"""Tests for GUI-facing HSE2 command builders."""

from __future__ import annotations

import unittest

from high_security_encryptor.hse2_gui_actions import build_hse2_gui_command


class HSE2GuiActionTests(unittest.TestCase):
    def test_encrypt_config_action(self) -> None:
        plan = build_hse2_gui_command(action="encrypt-config", config_path="encrypt.json")
        self.assertEqual(plan.argv, ("hse2-encrypt-config", "--config", "encrypt.json"))
        self.assertTrue(plan.experimental)

    def test_decrypt_config_action(self) -> None:
        plan = build_hse2_gui_command(action="decrypt-config", config_path="decrypt.json")
        self.assertEqual(plan.argv, ("hse2-decrypt-config", "--config", "decrypt.json"))

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

    def test_missing_required_config_path_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_hse2_gui_command(action="encrypt-config", config_path="")

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


if __name__ == "__main__":
    unittest.main()
