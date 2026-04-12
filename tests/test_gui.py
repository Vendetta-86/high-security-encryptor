from pathlib import Path
import json
import tempfile
import unittest

from high_security_encryptor.gui import (
    build_batch_args,
    build_init_example_args,
    build_validate_config_args,
    config_uses_prompt_provider,
    main,
)


class GuiTests(unittest.TestCase):
    def test_gui_smoke_test_does_not_open_window(self) -> None:
        """The GUI smoke path should validate imports without starting mainloop."""

        self.assertEqual(main(["--smoke-test"]), 0)

    def test_build_validate_config_args(self) -> None:
        """GUI validation controls should map to the existing CLI arguments."""

        args = build_validate_config_args(
            kind="decrypt",
            config_path="config.json",
            strict=True,
            report=True,
            report_format="text",
            output_path="report.txt",
            summary_only=True,
            exit_code_on_issues=True,
            warnings_as_errors=True,
        )

        self.assertEqual(
            args,
            [
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                "config.json",
                "--strict",
                "--report",
                "--format",
                "text",
                "--summary-only",
                "--output",
                "report.txt",
                "--exit-code-on-issues",
                "--warnings-as-errors",
            ],
        )

    def test_build_batch_args(self) -> None:
        """Batch GUI actions should preserve the CLI command contract."""

        self.assertEqual(
            build_batch_args(command="encrypt-batch", config_path="encrypt.json"),
            ["encrypt-batch", "--config", "encrypt.json"],
        )

    def test_build_init_example_args(self) -> None:
        """Example generation controls should map to init-example."""

        self.assertEqual(
            build_init_example_args(
                mode="no-password-tables",
                kind="decrypt",
                output_path="decrypt.json",
            ),
            [
                "init-example",
                "--mode",
                "no-password-tables",
                "--kind",
                "decrypt",
                "--output",
                "decrypt.json",
            ],
        )

    def test_gui_input_errors_are_chinese(self) -> None:
        """GUI input validation messages should be user-facing Chinese text."""

        with self.assertRaisesRegex(ValueError, "请选择配置文件"):
            build_batch_args(command="encrypt-batch", config_path="")

    def test_config_uses_prompt_provider_finds_nested_provider(self) -> None:
        """GUI should detect prompt providers before launching batch workflows."""

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "metadata_password": {"type": "env", "name": "META"},
                        "template_passwords_by_encrypted_name": {
                            "file.hse": {"type": "prompt", "prompt": "Password: "}
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertTrue(config_uses_prompt_provider(str(config_path)))

    def test_config_uses_prompt_provider_allows_non_prompt_sources(self) -> None:
        """Non-interactive password providers should be accepted by the GUI."""

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "metadata_password": {"type": "env", "name": "META"},
                        "source_passwords": {
                            "file.txt": {"type": "file", "path": "secret.txt"}
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertFalse(config_uses_prompt_provider(str(config_path)))


if __name__ == "__main__":
    unittest.main()
