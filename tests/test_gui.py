from pathlib import Path
import json
import tempfile
import unittest

from high_security_encryptor.gui import (
    CONFIG_KIND_LABELS,
    GuiCommandResult,
    HELP_TEXT,
    REPORT_FORMAT_LABELS,
    SECURITY_MODE_LABELS,
    build_removable_action_summary,
    build_file_decryption_config_payload,
    build_file_decryption_config_plan,
    build_file_encryption_config_payload,
    build_file_encryption_config_plan,
    build_validation_result_guidance,
    build_batch_args,
    build_init_example_args,
    build_validate_config_args,
    choose_multi_file_workflow,
    config_uses_prompt_provider,
    describe_removable_device_status,
    describe_removable_inventory_status,
    format_size_bytes,
    make_available_path,
    main,
    run_quick_action,
    split_drop_paths,
)
from high_security_encryptor.removable_bitlocker import (
    BitLockerActionResult,
    RemovableStorageDevice,
    RemovableStorageInventory,
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
                "--output",
                "report.txt",
                "--exit-code-on-issues",
                "--warnings-as-errors",
            ],
        )

    def test_validate_config_exit_options_force_report_details(self) -> None:
        """Exit-on-warning should request a full report so GUI can show advice."""

        args = build_validate_config_args(
            kind="encrypt",
            config_path="config.json",
            strict=False,
            report=False,
            report_format="json",
            output_path="",
            summary_only=True,
            exit_code_on_issues=False,
            warnings_as_errors=True,
        )

        self.assertEqual(
            args,
            [
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                "config.json",
                "--report",
                "--format",
                "json",
                "--exit-code-on-issues",
                "--warnings-as-errors",
            ],
        )

    def test_build_validation_result_guidance_includes_issue_suggestions(self) -> None:
        """Failed validation reports should be summarized in user-facing Chinese."""

        result = GuiCommandResult(
            exit_code=2,
            stdout=json.dumps(
                {
                    "issues": [
                        {
                            "code": "missing-template-runtime-passwords",
                            "severity": "error",
                            "message": "strict mode requires template runtime password mappings",
                            "suggestion": "Provide template_passwords_by_encrypted_name.",
                        },
                        {
                            "code": "top-level-password-table-enabled",
                            "severity": "warning",
                            "message": "top-level password table generation is enabled",
                            "suggestion": "Consider hardened mode.",
                        },
                    ]
                },
                ensure_ascii=False,
            ),
            stderr="",
        )

        guidance = build_validation_result_guidance(["validate-config"], result)

        self.assertIn("检查发现的问题和处理建议", guidance)
        self.assertIn("异常信息：strict mode requires template runtime password mappings", guidance)
        self.assertIn("解决建议：Provide template_passwords_by_encrypted_name.", guidance)
        self.assertIn("警告 top-level-password-table-enabled", guidance)

    def test_help_text_explains_gui_workflows(self) -> None:
        """The explanation tab should cover all GUI workflows."""

        self.assertIn("快速使用", HELP_TEXT)
        self.assertIn("检查配置", HELP_TEXT)
        self.assertIn("文件加密", HELP_TEXT)
        self.assertIn("文件解密", HELP_TEXT)
        self.assertIn("生成配置", HELP_TEXT)
        self.assertIn("出现警告后退出检查", HELP_TEXT)

    def test_help_text_mentions_removable_storage_encryption(self) -> None:
        """The help page should describe the dedicated removable-storage tab."""

        self.assertIn("移动存储加密", HELP_TEXT)
        self.assertIn("BitLocker To Go", HELP_TEXT)

    def test_removable_storage_helpers_produce_user_facing_labels(self) -> None:
        """The removable-storage tab should show concise device and action summaries."""

        device = RemovableStorageDevice(
            disk_number=7,
            mount_point="E:",
            friendly_name="USB SSD",
            bus_type="USB",
            partition_style="GPT",
            operational_status="Online",
            volume_label="WORK",
            file_system="NTFS",
            drive_type="Removable",
            health_status="Healthy",
            size_bytes=128000000000,
            free_bytes=64000000000,
            bitlocker_volume_status="EncryptionInProgress",
            bitlocker_protection_status="On",
            bitlocker_lock_status="Unlocked",
            bitlocker_encryption_percentage=45,
            bitlocker_encryption_method="XtsAes256",
            auto_unlock_enabled=False,
        )
        inventory = RemovableStorageInventory(
            devices=(device,),
            is_admin=True,
            bitlocker_module_available=True,
            status_warning=None,
        )
        result = BitLockerActionResult(
            mount_point="E:",
            volume_status="EncryptionInProgress",
            protection_status="On",
            lock_status="Unlocked",
            encryption_percentage=45,
            encryption_method="XtsAes256",
            auto_unlock_enabled=False,
            recovery_file=Path("C:/Recovery/BitLockerRecovery-E-guid.txt"),
        )

        self.assertEqual(format_size_bytes(1024), "1.0 KB")
        self.assertEqual(describe_removable_device_status(device), "已加密")
        self.assertIn("已检测到 1 个可移动存储卷", describe_removable_inventory_status(inventory))
        summary = build_removable_action_summary("移动存储加密", result)
        self.assertIn("移动存储加密完成：E:", summary)
        self.assertIn(f"恢复信息：{Path('C:/Recovery/BitLockerRecovery-E-guid.txt')}", summary)

    def test_make_available_path_keeps_existing_output(self) -> None:
        """Quick workflows should not overwrite existing files."""

        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "sample.txt"
            target.write_text("existing", encoding="utf-8")

            self.assertEqual(make_available_path(target), Path(temp_dir) / "sample (1).txt")

    def test_split_drop_paths_handles_tkinterdnd_file_lists(self) -> None:
        """Drag-and-drop file payloads should preserve paths containing spaces."""

        self.assertEqual(
            split_drop_paths("{C:/temp/a file.txt} C:/temp/b.txt"),
            ["C:/temp/a file.txt", "C:/temp/b.txt"],
        )

    def test_choose_multi_file_workflow_keeps_quick_page_simple(self) -> None:
        """Multi-file quick entries should route to the later file tabs."""

        self.assertEqual(
            choose_multi_file_workflow(["C:/temp/a.txt", "C:/temp/b.txt"], "加密"),
            "encrypt",
        )
        self.assertEqual(
            choose_multi_file_workflow(["C:/temp/a.txt.hse", "C:/temp/b.txt.hse"], "加密"),
            "decrypt",
        )
        self.assertEqual(
            choose_multi_file_workflow(["C:/temp/a.txt.hse", "C:/temp/b.txt.hse"], "解密"),
            "decrypt",
        )

    def test_build_file_encryption_config_payload_supports_inner_passwords_and_sidecar_paths(self) -> None:
        """The file-encryption multi-file setup should generate full batch configs."""

        plan = build_file_encryption_config_plan(
            sources_text="C:/docs\nC:/plain.txt\n",
            default_password="default-pass",
            metadata_password="",
            output_dir="D:/encrypted",
            security_mode=SECURITY_MODE_LABELS["compatible"],
            source_passwords_text="C:/plain.txt=file-pass",
            folder_inner_passwords_text="C:/docs|private/secret.txt|inner-pass",
            bundle_output_path="D:/encrypted/bundle.zip.hse",
            manifest_output_path="E:/sidecars/manifest.hsm",
            password_table_output_path="E:/sidecars/passwords.hsm",
            template_output_path="E:/sidecars/template.hsm",
        )
        payload = plan.payload

        self.assertTrue(payload["package_as_bundle"])
        self.assertEqual(payload["metadata_password"], {"type": "env", "name": "HSE_GUI_METADATA_PASSWORD"})
        self.assertEqual(payload["bundle_output_path"], "D:/encrypted/bundle.zip.hse")
        self.assertEqual(payload["source_passwords"]["C:/docs"], {"type": "env", "name": "HSE_GUI_SOURCE_PASSWORD_1"})
        self.assertEqual(
            payload["source_passwords"]["C:/plain.txt"],
            {"type": "env", "name": "HSE_GUI_SOURCE_PASSWORD_2"},
        )
        self.assertEqual(payload["individually_encrypted_files_by_folder"], {"C:/docs": ["private/secret.txt"]})
        self.assertEqual(
            payload["folder_inner_passwords"],
            {"C:/docs": {"private/secret.txt": {"type": "env", "name": "HSE_GUI_FOLDER_INNER_PASSWORD_1_1"}}},
        )
        self.assertEqual(payload["password_table_output_path"], "E:/sidecars/passwords.hsm")
        self.assertEqual(plan.runtime_env["HSE_GUI_METADATA_PASSWORD"], "default-pass")
        self.assertEqual(plan.runtime_env["HSE_GUI_SOURCE_PASSWORD_1"], "default-pass")
        self.assertEqual(plan.runtime_env["HSE_GUI_SOURCE_PASSWORD_2"], "file-pass")
        self.assertEqual(plan.runtime_env["HSE_GUI_FOLDER_INNER_PASSWORD_1_1"], "inner-pass")

    def test_build_file_encryption_config_payload_keeps_single_folder_as_folder_encryption(self) -> None:
        """A single folder from quick-use should not be forced into multi-file bundle mode."""

        payload = build_file_encryption_config_payload(
            sources_text="C:/docs\n",
            default_password="main-pass",
            metadata_password="",
            output_dir="D:/encrypted",
            security_mode=SECURITY_MODE_LABELS["compatible"],
            folder_inner_passwords_text="C:/docs|private/secret.txt|inner-pass",
            bundle_output_path="D:/encrypted/bundle.zip.hse",
        )

        self.assertFalse(payload["package_as_bundle"])
        self.assertNotIn("bundle_output_path", payload)
        self.assertEqual(payload["metadata_password"], {"type": "env", "name": "HSE_GUI_METADATA_PASSWORD"})

    def test_build_file_decryption_config_payload_accepts_manual_password_table_path(self) -> None:
        """The file-decryption multi-file setup should allow sidecars from different directories."""

        plan = build_file_decryption_config_plan(
            encrypted_files_text="D:/encrypted/a.txt.hse\n",
            manifest_path="E:/sidecars/manifest.hsm",
            password_table_path="F:/passwords/passwords.hsm",
            template_path="G:/templates/template.hsm",
            metadata_password="meta-pass",
            output_dir="D:/restored",
            security_mode=SECURITY_MODE_LABELS["compatible"],
        )
        payload = plan.payload

        self.assertEqual(payload["password_table_path"], "F:/passwords/passwords.hsm")
        self.assertEqual(payload["manifest_path"], "E:/sidecars/manifest.hsm")
        self.assertEqual(payload["metadata_password"], {"type": "env", "name": "HSE_GUI_METADATA_PASSWORD"})
        self.assertEqual(plan.runtime_env["HSE_GUI_METADATA_PASSWORD"], "meta-pass")

    def test_run_quick_action_encrypts_and_decrypts_file_without_config(self) -> None:
        """The one-click file path should work without JSON configs."""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source = temp_root / "sample.txt"
            source.write_text("secret", encoding="utf-8")

            encrypted = run_quick_action("encrypt", source, "password")
            decrypted = run_quick_action("decrypt", encrypted.output_path, "password")

            self.assertTrue(encrypted.output_path.name.endswith(".hse"))
            self.assertEqual(source.read_text(encoding="utf-8"), "secret")
            self.assertEqual(decrypted.output_path.name, "sample (1).txt")
            self.assertEqual(decrypted.output_path.read_text(encoding="utf-8"), "secret")

    def test_run_quick_action_encrypts_and_decrypts_folder_without_config(self) -> None:
        """The one-click folder path should create and restore a .zip.hse package."""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder = temp_root / "docs"
            folder.mkdir()
            (folder / "note.txt").write_text("secret", encoding="utf-8")

            encrypted = run_quick_action("encrypt", folder, "password")
            decrypted = run_quick_action("decrypt", encrypted.output_path, "password")

            self.assertEqual(encrypted.output_path.name, "docs.zip.hse")
            self.assertEqual(decrypted.output_path.name, "docs")
            self.assertEqual((decrypted.output_path / "note.txt").read_text(encoding="utf-8"), "secret")

    def test_build_validate_config_args_accepts_friendly_labels(self) -> None:
        """Chinese GUI labels should still map to the stable CLI arguments."""

        args = build_validate_config_args(
            kind=CONFIG_KIND_LABELS["decrypt"],
            config_path="config.json",
            strict=False,
            report=True,
            report_format=REPORT_FORMAT_LABELS["text"],
            output_path="",
            summary_only=False,
            exit_code_on_issues=False,
            warnings_as_errors=False,
        )

        self.assertEqual(
            args,
            [
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                "config.json",
                "--report",
                "--format",
                "text",
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

    def test_build_init_example_args_accepts_friendly_labels(self) -> None:
        """Example generation should accept the labels shown in the GUI."""

        self.assertEqual(
            build_init_example_args(
                mode=SECURITY_MODE_LABELS["no-password-tables"],
                kind=CONFIG_KIND_LABELS["decrypt"],
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
