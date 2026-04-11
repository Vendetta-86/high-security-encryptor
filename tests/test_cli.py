from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"


class CliTests(unittest.TestCase):
    def test_encrypt_batch_cli_emits_json_summary(self) -> None:
        """CLI 应能从 JSON 配置驱动批量加密。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("cli note", encoding="utf-8")

            config_path = temp_root / "encrypt.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {str(plain_source): "plain-pass"},
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "cli-batch",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli("encrypt-batch", "--config", str(config_path))
            summary = json.loads(result.stdout)

            self.assertEqual(summary["command"], "encrypt-batch")
            self.assertEqual(summary["binding"]["batch_id"], "cli-batch")
            self.assertEqual(len(summary["encrypted_files"]), 1)
            self.assertTrue(Path(summary["manifest_path"]).exists())
            self.assertTrue(Path(summary["password_table_path"]).exists())
            self.assertTrue(Path(summary["template_path"]).exists())

    def test_decrypt_batch_cli_handles_mixed_batch(self) -> None:
        """CLI 应能解密混合批次并继续处理文件夹内部内容。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("cli plain", encoding="utf-8")

            folder_source = temp_root / "docs"
            folder_source.mkdir()
            (folder_source / "visible.txt").write_text("visible", encoding="utf-8")
            (folder_source / "secret.txt").write_text("cli secret", encoding="utf-8")

            encrypt_config_path = temp_root / "encrypt.json"
            encrypt_config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source), str(folder_source)],
                        "source_passwords": {
                            str(plain_source): "plain-pass",
                            str(folder_source): "folder-pass",
                        },
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "cli-mixed",
                        "individually_encrypted_files_by_folder": {
                            str(folder_source): ["secret.txt"]
                        },
                        "folder_inner_passwords": {
                            str(folder_source): {
                                "secret.txt": "inner-pass"
                            }
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            encrypt_result = _run_cli("encrypt-batch", "--config", str(encrypt_config_path))
            encrypt_summary = json.loads(encrypt_result.stdout)

            decrypt_config_path = temp_root / "decrypt.json"
            decrypt_config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": encrypt_summary["encrypted_files"],
                        "manifest_path": encrypt_summary["manifest_path"],
                        "password_table_path": encrypt_summary["password_table_path"],
                        "template_path": encrypt_summary["template_path"],
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "decrypted"),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            decrypt_result = _run_cli("decrypt-batch", "--config", str(decrypt_config_path))
            decrypt_summary = json.loads(decrypt_result.stdout)

            self.assertEqual(decrypt_summary["command"], "decrypt-batch")
            self.assertEqual(decrypt_summary["binding"]["batch_id"], "cli-mixed")
            self.assertEqual(len(decrypt_summary["decrypted_files"]), 1)
            self.assertEqual(len(decrypt_summary["decrypted_folder_packages"]), 1)
            self.assertEqual(
                Path(decrypt_summary["decrypted_files"][0]["decrypted_path"]).read_text(encoding="utf-8"),
                "cli plain",
            )
            folder_root = Path(decrypt_summary["decrypted_folder_packages"][0]["extracted_root"])
            self.assertEqual((folder_root / "visible.txt").read_text(encoding="utf-8"), "visible")
            self.assertEqual((folder_root / "secret.txt").read_text(encoding="utf-8"), "cli secret")

    def test_encrypt_batch_cli_supports_environment_password_sources(self) -> None:
        """CLI 配置应能从环境变量读取密码。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("env cli note", encoding="utf-8")

            config_path = temp_root / "encrypt-env.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {
                            str(plain_source): {"type": "env", "name": "CLI_SOURCE_PASSWORD"}
                        },
                        "metadata_password": {"type": "env", "name": "CLI_METADATA_PASSWORD"},
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "env-cli-batch",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "encrypt-batch",
                "--config",
                str(config_path),
                extra_env={
                    "CLI_SOURCE_PASSWORD": "env-plain-pass",
                    "CLI_METADATA_PASSWORD": "env-meta-pass",
                },
            )
            summary = json.loads(result.stdout)

            self.assertEqual(summary["binding"]["batch_id"], "env-cli-batch")
            self.assertEqual(len(summary["encrypted_files"]), 1)
            self.assertTrue(Path(summary["encrypted_files"][0]).exists())

    def test_encrypt_batch_cli_supports_file_and_command_password_sources(self) -> None:
        """CLI 配置应支持基于文件和命令的密码来源。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("provider cli note", encoding="utf-8")

            metadata_secret_path = temp_root / "metadata.secret"
            metadata_secret_path.write_text("file-meta-pass\n", encoding="utf-8")

            config_path = temp_root / "encrypt-provider.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {
                            str(plain_source): {
                                "type": "command",
                                "argv": [sys.executable, "-c", "print('command-pass')"],
                            }
                        },
                        "metadata_password": {
                            "type": "file",
                            "path": str(metadata_secret_path),
                        },
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "provider-cli-batch",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli("encrypt-batch", "--config", str(config_path))
            summary = json.loads(result.stdout)

            self.assertEqual(summary["binding"]["batch_id"], "provider-cli-batch")
            self.assertEqual(len(summary["encrypted_files"]), 1)
            self.assertTrue(Path(summary["encrypted_files"][0]).exists())

    def test_decrypt_batch_cli_can_use_template_runtime_password_sources_without_password_table(self) -> None:
        """CLI 解密应能在没有密码表 sidecar 时工作。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("runtime cli secret", encoding="utf-8")

            encrypt_config_path = temp_root / "encrypt.json"
            encrypt_config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {str(plain_source): "plain-pass"},
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "runtime-cli-batch",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            encrypt_result = _run_cli("encrypt-batch", "--config", str(encrypt_config_path))
            encrypt_summary = json.loads(encrypt_result.stdout)

            decrypt_config_path = temp_root / "decrypt-runtime.json"
            decrypt_config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": encrypt_summary["encrypted_files"],
                        "manifest_path": encrypt_summary["manifest_path"],
                        "password_table_path": None,
                        "template_path": encrypt_summary["template_path"],
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "decrypted"),
                        "template_passwords_by_encrypted_name": {
                            "note.txt.hse": {"type": "env", "name": "RUNTIME_CLI_SECRET"}
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            decrypt_result = _run_cli(
                "decrypt-batch",
                "--config",
                str(decrypt_config_path),
                extra_env={"RUNTIME_CLI_SECRET": "plain-pass"},
            )
            decrypt_summary = json.loads(decrypt_result.stdout)

            self.assertEqual(len(decrypt_summary["decrypted_files"]), 1)
            self.assertEqual(
                Path(decrypt_summary["decrypted_files"][0]["decrypted_path"]).read_text(encoding="utf-8"),
                "runtime cli secret",
            )

    def test_decrypt_batch_cli_can_use_internal_folder_template_runtime_sources_without_internal_password_table(self) -> None:
        """CLI 解密应能仅依靠内部模板继续处理文件夹。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder_source = temp_root / "docs"
            folder_source.mkdir()
            (folder_source / "visible.txt").write_text("visible", encoding="utf-8")
            (folder_source / "secret.txt").write_text("inner runtime secret", encoding="utf-8")

            encrypt_config_path = temp_root / "encrypt-folder.json"
            encrypt_config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(folder_source)],
                        "source_passwords": {str(folder_source): "folder-pass"},
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "folder-runtime-cli-batch",
                        "individually_encrypted_files_by_folder": {
                            str(folder_source): ["secret.txt"]
                        },
                        "folder_inner_passwords": {
                            str(folder_source): {
                                "secret.txt": "inner-pass"
                            }
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            encrypt_result = _run_cli("encrypt-batch", "--config", str(encrypt_config_path))
            encrypt_summary = json.loads(encrypt_result.stdout)

            encrypted_package_path = Path(encrypt_summary["encrypted_files"][0])
            plaintext_zip_path = temp_root / "folder.zip"
            _run_python_inline(
                [
                    "from high_security_encryptor.api import decrypt_file_streaming;"
                    f"decrypt_file_streaming(r'{encrypted_package_path}', r'{plaintext_zip_path}', 'folder-pass')"
                ]
            )
            rebuilt_zip_path = temp_root / "folder-no-password-table.zip"
            with zipfile.ZipFile(plaintext_zip_path, "r") as source_zip, zipfile.ZipFile(
                rebuilt_zip_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as target_zip:
                for member in source_zip.infolist():
                    if member.filename == "docs/_hse_sidecars/batch_password_table.hsm":
                        continue
                    target_zip.writestr(member, source_zip.read(member.filename))
            _run_python_inline(
                [
                    "from high_security_encryptor.api import encrypt_file_streaming;"
                    f"encrypt_file_streaming(r'{rebuilt_zip_path}', r'{encrypted_package_path}', 'folder-pass')"
                ]
            )

            decrypt_config_path = temp_root / "decrypt-folder-runtime.json"
            decrypt_config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": encrypt_summary["encrypted_files"],
                        "manifest_path": encrypt_summary["manifest_path"],
                        "password_table_path": encrypt_summary["password_table_path"],
                        "template_path": encrypt_summary["template_path"],
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "decrypted"),
                        "folder_template_passwords_by_package_encrypted_name": {
                            encrypted_package_path.name: {
                                "by_encrypted_name": {
                                    "secret.txt.hse": {"type": "env", "name": "INNER_RUNTIME_SECRET"}
                                }
                            }
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            decrypt_result = _run_cli(
                "decrypt-batch",
                "--config",
                str(decrypt_config_path),
                extra_env={"INNER_RUNTIME_SECRET": "inner-pass"},
            )
            decrypt_summary = json.loads(decrypt_result.stdout)

            folder_root = Path(decrypt_summary["decrypted_folder_packages"][0]["extracted_root"])
            self.assertEqual((folder_root / "visible.txt").read_text(encoding="utf-8"), "visible")
            self.assertEqual((folder_root / "secret.txt").read_text(encoding="utf-8"), "inner runtime secret")

    def test_cli_encrypt_and_decrypt_can_omit_all_password_tables(self) -> None:
        """顶层和内部密码表都应当是可选项。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("no table plain", encoding="utf-8")

            folder_source = temp_root / "docs"
            folder_source.mkdir()
            (folder_source / "visible.txt").write_text("visible", encoding="utf-8")
            (folder_source / "secret.txt").write_text("no table inner", encoding="utf-8")

            encrypt_config_path = temp_root / "encrypt-no-tables.json"
            encrypt_config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source), str(folder_source)],
                        "source_passwords": {
                            str(plain_source): "plain-pass",
                            str(folder_source): "folder-pass",
                        },
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "no-tables-cli-batch",
                        "individually_encrypted_files_by_folder": {
                            str(folder_source): ["secret.txt"]
                        },
                        "folder_inner_passwords": {
                            str(folder_source): {
                                "secret.txt": "inner-pass"
                            }
                        },
                        "write_password_table": False,
                        "write_internal_password_tables": False,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            encrypt_result = _run_cli("encrypt-batch", "--config", str(encrypt_config_path))
            encrypt_summary = json.loads(encrypt_result.stdout)

            self.assertIsNone(encrypt_summary["password_table_path"])

            decrypt_config_path = temp_root / "decrypt-no-tables.json"
            decrypt_config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": encrypt_summary["encrypted_files"],
                        "manifest_path": encrypt_summary["manifest_path"],
                        "password_table_path": None,
                        "template_path": encrypt_summary["template_path"],
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "decrypted"),
                        "template_passwords_by_encrypted_name": {
                            "note.txt.hse": {"type": "env", "name": "TOP_SECRET"},
                            Path(encrypt_summary["encrypted_files"][1]).name: {
                                "type": "env",
                                "name": "FOLDER_SECRET",
                            },
                        },
                        "folder_template_passwords_by_package_encrypted_name": {
                            Path(encrypt_summary["encrypted_files"][1]).name: {
                                "by_encrypted_name": {
                                    "secret.txt.hse": {"type": "env", "name": "INNER_SECRET"}
                                }
                            }
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            decrypt_result = _run_cli(
                "decrypt-batch",
                "--config",
                str(decrypt_config_path),
                extra_env={
                    "TOP_SECRET": "plain-pass",
                    "FOLDER_SECRET": "folder-pass",
                    "INNER_SECRET": "inner-pass",
                },
            )
            decrypt_summary = json.loads(decrypt_result.stdout)

            self.assertEqual(
                Path(decrypt_summary["decrypted_files"][0]["decrypted_path"]).read_text(encoding="utf-8"),
                "no table plain",
            )
            folder_root = Path(decrypt_summary["decrypted_folder_packages"][0]["extracted_root"])
            self.assertEqual((folder_root / "visible.txt").read_text(encoding="utf-8"), "visible")
            self.assertEqual((folder_root / "secret.txt").read_text(encoding="utf-8"), "no table inner")

    def test_encrypt_batch_cli_supports_named_security_mode(self) -> None:
        """命名安全模式应自动映射到对应的生成策略。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("mode note", encoding="utf-8")

            config_path = temp_root / "encrypt-mode.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {str(plain_source): "plain-pass"},
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                        "batch_id": "mode-batch",
                        "security_mode": "hardened",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli("encrypt-batch", "--config", str(config_path))
            summary = json.loads(result.stdout)

            self.assertEqual(summary["security_mode"], "hardened")
            self.assertIsNone(summary["password_table_path"])
            self.assertEqual(len(summary["encrypted_files"]), 1)

    def test_init_example_cli_exports_requested_template(self) -> None:
        """CLI 应能按模式和用途导出官方示例配置。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            output_path = temp_root / "example.json"

            result = _run_cli(
                "init-example",
                "--mode",
                "no-password-tables",
                "--kind",
                "decrypt",
                "--output",
                str(output_path),
            )
            summary = json.loads(result.stdout)
            exported_payload = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual(summary["command"], "init-example")
            self.assertEqual(summary["security_mode"], "no-password-tables")
            self.assertEqual(summary["kind"], "decrypt")
            self.assertTrue(output_path.exists())
            self.assertEqual(exported_payload["security_mode"], "no-password-tables")
            self.assertIsNone(exported_payload["password_table_path"])

    def test_init_example_cli_can_print_template_to_stdout(self) -> None:
        """CLI 应能把示例模板直接打印到标准输出。"""

        result = _run_cli(
            "init-example",
            "--mode",
            "compatible",
            "--kind",
            "encrypt",
            "--print",
        )
        raw_template, raw_summary = result.stdout.split("###SUMMARY###\n", 1)
        printed_template = json.loads(raw_template)
        summary = json.loads(raw_summary)

        self.assertEqual(printed_template["security_mode"], "compatible")
        self.assertEqual(summary["command"], "init-example")
        self.assertIsNone(summary["output_path"])

    def test_init_example_cli_can_override_existing_fields(self) -> None:
        """CLI 应能在导出示例前替换已有 JSON 字段。"""

        result = _run_cli(
            "init-example",
            "--mode",
            "hardened",
            "--kind",
            "decrypt",
            "--print",
            "--set",
            "output_dir=D:/custom-output",
            "--set",
            "metadata_password.name=HSE_METADATA_PASSWORD",
            "--set",
            "encrypted_files.0=D:/encrypted/custom.hse",
        )
        raw_template, raw_summary = result.stdout.split("###SUMMARY###\n", 1)
        printed_template = json.loads(raw_template)
        summary = json.loads(raw_summary)

        self.assertEqual(printed_template["output_dir"], "D:/custom-output")
        self.assertEqual(printed_template["metadata_password"]["name"], "HSE_METADATA_PASSWORD")
        self.assertEqual(printed_template["encrypted_files"][0], "D:/encrypted/custom.hse")
        self.assertEqual(
            summary["applied_overrides"],
            ["output_dir", "metadata_password.name", "encrypted_files.0"],
        )

    def test_init_example_cli_can_override_existing_fields_from_json_file(self) -> None:
        """CLI 应能从 JSON 文件加载复杂结构并覆盖示例字段。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            provider_payload_path = temp_root / "provider.json"
            provider_payload_path.write_text(
                json.dumps(
                    {
                        "type": "command",
                        "argv": [sys.executable, "-c", "print('meta-from-file')"],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "init-example",
                "--mode",
                "compatible",
                "--kind",
                "encrypt",
                "--print",
                "--set-file",
                f"metadata_password=@{provider_payload_path}",
            )
            raw_template, raw_summary = result.stdout.split("###SUMMARY###\n", 1)
            printed_template = json.loads(raw_template)
            summary = json.loads(raw_summary)

            self.assertEqual(printed_template["metadata_password"]["type"], "command")
            self.assertEqual(
                printed_template["metadata_password"]["argv"],
                [sys.executable, "-c", "print('meta-from-file')"],
            )
            self.assertEqual(summary["applied_overrides"], ["metadata_password@file"])

    def test_validate_config_cli_checks_config_without_running_workflow(self) -> None:
        """CLI 应能仅校验配置而不执行实际工作流。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "validate.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
            )
            summary = json.loads(result.stdout)

            self.assertEqual(summary["command"], "validate-config")
            self.assertEqual(summary["kind"], "encrypt")
            self.assertEqual(summary["security_mode"], "compatible")
            self.assertTrue(summary["valid"])
            self.assertFalse(summary["strict"])

    def test_validate_config_cli_strict_rejects_security_mode_override_conflicts(self) -> None:
        """严格校验应拒绝与命名安全模式默认策略冲突的生成配置。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "strict-encrypt.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "write_password_table": True,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--strict",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("write_password_table", result.stderr)

    def test_validate_config_cli_strict_rejects_non_template_runtime_passwords(self) -> None:
        """严格校验应要求禁用密码表模式改走模板运行时密码映射。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "strict-decrypt.json"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("template mappings", result.stderr)

    def test_validate_config_cli_report_returns_structured_issues(self) -> None:
        """report 模式应返回结构化问题列表而不是直接失败。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-decrypt.json"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
            )
            summary = json.loads(result.stdout)

            self.assertFalse(summary["valid"])
            self.assertTrue(summary["strict"])
            self.assertTrue(summary["report"])
            self.assertEqual(summary["issues"][0]["code"], "non-template-runtime-passwords")

    def test_validate_config_cli_report_returns_valid_summary_for_good_config(self) -> None:
        """report 模式在配置通过时也应返回结构化成功结果。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-encrypt.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
            )
            summary = json.loads(result.stdout)

            self.assertTrue(summary["valid"])
            self.assertEqual(summary["issues"][0]["code"], "top-level-password-table-enabled")
            self.assertEqual(summary["issues"][0]["severity"], "warning")
            self.assertTrue(summary["report"])

    def test_validate_config_cli_report_can_render_text_format(self) -> None:
        """report 模式应支持更适合终端阅读的文本格式。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-text.json"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
                "--format",
                "text",
            )
            raw_report, raw_summary = result.stdout.split("###SUMMARY###\n", 1)
            summary = json.loads(raw_summary)

            self.assertIn("配置校验报告", raw_report)
            self.assertIn("non-template-runtime-passwords", raw_report)
            self.assertEqual(summary["format"], "text")
            self.assertFalse(summary["valid"])
 
    def test_validate_config_cli_report_can_return_nonzero_exit_code_on_issues(self) -> None:
        """report 模式应能在发现问题时返回适合 CI 使用的退出码。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-exit-code.json"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
                "--exit-code-on-issues",
            )
            summary = json.loads(result.stdout)

            self.assertEqual(result.returncode, 2)
            self.assertFalse(summary["valid"])
            self.assertTrue(summary["exit_code_on_issues"])
 
    def test_validate_config_cli_report_keeps_zero_exit_code_for_warning_only_by_default(self) -> None:
        """仅有 warning 时，默认不应因为 exit-code-on-issues 而失败。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-warning-only.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--exit-code-on-issues",
            )
            summary = json.loads(result.stdout)

            self.assertTrue(summary["valid"])
            self.assertEqual(summary["issues"][0]["severity"], "warning")
            self.assertFalse(summary["warnings_as_errors"])

    def test_validate_config_cli_report_can_treat_warnings_as_errors_for_exit_code(self) -> None:
        """warnings-as-errors 应让 warning 也参与 CI 退出码判定。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-warning-exit.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--exit-code-on-issues",
                "--warnings-as-errors",
            )
            summary = json.loads(result.stdout)

            self.assertEqual(result.returncode, 2)
            self.assertTrue(summary["valid"])
            self.assertTrue(summary["warnings_as_errors"])
            self.assertEqual(summary["issues"][0]["severity"], "warning")

    def test_validate_config_cli_report_summary_only_preserves_warning_exit_code(self) -> None:
        """summary-only stdout must not hide warning issues from exit-code evaluation."""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-summary-warning-exit.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--summary-only",
                "--exit-code-on-issues",
                "--warnings-as-errors",
            )
            summary = json.loads(result.stdout)

            self.assertEqual(result.returncode, 2)
            self.assertTrue(summary["summary_only"])
            self.assertTrue(summary["valid"])
            self.assertEqual(summary["issue_counts"]["warning"], 1)
 
    def test_validate_config_cli_report_can_write_json_report_to_file(self) -> None:
        """report 模式应支持把 JSON 报告写到文件。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-json-output.json"
            report_path = temp_root / "reports" / "validate.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--output",
                str(report_path),
            )
            summary = json.loads(result.stdout)
            written_summary = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(summary["output_path"], str(report_path))
            self.assertEqual(written_summary["output_path"], str(report_path))
            self.assertEqual(written_summary["format"], "json")
            self.assertTrue(report_path.exists())

    def test_validate_config_cli_report_can_write_text_report_to_file(self) -> None:
        """text 报告模式应支持把渲染后的文本写到文件。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-text-output.json"
            report_path = temp_root / "reports" / "validate.txt"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
                "--format",
                "text",
                "--output",
                str(report_path),
            )
            raw_report, raw_summary = result.stdout.split("###SUMMARY###\n", 1)
            summary = json.loads(raw_summary)
            written_text = report_path.read_text(encoding="utf-8")

            self.assertEqual(summary["output_path"], str(report_path))
            self.assertEqual(written_text, raw_report.rstrip("\n"))
            self.assertIn("non-template-runtime-passwords", written_text)
            self.assertIn("missing-template-runtime-passwords", written_text)
 
    def test_validate_config_cli_report_summary_only_can_compact_json_stdout(self) -> None:
        """summary-only 应把标准输出 JSON 压缩成摘要。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-summary-json.json"
            report_path = temp_root / "reports" / "full.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--summary-only",
                "--output",
                str(report_path),
            )
            summary = json.loads(result.stdout)
            full_report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertTrue(summary["summary_only"])
            self.assertEqual(summary["issue_counts"]["warning"], 1)
            self.assertEqual(summary["top_issue_code"], "top-level-password-table-enabled")
            self.assertNotIn("issues", summary)
            self.assertIn("issues", full_report)

    def test_validate_config_cli_report_summary_only_can_compact_text_stdout(self) -> None:
        """text + summary-only 应在终端只输出摘要文本。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-summary-text.json"
            report_path = temp_root / "reports" / "full.txt"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
                "--format",
                "text",
                "--summary-only",
                "--output",
                str(report_path),
            )
            raw_report, raw_summary = result.stdout.split("###SUMMARY###\n", 1)
            summary = json.loads(raw_summary)
            written_text = report_path.read_text(encoding="utf-8")

            self.assertIn("配置校验摘要", raw_report)
            self.assertIn("full_report:", raw_report)
            self.assertEqual(summary["issue_counts"]["error"], 2)
            self.assertIn("non-template-runtime-passwords", written_text)
 
    def test_validate_config_cli_report_can_filter_issue_codes(self) -> None:
        """include-codes 应只保留指定的问题码。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-filter.json"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
                "--include-codes",
                "missing-template-runtime-passwords",
            )
            summary = json.loads(result.stdout)

            self.assertEqual(summary["included_codes"], ["missing-template-runtime-passwords"])
            self.assertEqual(len(summary["issues"]), 1)
            self.assertEqual(summary["issues"][0]["code"], "missing-template-runtime-passwords")

    def test_validate_config_cli_report_filter_can_change_exit_code_result(self) -> None:
        """include-codes 过滤后，退出码判定也应基于过滤后的问题集合。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-filter-exit.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--exit-code-on-issues",
                "--include-codes",
                "missing-template-runtime-passwords",
            )
            summary = json.loads(result.stdout)

            self.assertTrue(summary["valid"])
            self.assertEqual(summary["issues"], [])
 
    def test_validate_config_cli_report_can_exclude_issue_codes(self) -> None:
        """exclude-codes 应移除指定的问题码。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-exclude.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["D:/data/file.txt"],
                        "source_passwords": {"D:/data/file.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "compatible",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
                "--report",
                "--exclude-codes",
                "top-level-password-table-enabled",
            )
            summary = json.loads(result.stdout)

            self.assertEqual(summary["excluded_codes"], ["top-level-password-table-enabled"])
            self.assertEqual(summary["issues"], [])

    def test_validate_config_cli_report_can_combine_include_and_exclude_filters(self) -> None:
        """include/exclude 组合时应先保留再排除。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            config_path = temp_root / "report-include-exclude.json"
            config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": ["D:/encrypted/file.hse"],
                        "manifest_path": "D:/encrypted/batch_manifest.hsm",
                        "password_table_path": None,
                        "template_path": "D:/encrypted/batch_template.hsm",
                        "metadata_password": "meta",
                        "output_dir": "D:/out",
                        "security_mode": "no-password-tables",
                        "passwords_by_encrypted_name": {
                            "file.hse": "pw"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli(
                "validate-config",
                "--kind",
                "decrypt",
                "--config",
                str(config_path),
                "--strict",
                "--report",
                "--include-codes",
                "missing-template-runtime-passwords,non-template-runtime-passwords",
                "--exclude-codes",
                "non-template-runtime-passwords",
            )
            summary = json.loads(result.stdout)

            self.assertEqual(summary["included_codes"], ["missing-template-runtime-passwords", "non-template-runtime-passwords"])
            self.assertEqual(summary["excluded_codes"], ["non-template-runtime-passwords"])
            self.assertEqual(len(summary["issues"]), 1)
            self.assertEqual(summary["issues"][0]["code"], "missing-template-runtime-passwords")

    def test_cli_returns_config_exit_code_for_missing_config_file(self) -> None:
        """Missing config files should produce a concise config error."""

        with tempfile.TemporaryDirectory() as temp_dir:
            missing_config = Path(temp_dir) / "missing.json"

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(missing_config),
            )

            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, "")
            self.assertIn("error: config file not found", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_returns_config_exit_code_for_invalid_json(self) -> None:
        """Invalid JSON should be reported without a Python traceback by default."""

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "invalid.json"
            config_path.write_text("{", encoding="utf-8")

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
            )

            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, "")
            self.assertIn("error: encryption config is not valid JSON", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_returns_config_exit_code_for_schema_errors(self) -> None:
        """Malformed config field types should be normalized as config errors."""

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "invalid-schema.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": ["note.txt"],
                        "source_passwords": {"note.txt": "pw"},
                        "metadata_password": "meta",
                        "output_dir": "out",
                        "write_password_table": "false",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error(
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
            )

            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, "")
            self.assertIn("write_password_table must be a boolean", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_debug_flag_prints_traceback_for_config_errors(self) -> None:
        """--debug should preserve tracebacks for development diagnostics."""

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "invalid.json"
            config_path.write_text("{", encoding="utf-8")

            result = _run_cli_expect_error(
                "--debug",
                "validate-config",
                "--kind",
                "encrypt",
                "--config",
                str(config_path),
            )

            self.assertEqual(result.returncode, 3)
            self.assertIn("Traceback", result.stderr)
            self.assertIn("CliConfigError", result.stderr)

    def test_cli_returns_password_exit_code_for_missing_env_password(self) -> None:
        """Password provider failures should use the password-source exit code."""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("secret", encoding="utf-8")
            missing_env_name = "HSE_TEST_MISSING_PASSWORD_SOURCE_9F1B5275"

            config_path = temp_root / "encrypt-missing-env.json"
            config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {
                            str(plain_source): {"type": "env", "name": missing_env_name}
                        },
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error("encrypt-batch", "--config", str(config_path))

            self.assertEqual(result.returncode, 4)
            self.assertEqual(result.stdout, "")
            self.assertIn(f"environment variable not set: {missing_env_name}", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cli_returns_integrity_exit_code_for_wrong_decryption_password(self) -> None:
        """Streaming integrity failures should use the integrity exit code."""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("decrypt me", encoding="utf-8")

            encrypt_config_path = temp_root / "encrypt.json"
            encrypt_config_path.write_text(
                json.dumps(
                    {
                        "sources": [str(plain_source)],
                        "source_passwords": {str(plain_source): "right-pass"},
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "encrypted"),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            encrypt_summary = json.loads(_run_cli("encrypt-batch", "--config", str(encrypt_config_path)).stdout)

            decrypt_config_path = temp_root / "decrypt-wrong-password.json"
            decrypt_config_path.write_text(
                json.dumps(
                    {
                        "encrypted_files": encrypt_summary["encrypted_files"],
                        "manifest_path": encrypt_summary["manifest_path"],
                        "password_table_path": encrypt_summary["password_table_path"],
                        "template_path": encrypt_summary["template_path"],
                        "metadata_password": "meta-pass",
                        "output_dir": str(temp_root / "decrypted"),
                        "passwords_by_encrypted_name": {
                            "note.txt.hse": "wrong-pass"
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = _run_cli_expect_error("decrypt-batch", "--config", str(decrypt_config_path))

            self.assertEqual(result.returncode, 5)
            self.assertEqual(result.stdout, "")
            self.assertIn("error:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


def _run_cli(*args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """在子进程中运行项目 CLI，并把 `src` 挂到 `PYTHONPATH`。"""

    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC_ROOT) if not existing_pythonpath else f"{SRC_ROOT}{os.pathsep}{existing_pythonpath}"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "high_security_encryptor", *args],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


def _run_cli_expect_error(*args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """运行 CLI 并保留非零退出码，供错误路径断言使用。"""

    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC_ROOT) if not existing_pythonpath else f"{SRC_ROOT}{os.pathsep}{existing_pythonpath}"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "high_security_encryptor", *args],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _run_python_inline(statements: list[str]) -> subprocess.CompletedProcess[str]:
    """运行一个极小的内联 Python 程序，并把 `src` 挂到 `PYTHONPATH`。"""

    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC_ROOT) if not existing_pythonpath else f"{SRC_ROOT}{os.pathsep}{existing_pythonpath}"
    return subprocess.run(
        [sys.executable, "-c", "\n".join(statements)],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )


if __name__ == "__main__":
    unittest.main()
