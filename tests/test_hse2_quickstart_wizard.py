from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2_config import HSE2DecryptConfig, HSE2EncryptConfig
from high_security_encryptor.hse2_quickstart_wizard import (
    DEFAULT_KEYFILE_BYTES,
    build_hse2_quickstart_command_steps,
    build_hse2_quickstart_commands,
    build_hse2_quickstart_dpapi_step,
    build_hse2_quickstart_paths,
    create_hse2_quickstart_workspace,
)
from high_security_encryptor.hse2_validation_config import HSE2ValidationConfig


class HSE2QuickstartWizardTests(unittest.TestCase):
    def test_create_quickstart_workspace_writes_parseable_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = create_hse2_quickstart_workspace(Path(temp_dir) / "quickstart")

            self.assertEqual(workspace.keyfile.stat().st_size, DEFAULT_KEYFILE_BYTES)
            self.assertTrue(workspace.sample_input.read_text(encoding="utf-8").startswith("HSE2 quickstart"))
            encrypt_config = HSE2EncryptConfig.from_json_file(workspace.encrypt_config)
            validate_config = HSE2ValidationConfig.from_json_file(workspace.validate_config)
            decrypt_config = HSE2DecryptConfig.from_json_file(workspace.decrypt_config)

            self.assertEqual(encrypt_config.input, str(workspace.sample_input))
            self.assertEqual(encrypt_config.output, str(workspace.encrypted_output))
            self.assertEqual(encrypt_config.wrapper, {"type": "keyfile", "path": str(workspace.keyfile)})
            self.assertEqual(validate_config.wrapper, {"type": "keyfile", "path": str(workspace.keyfile)})
            self.assertEqual(decrypt_config.input, str(workspace.encrypted_output))
            self.assertEqual(decrypt_config.output, str(workspace.restored_output))
            self.assertTrue(workspace.command_notes.is_file())

    def test_quickstart_command_steps_are_ordered_and_executable_through_cli_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = create_hse2_quickstart_workspace(temp_dir)
            steps = build_hse2_quickstart_command_steps(workspace)

            self.assertEqual([step.name for step in steps], ["加密示例文件", "校验 HSE2 容器", "解密 HSE2 容器"])
            self.assertEqual(
                [step.argv[0] for step in steps],
                ["hse2-encrypt-config", "hse2-validate", "hse2-decrypt-config"],
            )
            self.assertEqual(steps[0].argv, ("hse2-encrypt-config", "--config", str(workspace.encrypt_config)))
            self.assertEqual(
                steps[1].argv,
                (
                    "hse2-validate",
                    "--config",
                    str(workspace.validate_config),
                    "--output",
                    str(workspace.validation_report),
                ),
            )
            self.assertEqual(steps[2].argv, ("hse2-decrypt-config", "--config", str(workspace.decrypt_config)))

    def test_quickstart_dpapi_step_is_separate_from_default_three_step_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = create_hse2_quickstart_workspace(temp_dir)
            dpapi_step = build_hse2_quickstart_dpapi_step(workspace)

            self.assertEqual(dpapi_step.name, "DPAPI 保护 keyfile")
            self.assertEqual(dpapi_step.argv[0], "dpapi-protect")
            self.assertIn(str(workspace.keyfile), dpapi_step.argv)
            self.assertNotIn(dpapi_step, build_hse2_quickstart_command_steps(workspace))

    def test_quickstart_commands_include_expected_cli_steps_without_keyfile_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = create_hse2_quickstart_workspace(temp_dir)
            commands = build_hse2_quickstart_commands(workspace)

            self.assertIn("hse2-encrypt-config", commands)
            self.assertIn("hse2-validate", commands)
            self.assertIn("hse2-decrypt-config", commands)
            self.assertIn("dpapi-protect", commands)
            self.assertIn(str(workspace.keyfile), commands)
            self.assertNotIn(workspace.keyfile.read_bytes().hex(), commands)

    def test_create_quickstart_workspace_refuses_existing_outputs_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = create_hse2_quickstart_workspace(temp_dir)
            original = json.loads(workspace.encrypt_config.read_text(encoding="utf-8"))

            with self.assertRaises(FileExistsError):
                create_hse2_quickstart_workspace(temp_dir)

            self.assertEqual(json.loads(workspace.encrypt_config.read_text(encoding="utf-8")), original)

    def test_create_quickstart_workspace_allows_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = create_hse2_quickstart_workspace(temp_dir, keyfile_size=24)
            first_key = workspace.keyfile.read_bytes()
            overwritten = create_hse2_quickstart_workspace(temp_dir, keyfile_size=24, overwrite=True)

            self.assertEqual(overwritten.keyfile.stat().st_size, 24)
            self.assertNotEqual(first_key, overwritten.keyfile.read_bytes())

    def test_build_paths_does_not_touch_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "missing"
            workspace = build_hse2_quickstart_paths(root)

            self.assertEqual(workspace.base_dir, root)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
