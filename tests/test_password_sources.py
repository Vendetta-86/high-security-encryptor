from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.config import BatchEncryptionConfig
from high_security_encryptor.password_sources import PasswordResolver, PasswordSourceError


def _build_test_resolver(
    *,
    environment: dict[str, str] | None = None,
    prompt_value: str = "prompt-pass",
    file_values: dict[str, str] | None = None,
    command_values: dict[tuple[str, ...], str] | None = None,
) -> PasswordResolver:
    """为单元测试创建一个确定性的密码解析器。"""

    normalized_file_values = {str(Path(path)): value for path, value in (file_values or {}).items()}
    normalized_command_values = {
        tuple(argv): value for argv, value in (command_values or {}).items()
    }
    return PasswordResolver(
        environment=environment or {},
        prompt_callback=lambda prompt: prompt_value,
        file_reader=lambda path: normalized_file_values[str(Path(path))],
        command_runner=lambda argv: normalized_command_values[tuple(argv)],
    )


class PasswordSourceTests(unittest.TestCase):
    def test_password_resolver_reads_environment_source(self) -> None:
        """环境变量密码来源应能稳定解析。"""

        resolver = _build_test_resolver(environment={"APP_SECRET": "env-pass"})
        self.assertEqual(
            resolver.resolve({"type": "env", "name": "APP_SECRET"}, "test-context"),
            "env-pass",
        )

    def test_password_resolver_uses_prompt_callback(self) -> None:
        """提示式密码来源应调用注入的回调。"""

        seen_prompts: list[str] = []
        resolver = PasswordResolver(
            environment={},
            prompt_callback=lambda prompt: seen_prompts.append(prompt) or "prompt-pass",
            file_reader=lambda path: "",
            command_runner=lambda argv: "",
        )
        self.assertEqual(
            resolver.resolve({"type": "prompt", "prompt": "Enter test secret: "}, "test-context"),
            "prompt-pass",
        )
        self.assertEqual(seen_prompts, ["Enter test secret:"])

    def test_password_resolver_reads_file_source(self) -> None:
        """基于文件的密码来源只应去掉末尾换行。"""

        resolver = _build_test_resolver(file_values={"secret.txt": "file-pass\n"})
        self.assertEqual(
            resolver.resolve({"type": "file", "path": "secret.txt"}, "test-context"),
            "file-pass",
        )

    def test_password_resolver_runs_command_source(self) -> None:
        """基于命令的密码来源应按配置的 argv 执行。"""

        resolver = _build_test_resolver(
            command_values={("tool", "--emit-password"): "command-pass\n"}
        )
        self.assertEqual(
            resolver.resolve(
                {"type": "command", "argv": ["tool", "--emit-password"]},
                "test-context",
            ),
            "command-pass",
        )

    def test_batch_encryption_config_resolves_secret_specs(self) -> None:
        """批量配置应能解析混合的 direct/env/file/command 密码来源。"""

        config = BatchEncryptionConfig.from_dict(
            {
                "sources": ["a.txt"],
                "source_passwords": {
                    "a.txt": {"type": "env", "name": "SOURCE_SECRET"},
                },
                "metadata_password": {"type": "prompt", "prompt": "Metadata: "},
                "output_dir": "out",
                "individually_encrypted_files_by_folder": {"folder": ["nested.txt"]},
                "folder_inner_passwords": {
                    "folder": {
                        "nested.txt": {"type": "command", "argv": ["tool", "nested"]},
                    }
                },
            }
        )
        resolver = _build_test_resolver(
            environment={"SOURCE_SECRET": "source-pass"},
            prompt_value="meta-pass",
            command_values={("tool", "nested"): "nested-pass"},
        )

        self.assertEqual(config.resolve_metadata_password(resolver), "meta-pass")
        mapping = config.build_workflow_password_mapping(resolver)
        self.assertEqual(mapping["a.txt"], "source-pass")
        self.assertEqual(mapping[(Path("folder"), "nested.txt")], "nested-pass")

    def test_password_resolver_rejects_missing_environment_variable(self) -> None:
        """缺失的环境变量引用应尽早且明确地失败。"""

        resolver = _build_test_resolver()
        with self.assertRaises(PasswordSourceError):
            resolver.resolve({"type": "env", "name": "MISSING_SECRET"}, "test-context")


if __name__ == "__main__":
    unittest.main()
