from pathlib import Path
import json
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.config import BatchDecryptionConfig, BatchEncryptionConfig
from high_security_encryptor.security_mode import (
    SECURITY_MODE_COMPATIBLE,
    SECURITY_MODE_HARDENED,
    SECURITY_MODE_NO_PASSWORD_TABLES,
    get_security_mode_profile,
)


class SecurityModeTests(unittest.TestCase):
    def test_get_security_mode_profile_returns_expected_defaults(self) -> None:
        """安全模式应展开为稳定的默认开关。"""

        compatible = get_security_mode_profile(SECURITY_MODE_COMPATIBLE)
        hardened = get_security_mode_profile(SECURITY_MODE_HARDENED)
        no_tables = get_security_mode_profile(SECURITY_MODE_NO_PASSWORD_TABLES)

        self.assertTrue(compatible.write_password_table)
        self.assertTrue(compatible.write_internal_password_tables)
        self.assertFalse(hardened.write_password_table)
        self.assertTrue(hardened.write_internal_password_tables)
        self.assertFalse(no_tables.write_password_table)
        self.assertFalse(no_tables.write_internal_password_tables)

    def test_batch_encryption_config_applies_security_mode_defaults(self) -> None:
        """加密配置应根据命名安全模式自动补齐默认值。"""

        config = BatchEncryptionConfig.from_dict(
            {
                "sources": ["a.txt"],
                "source_passwords": {"a.txt": "pw"},
                "metadata_password": "meta",
                "output_dir": "out",
                "security_mode": SECURITY_MODE_HARDENED,
            }
        )

        self.assertEqual(config.security_mode, SECURITY_MODE_HARDENED)
        self.assertFalse(config.write_password_table)
        self.assertTrue(config.write_internal_password_tables)

    def test_explicit_password_table_flags_override_security_mode_defaults(self) -> None:
        """显式布尔开关应覆盖安全模式给出的默认值。"""

        config = BatchEncryptionConfig.from_dict(
            {
                "sources": ["a.txt"],
                "source_passwords": {"a.txt": "pw"},
                "metadata_password": "meta",
                "output_dir": "out",
                "security_mode": SECURITY_MODE_NO_PASSWORD_TABLES,
                "write_password_table": True,
                "write_internal_password_tables": True,
            }
        )

        self.assertTrue(config.write_password_table)
        self.assertTrue(config.write_internal_password_tables)

    def test_hardened_decrypt_mode_rejects_top_level_password_table_path(self) -> None:
        """`hardened` 模式下不应再接受顶层密码表路径。"""

        with self.assertRaises(ValueError):
            BatchDecryptionConfig.from_dict(
                {
                    "encrypted_files": ["a.hse"],
                    "manifest_path": "manifest.hsm",
                    "password_table_path": "passwords.hsm",
                    "template_path": "template.hsm",
                    "metadata_password": "meta",
                    "output_dir": "out",
                    "security_mode": SECURITY_MODE_HARDENED,
                    "template_passwords_by_encrypted_name": {"a.hse": "pw"},
                }
            )

    def test_example_configs_can_be_loaded(self) -> None:
        """官方示例 JSON 应能被配置层成功加载。"""

        examples_dir = PROJECT_ROOT / "examples"
        encryption_examples = [
            examples_dir / "compatible_encrypt.json",
            examples_dir / "hardened_encrypt.json",
            examples_dir / "no_password_tables_encrypt.json",
        ]
        decryption_examples = [
            examples_dir / "compatible_decrypt.json",
            examples_dir / "hardened_decrypt.json",
            examples_dir / "no_password_tables_decrypt.json",
        ]

        for path in encryption_examples:
            payload = json.loads(path.read_text(encoding="utf-8"))
            config = BatchEncryptionConfig.from_dict(payload)
            self.assertTrue(config.sources)

        for path in decryption_examples:
            payload = json.loads(path.read_text(encoding="utf-8"))
            config = BatchDecryptionConfig.from_dict(payload)
            self.assertTrue(config.encrypted_files)


if __name__ == "__main__":
    unittest.main()
