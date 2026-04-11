from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.config import BatchDecryptionConfig, BatchEncryptionConfig


def _minimal_encryption_payload() -> dict[str, object]:
    return {
        "sources": ["a.txt"],
        "source_passwords": {"a.txt": "pw"},
        "metadata_password": "meta",
        "output_dir": "out",
    }


def _minimal_decryption_payload() -> dict[str, object]:
    return {
        "encrypted_files": ["a.txt.hse"],
        "manifest_path": "manifest.hsm",
        "password_table_path": "passwords.hsm",
        "template_path": "template.hsm",
        "metadata_password": "meta",
        "output_dir": "out",
    }


class ConfigSchemaTests(unittest.TestCase):
    def test_encryption_config_rejects_non_object_payload(self) -> None:
        with self.assertRaisesRegex(ValueError, "config must be a JSON object"):
            BatchEncryptionConfig.from_dict(["not", "an", "object"])

    def test_encryption_config_rejects_scalar_sources(self) -> None:
        payload = _minimal_encryption_payload()
        payload["sources"] = "a.txt"

        with self.assertRaisesRegex(ValueError, "sources must be a list"):
            BatchEncryptionConfig.from_dict(payload)

    def test_encryption_config_rejects_string_boolean_flags(self) -> None:
        payload = _minimal_encryption_payload()
        payload["write_password_table"] = "false"

        with self.assertRaisesRegex(ValueError, "write_password_table must be a boolean"):
            BatchEncryptionConfig.from_dict(payload)

    def test_encryption_config_rejects_non_string_password_specs(self) -> None:
        payload = _minimal_encryption_payload()
        payload["source_passwords"] = {"a.txt": 12345}

        with self.assertRaisesRegex(ValueError, r"source_passwords\[a\.txt\] must be"):
            BatchEncryptionConfig.from_dict(payload)

    def test_decryption_config_rejects_string_auto_decrypt_flag(self) -> None:
        payload = _minimal_decryption_payload()
        payload["auto_decrypt_folder_inner_files"] = "false"

        with self.assertRaisesRegex(ValueError, "auto_decrypt_folder_inner_files must be a boolean"):
            BatchDecryptionConfig.from_dict(payload)

    def test_decryption_config_rejects_unknown_folder_runtime_scope(self) -> None:
        payload = _minimal_decryption_payload()
        payload["folder_template_passwords_by_package_encrypted_name"] = {
            "folder.hse": {
                "by_original_name": {
                    "secret.txt": "pw",
                }
            }
        }

        with self.assertRaisesRegex(ValueError, "unsupported scope: by_original_name"):
            BatchDecryptionConfig.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
