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

    def test_encryption_config_defaults_to_no_password_tables(self) -> None:
        config = BatchEncryptionConfig.from_dict(_minimal_encryption_payload())

        self.assertEqual(config.security_mode, "no-password-tables")
        self.assertFalse(config.write_password_table)
        self.assertFalse(config.write_internal_password_tables)

    def test_encryption_config_infers_compatible_for_explicit_password_table_path(self) -> None:
        payload = _minimal_encryption_payload()
        payload["password_table_output_path"] = "sidecars/passwords.hsm"

        config = BatchEncryptionConfig.from_dict(payload)

        self.assertEqual(config.security_mode, "compatible")
        self.assertTrue(config.write_password_table)
        self.assertTrue(config.write_internal_password_tables)

    def test_encryption_config_infers_hardened_for_internal_password_tables(self) -> None:
        payload = _minimal_encryption_payload()
        payload["write_internal_password_tables"] = True

        config = BatchEncryptionConfig.from_dict(payload)

        self.assertEqual(config.security_mode, "hardened")
        self.assertFalse(config.write_password_table)
        self.assertTrue(config.write_internal_password_tables)

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

    def test_encryption_config_accepts_custom_sidecar_output_paths(self) -> None:
        payload = _minimal_encryption_payload()
        payload["manifest_output_path"] = "sidecars/manifest.hsm"
        payload["password_table_output_path"] = "sidecars/passwords.hsm"
        payload["template_output_path"] = "sidecars/template.hsm"

        config = BatchEncryptionConfig.from_dict(payload)

        self.assertEqual(config.manifest_output_path, "sidecars/manifest.hsm")
        self.assertEqual(config.password_table_output_path, "sidecars/passwords.hsm")
        self.assertEqual(config.template_output_path, "sidecars/template.hsm")

    def test_encryption_config_accepts_bundle_output_mode(self) -> None:
        payload = _minimal_encryption_payload()
        payload["package_as_bundle"] = True
        payload["bundle_output_path"] = "out/easy_bundle.zip.hse"

        config = BatchEncryptionConfig.from_dict(payload)

        self.assertTrue(config.package_as_bundle)
        self.assertEqual(config.bundle_output_path, "out/easy_bundle.zip.hse")

    def test_decryption_config_rejects_string_auto_decrypt_flag(self) -> None:
        payload = _minimal_decryption_payload()
        payload["auto_decrypt_folder_inner_files"] = "false"

        with self.assertRaisesRegex(ValueError, "auto_decrypt_folder_inner_files must be a boolean"):
            BatchDecryptionConfig.from_dict(payload)

    def test_decryption_config_infers_compatible_for_password_table_path(self) -> None:
        config = BatchDecryptionConfig.from_dict(_minimal_decryption_payload())

        self.assertEqual(config.security_mode, "compatible")

    def test_decryption_config_defaults_to_no_password_tables_without_password_table_path(self) -> None:
        payload = _minimal_decryption_payload()
        payload["password_table_path"] = None
        payload["template_passwords_by_encrypted_name"] = {
            "a.txt.hse": {"type": "env", "name": "A_TXT_PASSWORD"}
        }

        config = BatchDecryptionConfig.from_dict(payload)

        self.assertEqual(config.security_mode, "no-password-tables")

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
