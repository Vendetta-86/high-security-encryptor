from io import BytesIO
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.batch_decryption_inputs import (
    build_top_level_password_mapping,
    derive_plain_file_output_name,
    extract_manifest_entries,
)
from high_security_encryptor.batch_workflow_inputs import (
    get_encrypted_target_path,
    normalize_folder_selection_mapping,
    resolve_inner_passwords,
    resolve_top_level_password,
)
from high_security_encryptor.cli_errors import CliConfigError, classify_cli_exception
from high_security_encryptor.config_decryption import BatchDecryptionConfig
from high_security_encryptor.config_encryption import BatchEncryptionConfig
from high_security_encryptor.config_parsing import normalize_secret_spec, read_folder_template_passwords
from high_security_encryptor.folder_archive import safe_extract_folder_archive
from high_security_encryptor.folder_package_utils import (
    normalize_relative_path_list,
    write_zip_from_directory,
)
from high_security_encryptor.security_mode import SECURITY_MODE_NO_PASSWORD_TABLES
from high_security_encryptor.streaming_primitives import (
    HEADER_MAGIC,
    HeaderError,
    LegacyFormatDetected,
    build_header,
    parse_header,
)
from high_security_encryptor.validation_rules import (
    collect_decryption_config_strict_issues,
    collect_encryption_config_report_warnings,
    collect_encryption_config_strict_issues,
)


class BatchWorkflowInputHelperTests(unittest.TestCase):
    def test_get_encrypted_target_path_uses_output_dir(self) -> None:
        self.assertEqual(
            get_encrypted_target_path("D:/data/report.txt", "D:/out"),
            Path("D:/out") / "report.txt.hse",
        )

    def test_normalize_folder_selection_mapping_normalizes_path_keys(self) -> None:
        mapping = normalize_folder_selection_mapping({Path("docs"): ["a.txt"]})

        self.assertEqual(mapping, {"docs": ["a.txt"]})

    def test_resolve_top_level_password_accepts_path_or_string_keys(self) -> None:
        source_path = Path("docs")

        self.assertEqual(resolve_top_level_password({source_path: "path-pass"}, source_path), "path-pass")
        self.assertEqual(resolve_top_level_password({"docs": "string-pass"}, source_path), "string-pass")

    def test_resolve_inner_passwords_accepts_supported_key_forms(self) -> None:
        source_path = Path("docs")

        self.assertEqual(
            resolve_inner_passwords(
                {
                    (source_path, "a.txt"): "tuple-path",
                    ("docs", "b.txt"): "tuple-string",
                    "docs::c.txt": "combined",
                },
                source_path,
                ["a.txt", "b.txt", "c.txt"],
            ),
            {
                "a.txt": "tuple-path",
                "b.txt": "tuple-string",
                "c.txt": "combined",
            },
        )


class BatchDecryptionInputHelperTests(unittest.TestCase):
    def test_build_top_level_password_mapping_applies_overrides_last(self) -> None:
        payload = {
            "records": [
                {"encrypted_name": "a.txt.hse", "password": "old"},
            ]
        }

        self.assertEqual(
            build_top_level_password_mapping(payload, {"a.txt.hse": "new", "b.txt.hse": "override"}),
            {"a.txt.hse": "new", "b.txt.hse": "override"},
        )

    def test_derive_plain_file_output_name_requires_hse_suffix(self) -> None:
        self.assertEqual(derive_plain_file_output_name("a.txt.hse"), "a.txt")
        with self.assertRaisesRegex(ValueError, "expected .hse"):
            derive_plain_file_output_name("a.txt")

    def test_extract_manifest_entries_returns_encrypted_names(self) -> None:
        self.assertEqual(
            extract_manifest_entries({"entries": [{"encrypted_name": "b.hse"}, {"encrypted_name": "a.hse"}]}),
            ["b.hse", "a.hse"],
        )


class ConfigParsingHelperTests(unittest.TestCase):
    def test_normalize_secret_spec_rejects_non_string_list_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata_password.argv\\[1\\] must be"):
            normalize_secret_spec({"type": "command", "argv": ["tool", 123]}, "metadata_password")

    def test_read_folder_template_passwords_accepts_supported_scopes(self) -> None:
        payload = {
            "folder_template_passwords_by_package_encrypted_name": {
                "docs.zip.hse": {
                    "by_encrypted_name": {"secret.txt.hse": "pw"},
                    "by_source_name": {"secret.txt": {"type": "env", "name": "INNER_SECRET"}},
                }
            }
        }

        parsed = read_folder_template_passwords(payload, "folder_template_passwords_by_package_encrypted_name")

        self.assertEqual(parsed["docs.zip.hse"]["by_encrypted_name"]["secret.txt.hse"], "pw")
        self.assertEqual(parsed["docs.zip.hse"]["by_source_name"]["secret.txt"]["name"], "INNER_SECRET")


class ValidationRuleTests(unittest.TestCase):
    def test_encryption_strict_rules_report_security_mode_overrides(self) -> None:
        config = BatchEncryptionConfig(
            sources=["a.txt"],
            source_passwords={"a.txt": "pw"},
            metadata_password="meta",
            output_dir="out",
            security_mode=SECURITY_MODE_NO_PASSWORD_TABLES,
            write_password_table=True,
            write_internal_password_tables=False,
        )

        issues = collect_encryption_config_strict_issues(config)

        self.assertEqual(issues[0]["code"], "security-mode-override-conflict")
        self.assertIn("write_password_table", issues[0]["message"])

    def test_decryption_strict_rules_require_template_passwords_without_tables(self) -> None:
        config = BatchDecryptionConfig(
            encrypted_files=["a.txt.hse"],
            manifest_path="manifest.hsm",
            password_table_path=None,
            template_path="template.hsm",
            metadata_password="meta",
            output_dir="out",
            security_mode=SECURITY_MODE_NO_PASSWORD_TABLES,
        )

        issues = collect_decryption_config_strict_issues(config)

        self.assertEqual(issues[0]["code"], "missing-template-runtime-passwords")

    def test_report_warnings_flag_top_level_password_tables(self) -> None:
        config = BatchEncryptionConfig(
            sources=["a.txt"],
            source_passwords={"a.txt": "pw"},
            metadata_password="meta",
            output_dir="out",
            write_password_table=True,
        )

        issues = collect_encryption_config_report_warnings(config)

        self.assertEqual(issues[0]["code"], "top-level-password-table-enabled")
        self.assertEqual(issues[0]["severity"], "warning")


class FolderHelperTests(unittest.TestCase):
    def test_normalize_relative_path_list_deduplicates_and_sorts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "docs"
            root.mkdir()
            (root / "a.txt").write_text("a", encoding="utf-8")
            (root / "b.txt").write_text("b", encoding="utf-8")

            self.assertEqual(
                normalize_relative_path_list(root, ["b.txt", "a.txt", "b.txt"]),
                ["a.txt", "b.txt"],
            )

    def test_normalize_relative_path_list_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "docs"
            root.mkdir()

            with self.assertRaisesRegex(ValueError, "unsafe path segments"):
                normalize_relative_path_list(root, ["../secret.txt"])

    def test_write_zip_from_directory_preserves_root_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_root = temp_root / "docs"
            nested = source_root / "nested"
            nested.mkdir(parents=True)
            (nested / "a.txt").write_text("a", encoding="utf-8")
            zip_path = temp_root / "docs.zip"

            write_zip_from_directory(source_root, zip_path)

            with zipfile.ZipFile(zip_path) as zip_file:
                self.assertEqual(zip_file.namelist(), ["docs/nested/a.txt"])

    def test_safe_extract_folder_archive_rejects_symlink_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            archive_path = temp_root / "symlink.zip"
            member = zipfile.ZipInfo("docs/link")
            member.external_attr = 0o120777 << 16
            with zipfile.ZipFile(archive_path, "w") as zip_file:
                zip_file.writestr(member, "target")

            with self.assertRaisesRegex(ValueError, "symlink"):
                safe_extract_folder_archive(archive_path, temp_root / "out")


class StreamingPrimitiveTests(unittest.TestCase):
    def test_build_and_parse_header_round_trip(self) -> None:
        header = build_header(4096, b"s" * 16, b"n" * 12)

        parsed_header, salt, chunk_size = parse_header(BytesIO(header))

        self.assertEqual(parsed_header, header)
        self.assertEqual(salt, b"s" * 16)
        self.assertEqual(chunk_size, 4096)

    def test_parse_header_rejects_legacy_magic(self) -> None:
        with self.assertRaises(LegacyFormatDetected):
            parse_header(BytesIO(b"GCM1" + b"\x00" * 32))

    def test_parse_header_rejects_truncated_payload(self) -> None:
        with self.assertRaises(HeaderError):
            parse_header(BytesIO(HEADER_MAGIC))


class CliErrorHelperTests(unittest.TestCase):
    def test_classify_cli_exception_treats_config_errors_as_config_exit(self) -> None:
        self.assertEqual(classify_cli_exception(CliConfigError("bad config")), 3)


if __name__ == "__main__":
    unittest.main()
