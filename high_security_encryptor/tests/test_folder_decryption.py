from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.api import decrypt_file_streaming, encrypt_file_streaming
from high_security_encryptor.folder_decryption import decrypt_folder_archive, safe_extract_folder_archive
from high_security_encryptor.folder_workflow import package_folder_to_encrypted_archive
from high_security_encryptor.integrity import IntegrityValidationError
from high_security_encryptor.password_sources import PasswordResolver
from high_security_encryptor.runtime_password_plan import RuntimePasswordPlan


class FolderDecryptionTests(unittest.TestCase):
    def test_decrypt_folder_archive_auto_decrypts_inner_hse_members(self) -> None:
        """文件夹解密工作流应能继续处理受保护的内部成员。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_folder = temp_root / "docs"
            source_folder.mkdir()
            (source_folder / "visible.txt").write_text("visible", encoding="utf-8")
            (source_folder / "secret.txt").write_text("secret", encoding="utf-8")

            package_result = package_folder_to_encrypted_archive(
                source_folder,
                temp_root / "docs.zip.hse",
                folder_password="outer-pass",
                metadata_password="meta-pass",
                individually_encrypted_relative_paths=["secret.txt"],
                inner_passwords_by_relative_path={"secret.txt": "inner-pass"},
            )

            result = decrypt_folder_archive(
                package_result.package_path,
                temp_root / "decrypted",
                folder_password="outer-pass",
                metadata_password="meta-pass",
            )

            self.assertEqual(result.extracted_root, temp_root / "decrypted" / "docs")
            self.assertIsNotNone(result.discovered_binding)
            self.assertEqual(len(result.decrypted_inner_files), 1)
            self.assertEqual(
                result.decrypted_inner_files[0].encrypted_relative_path,
                "secret.txt.hse",
            )
            self.assertEqual(
                (result.extracted_root / "visible.txt").read_text(encoding="utf-8"),
                "visible",
            )
            self.assertEqual(
                (result.extracted_root / "secret.txt").read_text(encoding="utf-8"),
                "secret",
            )

    def test_safe_extract_folder_archive_rejects_path_traversal(self) -> None:
        """解压应拒绝试图逃逸目标目录的归档。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            malicious_zip = temp_root / "malicious.zip"
            with zipfile.ZipFile(malicious_zip, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr("docs/ok.txt", "ok")
                zip_file.writestr("../escape.txt", "nope")

            with self.assertRaises(ValueError):
                safe_extract_folder_archive(malicious_zip, temp_root / "out")

    def test_decrypt_folder_archive_rejects_extra_internal_hse_entry(self) -> None:
        """内部 manifest 校验应拒绝意外出现的加密成员。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_folder = temp_root / "docs"
            source_folder.mkdir()
            (source_folder / "visible.txt").write_text("visible", encoding="utf-8")
            (source_folder / "secret.txt").write_text("secret", encoding="utf-8")

            package_result = package_folder_to_encrypted_archive(
                source_folder,
                temp_root / "docs.zip.hse",
                folder_password="outer-pass",
                metadata_password="meta-pass",
                individually_encrypted_relative_paths=["secret.txt"],
                inner_passwords_by_relative_path={"secret.txt": "inner-pass"},
            )

            tampered_zip_path = temp_root / "tampered.zip"
            decrypt_file_streaming(package_result.package_path, tampered_zip_path, "outer-pass")
            with zipfile.ZipFile(tampered_zip_path, "a", compression=zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr("docs/extra.txt.hse", b"unexpected")
            tampered_package_path = temp_root / "tampered.zip.hse"
            encrypt_file_streaming(tampered_zip_path, tampered_package_path, "outer-pass")

            with self.assertRaises(IntegrityValidationError):
                decrypt_folder_archive(
                    tampered_package_path,
                    temp_root / "decrypted",
                    folder_password="outer-pass",
                    metadata_password="meta-pass",
                )

    def test_decrypt_folder_archive_records_internal_entry_comparison(self) -> None:
        """成功的文件夹续解密应暴露已验证的条目比较结果。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_folder = temp_root / "docs"
            source_folder.mkdir()
            (source_folder / "visible.txt").write_text("visible", encoding="utf-8")
            (source_folder / "secret.txt").write_text("secret", encoding="utf-8")

            package_result = package_folder_to_encrypted_archive(
                source_folder,
                temp_root / "docs.zip.hse",
                folder_password="outer-pass",
                metadata_password="meta-pass",
                individually_encrypted_relative_paths=["secret.txt"],
                inner_passwords_by_relative_path={"secret.txt": "inner-pass"},
            )

            result = decrypt_folder_archive(
                package_result.package_path,
                temp_root / "decrypted",
                folder_password="outer-pass",
                metadata_password="meta-pass",
            )

            self.assertIsNotNone(result.internal_entry_comparison)
            self.assertEqual(result.internal_entry_comparison.missing_entries, [])
            self.assertEqual(result.internal_entry_comparison.extra_entries, [])
            self.assertEqual(result.internal_entry_comparison.actual_entries, ["secret.txt.hse"])

    def test_decrypt_folder_archive_can_use_internal_template_runtime_plan_without_password_table(self) -> None:
        """文件夹内部续解密应能在没有持久化密码表时工作。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_folder = temp_root / "docs"
            source_folder.mkdir()
            (source_folder / "visible.txt").write_text("visible", encoding="utf-8")
            (source_folder / "secret.txt").write_text("secret", encoding="utf-8")

            package_result = package_folder_to_encrypted_archive(
                source_folder,
                temp_root / "docs.zip.hse",
                folder_password="outer-pass",
                metadata_password="meta-pass",
                individually_encrypted_relative_paths=["secret.txt"],
                inner_passwords_by_relative_path={"secret.txt": "inner-pass"},
            )

            plaintext_zip_path = temp_root / "docs.zip"
            decrypt_file_streaming(package_result.package_path, plaintext_zip_path, "outer-pass")
            rebuilt_zip_path = temp_root / "docs-no-password-table.zip"
            with zipfile.ZipFile(plaintext_zip_path, "r") as source_zip, zipfile.ZipFile(
                rebuilt_zip_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as target_zip:
                for member in source_zip.infolist():
                    if member.filename == "docs/_hse_sidecars/batch_password_table.hsm":
                        continue
                    target_zip.writestr(member, source_zip.read(member.filename))

            rebuilt_package_path = temp_root / "docs-no-password-table.zip.hse"
            encrypt_file_streaming(rebuilt_zip_path, rebuilt_package_path, "outer-pass")
            resolver = PasswordResolver(
                environment={"INNER_SECRET": "inner-pass"},
                prompt_callback=lambda prompt: "",
                file_reader=lambda path: "",
                command_runner=lambda argv: "",
            )

            result = decrypt_folder_archive(
                rebuilt_package_path,
                temp_root / "decrypted",
                folder_password="outer-pass",
                metadata_password="meta-pass",
                internal_runtime_password_plan=RuntimePasswordPlan(
                    by_encrypted_name={"secret.txt.hse": {"type": "env", "name": "INNER_SECRET"}},
                    by_source_name={},
                ),
                password_resolver=resolver,
            )

            self.assertEqual(len(result.decrypted_inner_files), 1)
            self.assertEqual(
                (result.extracted_root / "secret.txt").read_text(encoding="utf-8"),
                "secret",
            )


if __name__ == "__main__":
    unittest.main()
