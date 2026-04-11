from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.batch_decryption import decrypt_batch_files
from high_security_encryptor.integrity import IntegrityValidationError
from high_security_encryptor.batch_workflow import encrypt_batch_files


class BatchDecryptionTests(unittest.TestCase):
    def test_decrypt_batch_files_handles_plain_files_and_folder_packages(self) -> None:
        """混合批次应能解出顶层文件并继续处理文件夹。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("top secret note", encoding="utf-8")

            folder_source = temp_root / "docs"
            folder_source.mkdir()
            (folder_source / "visible.txt").write_text("visible", encoding="utf-8")
            (folder_source / "secret.txt").write_text("folder secret", encoding="utf-8")

            encrypted_batch = encrypt_batch_files(
                [plain_source, folder_source],
                {
                    plain_source: "plain-pass",
                    folder_source: "folder-pass",
                    (folder_source, "secret.txt"): "inner-pass",
                },
                metadata_password="meta-pass",
                output_dir=temp_root / "encrypted",
                batch_id="mixed-batch",
                individually_encrypted_files_by_folder={folder_source: ["secret.txt"]},
            )

            result = decrypt_batch_files(
                encrypted_batch.encrypted_files,
                encrypted_batch.manifest_path,
                encrypted_batch.password_table_path,
                encrypted_batch.template_path,
                metadata_password="meta-pass",
                output_dir=temp_root / "decrypted",
            )

            self.assertEqual(result.binding.batch_id, "mixed-batch")
            self.assertEqual(result.top_level_entry_comparison.missing_entries, [])
            self.assertEqual(result.top_level_entry_comparison.extra_entries, [])
            self.assertEqual(len(result.decrypted_files), 1)
            self.assertEqual(len(result.decrypted_folder_packages), 1)
            self.assertEqual(
                result.decrypted_files[0].decrypted_path.read_text(encoding="utf-8"),
                "top secret note",
            )

            folder_result = result.decrypted_folder_packages[0]
            self.assertEqual(
                (folder_result.extracted_root / "visible.txt").read_text(encoding="utf-8"),
                "visible",
            )
            self.assertEqual(
                (folder_result.extracted_root / "secret.txt").read_text(encoding="utf-8"),
                "folder secret",
            )
            self.assertEqual(len(folder_result.decrypted_inner_files), 1)
            self.assertEqual(
                folder_result.decrypted_inner_files[0].encrypted_relative_path,
                "secret.txt.hse",
            )

    def test_decrypt_batch_files_accepts_top_level_password_override(self) -> None:
        """显式提供的顶层密码覆盖应优先生效。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("override me", encoding="utf-8")

            encrypted_batch = encrypt_batch_files(
                [plain_source],
                {plain_source: "original-pass"},
                metadata_password="meta-pass",
                output_dir=temp_root / "encrypted",
                batch_id="override-batch",
            )

            result = decrypt_batch_files(
                encrypted_batch.encrypted_files,
                encrypted_batch.manifest_path,
                encrypted_batch.password_table_path,
                encrypted_batch.template_path,
                metadata_password="meta-pass",
                output_dir=temp_root / "decrypted",
                passwords_by_encrypted_name={"note.txt.hse": "original-pass"},
            )

            self.assertEqual(len(result.decrypted_files), 1)
            self.assertEqual(
                result.decrypted_files[0].decrypted_path.read_text(encoding="utf-8"),
                "override me",
            )

    def test_decrypt_batch_files_rejects_missing_top_level_entry(self) -> None:
        """顶层 manifest 校验应在部分解密开始前失败。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_a = temp_root / "a.txt"
            source_b = temp_root / "b.txt"
            source_a.write_text("alpha", encoding="utf-8")
            source_b.write_text("beta", encoding="utf-8")

            encrypted_batch = encrypt_batch_files(
                [source_a, source_b],
                {source_a: "pw-a", source_b: "pw-b"},
                metadata_password="meta-pass",
                output_dir=temp_root / "encrypted",
                batch_id="integrity-batch",
            )

            with self.assertRaises(IntegrityValidationError):
                decrypt_batch_files(
                    encrypted_batch.encrypted_files[:-1],
                    encrypted_batch.manifest_path,
                    encrypted_batch.password_table_path,
                    encrypted_batch.template_path,
                    metadata_password="meta-pass",
                    output_dir=temp_root / "decrypted",
                )


if __name__ == "__main__":
    unittest.main()
