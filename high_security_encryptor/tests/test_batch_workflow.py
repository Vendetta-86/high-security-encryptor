from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.api import decrypt_file_streaming
from high_security_encryptor.batch_artifacts import (
    load_manifest_artifact,
    load_password_table_artifact,
    load_template_artifact,
)
from high_security_encryptor.batch_binding import BindingValidationError
from high_security_encryptor.batch_workflow import encrypt_batch_files, load_batch_sidecars


class BatchWorkflowTests(unittest.TestCase):
    def test_encrypt_batch_files_outputs_encrypted_files_and_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_a = temp_root / "a.txt"
            source_b = temp_root / "b.txt"
            source_a.write_text("alpha", encoding="utf-8")
            source_b.write_text("beta", encoding="utf-8")

            result = encrypt_batch_files(
                [source_a, source_b],
                {source_a: "pw-a", source_b: "pw-b"},
                metadata_password="meta-secret",
                output_dir=temp_root / "out",
                batch_id="batch-1",
            )

            self.assertEqual(len(result.encrypted_files), 2)
            self.assertTrue(all(path.exists() for path in result.encrypted_files))
            self.assertTrue(result.manifest_path.exists())
            self.assertTrue(result.password_table_path.exists())
            self.assertTrue(result.template_path.exists())

            sidecars = load_batch_sidecars(result, "meta-secret")
            self.assertEqual(sidecars["manifest"]["binding"]["batch_id"], "batch-1")
            self.assertEqual(len(sidecars["password_table"]["records"]), 2)
            self.assertEqual(len(sidecars["template"]["rows"]), 2)

    def test_cross_batch_password_table_rejected_by_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_a = temp_root / "a.txt"
            source_b = temp_root / "b.txt"
            source_a.write_text("alpha", encoding="utf-8")
            source_b.write_text("beta", encoding="utf-8")

            result_a = encrypt_batch_files(
                [source_a],
                {source_a: "pw-a"},
                metadata_password="meta-secret",
                output_dir=temp_root / "out-a",
                batch_id="batch-a",
            )
            result_b = encrypt_batch_files(
                [source_b],
                {source_b: "pw-b"},
                metadata_password="meta-secret",
                output_dir=temp_root / "out-b",
                batch_id="batch-b",
            )

            with self.assertRaises(BindingValidationError):
                load_password_table_artifact(result_b.password_table_path, "meta-secret", result_a.binding)

    def test_encrypt_batch_files_supports_folder_packages_with_inner_encrypted_files(self) -> None:
        """Folder sources should become `.zip.hse` files with embedded inner sidecars.

        This test covers the most security-sensitive folder path currently in
        scope:

        1. one folder is packaged as an encrypted outer archive
        2. one inner file is converted into an independent `.hse` member
        3. internal manifest/password-table/template sidecars are embedded
        4. after outer decryption and extraction, those sidecars can be loaded
           with the same artifact validation helpers used elsewhere
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder_source = temp_root / "docs"
            folder_source.mkdir()
            (folder_source / "plain.txt").write_text("public", encoding="utf-8")
            (folder_source / "secret.txt").write_text("hidden", encoding="utf-8")

            result = encrypt_batch_files(
                [folder_source],
                {
                    folder_source: "folder-pass",
                    (folder_source, "secret.txt"): "inner-pass",
                },
                metadata_password="meta-secret",
                output_dir=temp_root / "out",
                batch_id="folder-batch",
                individually_encrypted_files_by_folder={folder_source: ["secret.txt"]},
            )

            self.assertEqual(len(result.encrypted_files), 1)
            self.assertTrue(result.encrypted_files[0].name.endswith(".zip.hse"))
            self.assertEqual(len(result.folder_packages), 1)

            folder_package = result.folder_packages[0]
            self.assertEqual(folder_package.internal_encrypted_files, ["secret.txt.hse"])
            self.assertIsNotNone(folder_package.internal_binding)
            self.assertEqual(folder_package.internal_manifest_relative_path, "_hse_sidecars/batch_manifest.hsm")
            self.assertEqual(
                folder_package.internal_password_table_relative_path,
                "_hse_sidecars/batch_password_table.hsm",
            )
            self.assertEqual(folder_package.internal_template_relative_path, "_hse_sidecars/batch_template.hsm")

            decrypted_zip_path = temp_root / "docs.zip"
            decrypt_file_streaming(folder_package.package_path, decrypted_zip_path, "folder-pass")

            with zipfile.ZipFile(decrypted_zip_path) as zip_file:
                archived_names = set(zip_file.namelist())

            self.assertIn("docs/plain.txt", archived_names)
            self.assertIn("docs/secret.txt.hse", archived_names)
            self.assertNotIn("docs/secret.txt", archived_names)
            self.assertIn("docs/_hse_sidecars/batch_manifest.hsm", archived_names)
            self.assertIn("docs/_hse_sidecars/batch_password_table.hsm", archived_names)
            self.assertIn("docs/_hse_sidecars/batch_template.hsm", archived_names)

            extract_root = temp_root / "unzipped"
            with zipfile.ZipFile(decrypted_zip_path) as zip_file:
                zip_file.extractall(extract_root)

            package_root = extract_root / "docs"
            manifest_payload = load_manifest_artifact(
                package_root / folder_package.internal_manifest_relative_path,
                "meta-secret",
                folder_package.internal_binding,
            )
            password_table_payload = load_password_table_artifact(
                package_root / folder_package.internal_password_table_relative_path,
                "meta-secret",
                folder_package.internal_binding,
            )
            template_payload = load_template_artifact(
                package_root / folder_package.internal_template_relative_path,
                "meta-secret",
                folder_package.internal_binding,
            )

            self.assertEqual(manifest_payload["mode"], "folder_internal_selection")
            self.assertEqual(
                password_table_payload["records"][0]["encrypted_name"],
                "secret.txt.hse",
            )
            self.assertEqual(template_payload["rows"][0]["source_name"], "secret.txt")

            inner_decrypted_path = temp_root / "secret.dec.txt"
            decrypt_file_streaming(package_root / "secret.txt.hse", inner_decrypted_path, "inner-pass")
            self.assertEqual(inner_decrypted_path.read_text(encoding="utf-8"), "hidden")


if __name__ == "__main__":
    unittest.main()
