from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

def find_project_root(start: Path) -> Path:
    for path in (start, *start.parents):
        if (path / "src" / "high_security_encryptor").is_dir():
            return path
    raise RuntimeError("project root not found")


PROJECT_ROOT = find_project_root(Path(__file__).resolve().parent)
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.api import decrypt_file_streaming, encrypt_file_streaming
from high_security_encryptor.batch_artifacts import load_manifest_artifact, load_template_artifact
from high_security_encryptor.batch_workflow_inputs import get_encrypted_target_path
from high_security_encryptor.folder_archive import safe_extract_folder_archive
from high_security_encryptor.folder_workflow import (
    get_folder_package_target_path,
    package_folder_to_encrypted_archive,
)
from high_security_encryptor.metadata_crypto import MetadataIntegrityError
from high_security_encryptor.streaming_format import IntegrityError, encrypted_output_stream
from high_security_encryptor.streaming_primitives import CHUNK_HEADER_STRUCT, HEADER_STRUCT, MAX_CHUNK_SIZE, NONCE_LEN, SALT_LEN


class AesGcmSecurityRegressionTests(unittest.TestCase):
    def test_safe_extract_folder_archive_blocks_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            archive_path = temp_root / "evil.zip"
            output_dir = temp_root / "out"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("folder/ok.txt", "ok")
                archive.writestr("../evil.txt", "blocked")

            with self.assertRaises(ValueError):
                safe_extract_folder_archive(archive_path, output_dir)

            self.assertFalse((temp_root / "evil.txt").exists())
            self.assertFalse((output_dir / "folder").exists())

    def test_safe_extract_folder_archive_extracts_normal_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            archive_path = temp_root / "ok.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("folder/nested/file.txt", "hello")

            extracted_root = safe_extract_folder_archive(archive_path, temp_root / "out")

            self.assertEqual(extracted_root, temp_root / "out" / "folder")
            self.assertEqual((extracted_root / "nested" / "file.txt").read_text(encoding="utf-8"), "hello")

    def test_folder_package_encrypts_marked_inner_file_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder_path = temp_root / "folder"
            folder_path.mkdir()
            (folder_path / "plain.txt").write_text("plain", encoding="utf-8")
            (folder_path / "secret.txt").write_text("secret", encoding="utf-8")

            result = package_folder_to_encrypted_archive(
                folder_path,
                temp_root / "folder.zip.hse",
                folder_password="outer-password",  # pragma: allowlist secret
                metadata_password="metadata-password",  # pragma: allowlist secret
                individually_encrypted_relative_paths=["secret.txt"],
                inner_passwords_by_relative_path={"secret.txt": "child-password"},
            )
            decrypted_zip = temp_root / "folder.zip"
            decrypt_file_streaming(result.package_path, decrypted_zip, "outer-password")

            with zipfile.ZipFile(decrypted_zip, "r") as archive:
                names = set(archive.namelist())

            self.assertIn("folder/plain.txt", names)
            self.assertIn("folder/secret.txt.hse", names)
            self.assertNotIn("folder/secret.txt", names)
            self.assertIn("folder/_hse_sidecars/batch_manifest.hsm", names)
            self.assertIn("folder/_hse_sidecars/batch_template.hsm", names)

    def test_encrypted_output_stream_can_write_zip_directly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            encrypted_zip = temp_root / "streamed.zip.hse"
            decrypted_zip = temp_root / "streamed.zip"

            with encrypted_output_stream(encrypted_zip, "outer-password") as encrypted_stream:
                with zipfile.ZipFile(encrypted_stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("folder/note.txt", "hello")

            decrypt_file_streaming(encrypted_zip, decrypted_zip, "outer-password")
            with zipfile.ZipFile(decrypted_zip, "r") as archive:
                self.assertEqual(archive.read("folder/note.txt"), b"hello")

    def test_folder_package_rejects_reserved_sidecar_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder_path = temp_root / "folder"
            reserved = folder_path / "_hse_sidecars"
            reserved.mkdir(parents=True)
            (reserved / "batch_manifest.hsm").write_text("not a real sidecar", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "reserved sidecar directory"):
                package_folder_to_encrypted_archive(
                    folder_path,
                    temp_root / "folder.zip.hse",
                    folder_password="outer-password",  # pragma: allowlist secret
                    metadata_password="metadata-password",  # pragma: allowlist secret
                )

            self.assertFalse((temp_root / "folder.zip.hse").exists())

    def test_folder_package_uses_child_password_and_encrypted_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder_path = temp_root / "folder"
            folder_path.mkdir()
            (folder_path / "secret.txt").write_text("secret", encoding="utf-8")

            result = package_folder_to_encrypted_archive(
                folder_path,
                temp_root / "folder.zip.hse",
                folder_password="outer-password",  # pragma: allowlist secret
                metadata_password="metadata-password",  # pragma: allowlist secret
                individually_encrypted_relative_paths=["secret.txt"],
                inner_passwords_by_relative_path={"secret.txt": "child-password"},
            )
            decrypted_zip = temp_root / "folder.zip"
            decrypt_file_streaming(result.package_path, decrypted_zip, "outer-password")
            extracted_root = safe_extract_folder_archive(decrypted_zip, temp_root / "out")

            encrypted_secret = extracted_root / "secret.txt.hse"
            decrypted_secret = temp_root / "secret.txt"
            decrypt_file_streaming(encrypted_secret, decrypted_secret, "child-password")
            self.assertEqual(decrypted_secret.read_text(encoding="utf-8"), "secret")
            with self.assertRaises(IntegrityError):
                decrypt_file_streaming(encrypted_secret, temp_root / "wrong.txt", "outer-password")

            self.assertIsNotNone(result.internal_binding)
            manifest_path = extracted_root / result.internal_manifest_relative_path
            template_path = extracted_root / result.internal_template_relative_path
            raw_manifest = manifest_path.read_bytes()
            self.assertNotIn(b"secret.txt.hse", raw_manifest)
            self.assertNotIn(b"entries", raw_manifest)

            manifest = load_manifest_artifact(manifest_path, "metadata-password", result.internal_binding)
            template = load_template_artifact(template_path, "metadata-password", result.internal_binding)
            self.assertEqual(manifest["entries"][0]["encrypted_name"], "secret.txt.hse")
            self.assertEqual(template["rows"], [{"source_name": "secret.txt", "encrypted_name": "secret.txt.hse", "password": ""}])

            with self.assertRaises(MetadataIntegrityError):
                load_manifest_artifact(manifest_path, "wrong-metadata-password", result.internal_binding)

    def test_output_path_helpers_use_hardened_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            folder_path = temp_root / "folder"
            file_path = temp_root / "demo.txt"
            folder_path.mkdir()
            file_path.write_text("x", encoding="utf-8")

            self.assertEqual(get_folder_package_target_path(folder_path).name, "folder.zip.hse")
            self.assertEqual(get_encrypted_target_path(file_path).name, "demo.txt.hse")

    def test_decrypt_streaming_rejects_unbounded_chunk_length_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source = temp_root / "plain.txt"
            encrypted = temp_root / "plain.txt.hse"
            tampered = temp_root / "tampered.hse"
            restored = temp_root / "restored.txt"
            source.write_text("secret", encoding="utf-8")
            encrypt_file_streaming(source, encrypted, "password")

            blob = bytearray(encrypted.read_bytes())
            first_chunk_meta_offset = HEADER_STRUCT.size + SALT_LEN + NONCE_LEN
            blob[first_chunk_meta_offset : first_chunk_meta_offset + CHUNK_HEADER_STRUCT.size] = (
                CHUNK_HEADER_STRUCT.pack(0, MAX_CHUNK_SIZE + 1)
            )
            tampered.write_bytes(blob)

            with self.assertRaisesRegex(IntegrityError, "invalid chunk length"):
                decrypt_file_streaming(tampered, restored, "password")


if __name__ == "__main__":
    unittest.main()
