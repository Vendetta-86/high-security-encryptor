from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.batch_artifacts import (
    load_manifest_artifact,
    load_password_table_artifact,
    load_template_artifact,
    write_manifest_artifact,
    write_password_table_artifact,
    write_template_artifact,
)
from high_security_encryptor.batch_binding import BindingValidationError
from high_security_encryptor.batch_payloads import PasswordRecord


class BatchArtifactTests(unittest.TestCase):
    def test_password_table_artifact_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "passwords.hsm"
            binding = write_password_table_artifact(
                artifact_path,
                [PasswordRecord("a.txt", "a.txt.gcm", "pw-1")],
                ["a.txt.gcm"],
                password="metadata-secret",
                batch_id="batch-1",
            )

            payload = load_password_table_artifact(artifact_path, "metadata-secret", binding)

            self.assertEqual(payload["kind"], "password_table")
            self.assertEqual(payload["records"][0]["encrypted_name"], "a.txt.gcm")

    def test_template_artifact_rejects_cross_batch_load(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path_a = Path(temp_dir) / "template-a.hsm"
            path_b = Path(temp_dir) / "template-b.hsm"
            binding_a = write_template_artifact(
                path_a,
                ["a.txt"],
                ["a.txt.gcm"],
                password="metadata-secret",
                batch_id="batch-a",
            )
            write_template_artifact(
                path_b,
                ["b.txt"],
                ["b.txt.gcm"],
                password="metadata-secret",
                batch_id="batch-b",
            )

            with self.assertRaises(BindingValidationError):
                load_template_artifact(path_b, "metadata-secret", binding_a)

    def test_manifest_artifact_rejects_cross_batch_load(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path_a = Path(temp_dir) / "manifest-a.hsm"
            path_b = Path(temp_dir) / "manifest-b.hsm"
            binding_a = write_manifest_artifact(
                path_a,
                ["a.txt.gcm"],
                mode="bundle",
                password="metadata-secret",
                batch_id="batch-a",
            )
            write_manifest_artifact(
                path_b,
                ["b.txt.gcm"],
                mode="bundle",
                password="metadata-secret",
                batch_id="batch-b",
            )

            with self.assertRaises(BindingValidationError):
                load_manifest_artifact(path_b, "metadata-secret", binding_a)


if __name__ == "__main__":
    unittest.main()
