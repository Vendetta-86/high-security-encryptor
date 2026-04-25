from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.metadata_crypto import (
    MAX_ENCRYPTED_METADATA_BYTES,
    MAX_METADATA_PLAINTEXT_BYTES,
    MetadataIntegrityError,
    decrypt_metadata_bytes,
    encrypt_metadata_bytes,
    read_encrypted_metadata_file,
)


class MetadataCryptoTests(unittest.TestCase):
    def test_metadata_round_trip(self) -> None:
        encrypted = encrypt_metadata_bytes(b'{"kind":"manifest"}', "metadata-pass")

        self.assertEqual(decrypt_metadata_bytes(encrypted, "metadata-pass"), b'{"kind":"manifest"}')

    def test_encrypt_metadata_rejects_oversized_plaintext_before_kdf(self) -> None:
        with self.assertRaisesRegex(ValueError, "metadata payload is too large"):
            encrypt_metadata_bytes(b"x" * (MAX_METADATA_PLAINTEXT_BYTES + 1), "metadata-pass")

    def test_decrypt_metadata_rejects_oversized_blob_before_kdf(self) -> None:
        oversized_blob = b"x" * (MAX_ENCRYPTED_METADATA_BYTES + 1)

        with self.assertRaisesRegex(MetadataIntegrityError, "metadata blob is too large"):
            decrypt_metadata_bytes(oversized_blob, "metadata-pass")

    def test_read_metadata_rejects_oversized_file_before_loading_fully(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_path = Path(temp_dir) / "oversized.hsm"
            with metadata_path.open("wb") as file_obj:
                file_obj.truncate(MAX_ENCRYPTED_METADATA_BYTES + 1)

            with self.assertRaisesRegex(MetadataIntegrityError, "metadata blob is too large"):
                read_encrypted_metadata_file(metadata_path, "metadata-pass")


if __name__ == "__main__":
    unittest.main()
