from pathlib import Path
import sys
import tempfile
import unittest

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.api import decrypt_file_streaming, encrypt_file_streaming
from high_security_encryptor.streaming_format import HEADER_MAGIC, IntegrityError


def build_legacy_blob(data: bytes, password: str) -> bytes:
    header = b"GCM1" + bytes([1])
    salt = b"\x01" * 16
    nonce = b"\x02" * 12
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return header + salt + nonce + tag + ciphertext


class Phase1StreamingTests(unittest.TestCase):
    def test_encrypt_and_decrypt_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.bin"
            encrypted = Path(temp_dir) / "sample.hse"
            decrypted = Path(temp_dir) / "sample.out"
            payload = (b"chunked-data-" * 200000)[:3_000_000]
            source.write_bytes(payload)

            encrypt_file_streaming(source, encrypted, "secret")
            self.assertTrue(encrypted.read_bytes().startswith(HEADER_MAGIC))

            decrypt_file_streaming(encrypted, decrypted, "secret")
            self.assertEqual(decrypted.read_bytes(), payload)

    def test_encrypt_uses_unique_temporary_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.bin"
            encrypted = Path(temp_dir) / "sample.hse"
            legacy_temp_name = encrypted.with_suffix(encrypted.suffix + ".tmp")
            source.write_bytes(b"payload")
            legacy_temp_name.write_bytes(b"do-not-touch")

            encrypt_file_streaming(source, encrypted, "secret")

            self.assertEqual(legacy_temp_name.read_bytes(), b"do-not-touch")
            self.assertTrue(encrypted.exists())

    def test_failed_decrypt_does_not_remove_existing_fixed_temp_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.bin"
            encrypted = Path(temp_dir) / "sample.hse"
            decrypted = Path(temp_dir) / "sample.out"
            legacy_temp_name = decrypted.with_suffix(decrypted.suffix + ".tmp")
            source.write_bytes(b"payload")
            legacy_temp_name.write_bytes(b"do-not-touch")
            encrypt_file_streaming(source, encrypted, "right-password")

            with self.assertRaises(IntegrityError):
                decrypt_file_streaming(encrypted, decrypted, "wrong-password")

            self.assertEqual(legacy_temp_name.read_bytes(), b"do-not-touch")
            self.assertFalse(decrypted.exists())

    def test_decrypt_supports_legacy_gcm1_format(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "legacy.bin"
            target = Path(temp_dir) / "out.bin"
            source.write_bytes(build_legacy_blob(b"legacy payload", "secret"))

            decrypt_file_streaming(source, target, "secret")
            self.assertEqual(target.read_bytes(), b"legacy payload")

    def test_decrypt_detects_tampered_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.bin"
            encrypted = Path(temp_dir) / "sample.hse"
            decrypted = Path(temp_dir) / "sample.out"
            source.write_bytes(b"very secret payload" * 1024)

            encrypt_file_streaming(source, encrypted, "secret")
            blob = bytearray(encrypted.read_bytes())
            blob[-1] ^= 0x01
            encrypted.write_bytes(blob)

            with self.assertRaises(IntegrityError):
                decrypt_file_streaming(encrypted, decrypted, "secret")

    def test_decrypt_rejects_wrong_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.bin"
            encrypted = Path(temp_dir) / "sample.hse"
            decrypted = Path(temp_dir) / "sample.out"
            source.write_bytes(b"payload")

            encrypt_file_streaming(source, encrypted, "right-password")

            with self.assertRaises(IntegrityError):
                decrypt_file_streaming(encrypted, decrypted, "wrong-password")

    def test_decrypt_detects_tampered_trailer_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.bin"
            encrypted = Path(temp_dir) / "sample.hse"
            decrypted = Path(temp_dir) / "sample.out"
            source.write_bytes(b"digest-bound payload" * 4096)

            encrypt_file_streaming(source, encrypted, "secret")
            blob = bytearray(encrypted.read_bytes())
            trailer_digest_offset = len(blob) - 16 - 32
            blob[trailer_digest_offset] ^= 0x01
            encrypted.write_bytes(blob)

            with self.assertRaises(IntegrityError):
                decrypt_file_streaming(encrypted, decrypted, "secret")


if __name__ == "__main__":
    unittest.main()
