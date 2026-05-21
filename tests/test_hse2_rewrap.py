"""Tests for experimental HSE2 rewrap helpers."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2_rewrap import (
    build_rewrapped_hse2_header,
    read_hse2_rewrap_source,
    rewrap_hse2_file,
)
from high_security_encryptor.hse2_streaming import decrypt_streaming_hse2, encrypt_streaming_hse2, read_hse2_header_frame
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED
from high_security_encryptor.streaming_primitives import IntegrityError

TEST_KDF_PROFILE = KDF_PROFILE_COMPATIBLE


class HSE2RewrapTests(unittest.TestCase):
    def test_rewrap_allows_new_secret_and_rejects_old_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            restored = root / "restored.bin"
            source.write_bytes((b"payload" * 1000) + b"tail")

            encrypt_streaming_hse2(
                source,
                encrypted,
                "old phrase",
                kdf_profile_name=TEST_KDF_PROFILE,
                chunk_size=128,
            )
            rewrap_hse2_file(
                encrypted,
                rewrapped,
                "old phrase",
                "new phrase",
                new_kdf_profile_name=TEST_KDF_PROFILE,
            )
            decrypt_streaming_hse2(rewrapped, restored, "new phrase")

            self.assertEqual(restored.read_bytes(), source.read_bytes())
            with self.assertRaises(IntegrityError):
                decrypt_streaming_hse2(rewrapped, root / "old-fail.bin", "old phrase")

    def test_rewrap_copies_payload_bytes_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            source.write_bytes(b"payload" * 200)

            encrypt_streaming_hse2(
                source,
                encrypted,
                "old phrase",
                kdf_profile_name=TEST_KDF_PROFILE,
                chunk_size=64,
            )
            old_header, _data_key, old_payload_offset = read_hse2_rewrap_source(encrypted, "old phrase")
            old_payload = encrypted.read_bytes()[old_payload_offset:]

            rewrap_hse2_file(
                encrypted,
                rewrapped,
                "old phrase",
                "new phrase",
                new_kdf_profile_name=TEST_KDF_PROFILE,
            )
            with rewrapped.open("rb") as handle:
                _new_header_frame, new_header = read_hse2_header_frame(handle)
                new_payload_offset = handle.tell()
            new_payload = rewrapped.read_bytes()[new_payload_offset:]

            self.assertEqual(new_payload, old_payload)
            self.assertEqual(new_header.associated_data(), old_header.associated_data())
            self.assertNotEqual(new_header.to_json_bytes(), old_header.to_json_bytes())

    def test_wrong_old_secret_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            rewrapped = root / "rewrapped.hse2"
            source.write_bytes(b"payload")
            encrypt_streaming_hse2(
                source,
                encrypted,
                "old phrase",
                kdf_profile_name=TEST_KDF_PROFILE,
                chunk_size=64,
            )

            with self.assertRaises(IntegrityError):
                rewrap_hse2_file(
                    encrypted,
                    rewrapped,
                    "wrong phrase",
                    "new phrase",
                    new_kdf_profile_name=TEST_KDF_PROFILE,
                )

    def test_build_rewrapped_header_can_change_kdf_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            source.write_bytes(b"payload")
            encrypt_streaming_hse2(
                source,
                encrypted,
                "old phrase",
                kdf_profile_name=TEST_KDF_PROFILE,
                chunk_size=64,
            )
            old_header, data_key, _payload_offset = read_hse2_rewrap_source(encrypted, "old phrase")

            new_header = build_rewrapped_hse2_header(
                old_header,
                data_key,
                "new phrase",
                new_kdf_profile_name=KDF_PROFILE_HARDENED,
            )

            self.assertEqual(new_header.kdf.name, KDF_PROFILE_HARDENED)
            self.assertEqual(new_header.associated_data(), old_header.associated_data())


if __name__ == "__main__":
    unittest.main()
