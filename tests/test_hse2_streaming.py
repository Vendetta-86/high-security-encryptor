"""Tests for experimental HSE2 streaming file helpers."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2_streaming import decrypt_streaming_hse2, encrypt_streaming_hse2, read_hse2_header_frame
from high_security_encryptor.streaming_primitives import IntegrityError


class HSE2StreamingTests(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            payload = (b"abc123" * 1000) + b"tail"
            source.write_bytes(payload)

            encrypt_streaming_hse2(source, encrypted, "unit test phrase", chunk_size=128)
            decrypt_streaming_hse2(encrypted, restored, "unit test phrase")

            self.assertEqual(restored.read_bytes(), payload)

    def test_wrong_password_fails_before_payload_decryption(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            source.write_bytes(b"payload")

            encrypt_streaming_hse2(source, encrypted, "correct phrase", chunk_size=64)

            with self.assertRaises(IntegrityError):
                decrypt_streaming_hse2(encrypted, restored, "wrong phrase")

    def test_header_tampering_fails_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            source.write_bytes(b"payload" * 100)
            encrypt_streaming_hse2(source, encrypted, "unit test phrase", chunk_size=64)
            blob = bytearray(encrypted.read_bytes())

            # Flip a byte inside the JSON header payload after the 8-byte frame prefix.
            blob[8] ^= 0x01
            encrypted.write_bytes(blob)

            with self.assertRaises(Exception):
                decrypt_streaming_hse2(encrypted, restored, "unit test phrase")

    def test_chunk_tampering_fails_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            source.write_bytes(b"payload" * 100)
            encrypt_streaming_hse2(source, encrypted, "unit test phrase", chunk_size=64)

            with encrypted.open("rb") as handle:
                _header_frame, _header = read_hse2_header_frame(handle)
                first_payload_offset = handle.tell()
            blob = bytearray(encrypted.read_bytes())
            blob[first_payload_offset + 20] ^= 0x01
            encrypted.write_bytes(blob)

            with self.assertRaises(IntegrityError):
                decrypt_streaming_hse2(encrypted, restored, "unit test phrase")

    def test_trailer_tampering_fails_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "plain.bin"
            encrypted = root / "cipher.hse2"
            restored = root / "restored.bin"
            source.write_bytes(b"payload" * 100)
            encrypt_streaming_hse2(source, encrypted, "unit test phrase", chunk_size=64)
            blob = bytearray(encrypted.read_bytes())

            blob[-1] ^= 0x01
            encrypted.write_bytes(blob)

            with self.assertRaises(IntegrityError):
                decrypt_streaming_hse2(encrypted, restored, "unit test phrase")

    def test_empty_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "empty.bin"
            encrypted = root / "empty.hse2"
            restored = root / "restored.bin"
            source.write_bytes(b"")

            encrypt_streaming_hse2(source, encrypted, "unit test phrase", chunk_size=64)
            decrypt_streaming_hse2(encrypted, restored, "unit test phrase")

            self.assertEqual(restored.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
