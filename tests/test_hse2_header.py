"""Tests for HSE2 self-describing headers."""

from __future__ import annotations

import unittest

from high_security_encryptor.hse2_header import (
    CONTENT_ALGORITHM,
    HSE2_MAGIC,
    HSE2_VERSION,
    build_header_frame,
    build_hse2_header,
    parse_header_frame,
    split_header_frame,
)
from high_security_encryptor.key_wrapping import DEK_LEN, wrap_data_key
from high_security_encryptor.kdf_profiles import KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED
from high_security_encryptor.streaming_primitives import DEFAULT_CHUNK_SIZE, NONCE_LEN


class HSE2HeaderTests(unittest.TestCase):
    def _sample_header(self):
        wrapped = wrap_data_key(b"d" * DEK_LEN, b"w" * DEK_LEN, associated_data=b"header-test")
        return build_hse2_header(
            kdf_profile_name=KDF_PROFILE_HARDENED,
            kdf_salt=b"hse2-kdf-salt-000",
            wrapped_data_key=wrapped,
            base_nonce=b"n" * NONCE_LEN,
            chunk_size=DEFAULT_CHUNK_SIZE,
        )

    def test_header_dict_is_self_describing(self) -> None:
        header = self._sample_header()
        payload = header.as_dict()

        self.assertEqual(payload["version"], HSE2_VERSION)
        self.assertEqual(payload["content_algorithm"], CONTENT_ALGORITHM)
        self.assertEqual(payload["chunk_size"], DEFAULT_CHUNK_SIZE)
        self.assertEqual(payload["kdf"]["algorithm"], "argon2id")
        self.assertEqual(payload["kdf"]["profile"], KDF_PROFILE_HARDENED)
        self.assertIn("wrapped_data_key", payload)

    def test_json_round_trip(self) -> None:
        header = self._sample_header()

        restored = type(header).from_json_bytes(header.to_json_bytes())

        self.assertEqual(restored, header)

    def test_frame_round_trip(self) -> None:
        header = self._sample_header()

        frame = build_header_frame(header)
        restored = parse_header_frame(frame)

        self.assertTrue(frame.startswith(HSE2_MAGIC))
        self.assertEqual(restored, header)

    def test_split_frame_returns_consumed_length(self) -> None:
        header = self._sample_header()
        frame = build_header_frame(header)

        json_bytes, consumed = split_header_frame(frame + b"payload")

        self.assertEqual(consumed, len(frame))
        self.assertEqual(type(header).from_json_bytes(json_bytes), header)

    def test_associated_data_is_rewrap_compatible_payload_metadata(self) -> None:
        header = self._sample_header()
        rewrapped = build_hse2_header(
            kdf_profile_name=KDF_PROFILE_COMPATIBLE,
            kdf_salt=b"different-kdf-salt",
            wrapped_data_key=wrap_data_key(b"d" * DEK_LEN, b"x" * DEK_LEN),
            base_nonce=header.base_nonce,
            chunk_size=header.chunk_size,
        )

        self.assertNotEqual(header.to_json_bytes(), rewrapped.to_json_bytes())
        self.assertEqual(header.associated_data(), rewrapped.associated_data())
        self.assertNotEqual(header.associated_data(), build_header_frame(header))

    def test_payload_associated_data_changes_for_payload_metadata(self) -> None:
        header = self._sample_header()
        changed_nonce = build_hse2_header(
            kdf_profile_name=KDF_PROFILE_HARDENED,
            kdf_salt=header.kdf_salt,
            wrapped_data_key=header.wrapped_data_key,
            base_nonce=b"m" * NONCE_LEN,
            chunk_size=header.chunk_size,
        )
        changed_chunk_size = build_hse2_header(
            kdf_profile_name=KDF_PROFILE_HARDENED,
            kdf_salt=header.kdf_salt,
            wrapped_data_key=header.wrapped_data_key,
            base_nonce=header.base_nonce,
            chunk_size=header.chunk_size // 2,
        )

        self.assertNotEqual(header.associated_data(), changed_nonce.associated_data())
        self.assertNotEqual(header.associated_data(), changed_chunk_size.associated_data())

    def test_invalid_magic_is_rejected(self) -> None:
        frame = build_header_frame(self._sample_header())

        with self.assertRaises(ValueError):
            parse_header_frame(b"BAD!" + frame[4:])

    def test_trailing_bytes_are_rejected_by_full_frame_parser(self) -> None:
        frame = build_header_frame(self._sample_header())

        with self.assertRaises(ValueError):
            parse_header_frame(frame + b"payload")

    def test_kdf_profile_parameter_mismatch_is_rejected(self) -> None:
        payload = self._sample_header().as_dict()
        payload["kdf"]["memory_cost_kib"] += 1

        with self.assertRaises(ValueError):
            type(self._sample_header()).from_dict(payload)

    def test_invalid_lengths_are_rejected(self) -> None:
        wrapped = wrap_data_key(b"d" * DEK_LEN, b"w" * DEK_LEN)

        with self.assertRaises(ValueError):
            build_hse2_header(
                kdf_profile_name=KDF_PROFILE_HARDENED,
                kdf_salt=b"short",
                wrapped_data_key=wrapped,
                base_nonce=b"n" * NONCE_LEN,
            )
        with self.assertRaises(ValueError):
            build_hse2_header(
                kdf_profile_name=KDF_PROFILE_HARDENED,
                kdf_salt=b"hse2-kdf-salt-000",
                wrapped_data_key=wrapped,
                base_nonce=b"short",
            )


if __name__ == "__main__":
    unittest.main()
