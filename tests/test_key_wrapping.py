"""Tests for HSE2 key-wrapping primitives."""

from __future__ import annotations

import unittest

from high_security_encryptor.key_wrapping import (
    DEK_LEN,
    KEY_WRAP_ALGORITHM,
    WRAPPED_KEY_VERSION,
    WrappedDataKey,
    generate_data_key,
    unwrap_data_key,
    wrap_data_key,
)
from high_security_encryptor.streaming_primitives import NONCE_LEN, TAG_LEN


class KeyWrappingTests(unittest.TestCase):
    def test_generate_data_key_returns_expected_length_and_random_values(self) -> None:
        first = generate_data_key()
        second = generate_data_key()

        self.assertEqual(len(first), DEK_LEN)
        self.assertEqual(len(second), DEK_LEN)
        self.assertNotEqual(first, second)

    def test_wrap_and_unwrap_round_trip(self) -> None:
        data_key = b"d" * DEK_LEN
        wrapping_key = b"w" * DEK_LEN
        aad = b"hse2 header context"

        wrapped = wrap_data_key(data_key, wrapping_key, associated_data=aad)
        unwrapped = unwrap_data_key(wrapped, wrapping_key, associated_data=aad)

        self.assertEqual(unwrapped, data_key)
        self.assertEqual(wrapped.algorithm, KEY_WRAP_ALGORITHM)
        self.assertEqual(wrapped.version, WRAPPED_KEY_VERSION)
        self.assertEqual(len(wrapped.nonce), NONCE_LEN)
        self.assertEqual(len(wrapped.tag), TAG_LEN)

    def test_wrong_wrapping_key_fails_authentication(self) -> None:
        data_key = b"d" * DEK_LEN
        wrapped = wrap_data_key(data_key, b"w" * DEK_LEN)

        with self.assertRaises(ValueError):
            unwrap_data_key(wrapped, b"x" * DEK_LEN)

    def test_wrong_associated_data_fails_authentication(self) -> None:
        data_key = b"d" * DEK_LEN
        wrapping_key = b"w" * DEK_LEN
        wrapped = wrap_data_key(data_key, wrapping_key, associated_data=b"expected")

        with self.assertRaises(ValueError):
            unwrap_data_key(wrapped, wrapping_key, associated_data=b"tampered")

    def test_serialization_round_trip(self) -> None:
        wrapped = wrap_data_key(b"d" * DEK_LEN, b"w" * DEK_LEN, associated_data=b"ctx")

        restored = WrappedDataKey.from_dict(wrapped.as_dict())

        self.assertEqual(restored, wrapped)

    def test_invalid_payload_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            WrappedDataKey.from_dict({"algorithm": KEY_WRAP_ALGORITHM})

    def test_invalid_key_lengths_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            wrap_data_key(b"short", b"w" * DEK_LEN)
        with self.assertRaises(ValueError):
            wrap_data_key(b"d" * DEK_LEN, b"short")

    def test_non_bytes_key_material_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            wrap_data_key("not-bytes", b"w" * DEK_LEN)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
