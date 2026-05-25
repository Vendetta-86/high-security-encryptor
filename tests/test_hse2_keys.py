import unittest

from high_security_encryptor.hse2 import (
    HSE2_KEY_SIZE,
    HSE2KeyMaterial,
    HSE2ModelError,
    generate_dek,
    generate_kek,
    generate_key_material,
    generate_mek,
    validate_key_bytes,
)


class HSE2KeyPrimitiveTests(unittest.TestCase):
    def test_generated_keys_have_expected_purposes_and_size(self) -> None:
        dek = generate_dek()
        mek = generate_mek()
        kek = generate_kek()

        self.assertEqual(dek.purpose, "DEK")
        self.assertEqual(mek.purpose, "MEK")
        self.assertEqual(kek.purpose, "KEK")
        self.assertEqual(len(dek.as_bytes()), HSE2_KEY_SIZE)
        self.assertEqual(len(mek.as_bytes()), HSE2_KEY_SIZE)
        self.assertEqual(len(kek.as_bytes()), HSE2_KEY_SIZE)

    def test_generated_keys_are_random(self) -> None:
        first = generate_dek()
        second = generate_dek()

        self.assertNotEqual(first.as_bytes(), second.as_bytes())

    def test_validate_key_bytes_returns_valid_key(self) -> None:
        raw = b"a" * HSE2_KEY_SIZE

        self.assertEqual(validate_key_bytes(raw, purpose="DEK"), raw)

    def test_short_key_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2KeyMaterial(purpose="DEK", value=b"short")

    def test_non_bytes_key_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2KeyMaterial(purpose="DEK", value="not-bytes")  # type: ignore[arg-type]

    def test_unknown_key_purpose_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            generate_key_material("DATA")


if __name__ == "__main__":
    unittest.main()
