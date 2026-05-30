import unittest

from high_security_encryptor.hse2 import (
    HSE2_KEYFILE_MIN_SIZE,
    HSE2_KEY_SIZE,
    HSE2ModelError,
    derive_kek_from_keyfile,
    validate_keyfile_bytes,
)


class HSE2KeyfileKDFTests(unittest.TestCase):
    def test_validate_keyfile_bytes_accepts_minimum_size(self) -> None:
        material = b"k" * HSE2_KEYFILE_MIN_SIZE

        self.assertEqual(validate_keyfile_bytes(material), material)

    def test_validate_keyfile_bytes_rejects_short_material(self) -> None:
        with self.assertRaises(HSE2ModelError):
            validate_keyfile_bytes(b"k" * (HSE2_KEYFILE_MIN_SIZE - 1))

    def test_validate_keyfile_bytes_rejects_non_bytes(self) -> None:
        with self.assertRaises(HSE2ModelError):
            validate_keyfile_bytes("not-bytes")  # type: ignore[arg-type]

    def test_derive_kek_from_keyfile_is_deterministic(self) -> None:
        material = b"k" * HSE2_KEYFILE_MIN_SIZE
        first = derive_kek_from_keyfile(material)
        second = derive_kek_from_keyfile(material)

        self.assertEqual(first.kek.purpose, "KEK")
        self.assertEqual(len(first.kek.as_bytes()), HSE2_KEY_SIZE)
        self.assertEqual(first.kek.as_bytes(), second.kek.as_bytes())
        self.assertEqual(first.keyfile_size, HSE2_KEYFILE_MIN_SIZE)
        self.assertEqual(first.keyfile_sha256, second.keyfile_sha256)

    def test_derive_kek_from_keyfile_changes_with_material(self) -> None:
        first = derive_kek_from_keyfile(b"a" * HSE2_KEYFILE_MIN_SIZE)
        second = derive_kek_from_keyfile(b"b" * HSE2_KEYFILE_MIN_SIZE)

        self.assertNotEqual(first.kek.as_bytes(), second.kek.as_bytes())
        self.assertNotEqual(first.keyfile_sha256, second.keyfile_sha256)

    def test_metadata_does_not_include_raw_key_material(self) -> None:
        material = b"k" * HSE2_KEYFILE_MIN_SIZE
        result = derive_kek_from_keyfile(material)
        metadata = result.metadata()

        self.assertEqual(metadata["algorithm"], "sha256-domain-separated")
        self.assertEqual(metadata["keyfile_size"], HSE2_KEYFILE_MIN_SIZE)
        self.assertEqual(metadata["keyfile_sha256"], result.keyfile_sha256)
        self.assertNotIn("keyfile", metadata)
        self.assertNotIn("material", metadata)


if __name__ == "__main__":
    unittest.main()
