import base64
import unittest

from high_security_encryptor.hse2 import (
    HSE2_KDF_SALT_SIZE,
    HSE2_KEY_SIZE,
    HSE2ModelError,
    derive_kek_from_password,
    normalize_password,
)


class HSE2PasswordKDFTests(unittest.TestCase):
    def test_normalize_password_returns_utf8_bytes(self) -> None:
        self.assertEqual(normalize_password("密碼"), "密碼".encode("utf-8"))

    def test_empty_password_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            normalize_password("")

    def test_non_string_password_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            normalize_password(b"password")  # type: ignore[arg-type]

    def test_derive_kek_from_password_is_deterministic_with_same_salt(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        first = derive_kek_from_password("correct horse battery staple", profile_name="compatible", salt=salt)
        second = derive_kek_from_password("correct horse battery staple", profile_name="compatible", salt=salt)

        self.assertEqual(first.kek.purpose, "KEK")
        self.assertEqual(len(first.kek.as_bytes()), HSE2_KEY_SIZE)
        self.assertEqual(first.kek.as_bytes(), second.kek.as_bytes())
        self.assertEqual(first.profile.name, "compatible")
        self.assertEqual(first.salt, salt)

    def test_derive_kek_changes_with_password(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        first = derive_kek_from_password("password one", profile_name="compatible", salt=salt)
        second = derive_kek_from_password("password two", profile_name="compatible", salt=salt)

        self.assertNotEqual(first.kek.as_bytes(), second.kek.as_bytes())

    def test_derive_kek_generates_random_salt_when_missing(self) -> None:
        first = derive_kek_from_password("password", profile_name="compatible")
        second = derive_kek_from_password("password", profile_name="compatible")

        self.assertEqual(len(first.salt), HSE2_KDF_SALT_SIZE)
        self.assertEqual(len(second.salt), HSE2_KDF_SALT_SIZE)
        self.assertNotEqual(first.salt, second.salt)
        self.assertNotEqual(first.kek.as_bytes(), second.kek.as_bytes())

    def test_invalid_salt_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            derive_kek_from_password("password", profile_name="compatible", salt=b"short")

    def test_kdf_metadata_includes_base64_salt_and_profile(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        result = derive_kek_from_password("password", profile_name="compatible", salt=salt)
        metadata = result.kdf_metadata()

        self.assertEqual(metadata["profile"], "compatible")
        self.assertEqual(metadata["algorithm"], "argon2id")
        self.assertEqual(base64.b64decode(metadata["salt"]), salt)


if __name__ == "__main__":
    unittest.main()
