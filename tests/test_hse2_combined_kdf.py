import base64
import unittest

from high_security_encryptor.hse2 import (
    HSE2_KEYFILE_MIN_SIZE,
    HSE2_KDF_SALT_SIZE,
    HSE2_KEY_SIZE,
    HSE2ModelError,
    derive_kek_from_password_and_keyfile,
)


class HSE2CombinedKDFTests(unittest.TestCase):
    def test_combined_kdf_is_deterministic_with_same_inputs(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        keyfile = b"k" * HSE2_KEYFILE_MIN_SIZE
        first = derive_kek_from_password_and_keyfile(
            "password",
            keyfile,
            profile_name="compatible",
            salt=salt,
        )
        second = derive_kek_from_password_and_keyfile(
            "password",
            keyfile,
            profile_name="compatible",
            salt=salt,
        )

        self.assertEqual(first.kek.purpose, "KEK")
        self.assertEqual(len(first.kek.as_bytes()), HSE2_KEY_SIZE)
        self.assertEqual(first.kek.as_bytes(), second.kek.as_bytes())
        self.assertEqual(first.profile.name, "compatible")
        self.assertEqual(first.salt, salt)
        self.assertEqual(first.keyfile_size, HSE2_KEYFILE_MIN_SIZE)

    def test_combined_kdf_changes_with_password(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        keyfile = b"k" * HSE2_KEYFILE_MIN_SIZE
        first = derive_kek_from_password_and_keyfile("password-one", keyfile, profile_name="compatible", salt=salt)
        second = derive_kek_from_password_and_keyfile("password-two", keyfile, profile_name="compatible", salt=salt)

        self.assertNotEqual(first.kek.as_bytes(), second.kek.as_bytes())

    def test_combined_kdf_changes_with_keyfile(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        first = derive_kek_from_password_and_keyfile("password", b"a" * HSE2_KEYFILE_MIN_SIZE, profile_name="compatible", salt=salt)
        second = derive_kek_from_password_and_keyfile("password", b"b" * HSE2_KEYFILE_MIN_SIZE, profile_name="compatible", salt=salt)

        self.assertNotEqual(first.kek.as_bytes(), second.kek.as_bytes())
        self.assertNotEqual(first.keyfile_sha256, second.keyfile_sha256)

    def test_combined_kdf_generates_random_salt_when_missing(self) -> None:
        keyfile = b"k" * HSE2_KEYFILE_MIN_SIZE
        first = derive_kek_from_password_and_keyfile("password", keyfile, profile_name="compatible")
        second = derive_kek_from_password_and_keyfile("password", keyfile, profile_name="compatible")

        self.assertEqual(len(first.salt), HSE2_KDF_SALT_SIZE)
        self.assertEqual(len(second.salt), HSE2_KDF_SALT_SIZE)
        self.assertNotEqual(first.salt, second.salt)
        self.assertNotEqual(first.kek.as_bytes(), second.kek.as_bytes())

    def test_combined_kdf_rejects_short_keyfile(self) -> None:
        with self.assertRaises(HSE2ModelError):
            derive_kek_from_password_and_keyfile("password", b"k" * (HSE2_KEYFILE_MIN_SIZE - 1), profile_name="compatible")

    def test_combined_kdf_rejects_invalid_salt(self) -> None:
        with self.assertRaises(HSE2ModelError):
            derive_kek_from_password_and_keyfile("password", b"k" * HSE2_KEYFILE_MIN_SIZE, profile_name="compatible", salt=b"short")

    def test_combined_metadata_excludes_secret_material(self) -> None:
        salt = b"s" * HSE2_KDF_SALT_SIZE
        keyfile = b"k" * HSE2_KEYFILE_MIN_SIZE
        result = derive_kek_from_password_and_keyfile("password", keyfile, profile_name="compatible", salt=salt)
        metadata = result.kdf_metadata()

        self.assertEqual(metadata["mode"], "password_keyfile")
        self.assertEqual(metadata["profile"], "compatible")
        self.assertEqual(base64.b64decode(metadata["salt"]), salt)
        self.assertEqual(metadata["keyfile_size"], HSE2_KEYFILE_MIN_SIZE)
        self.assertEqual(metadata["keyfile_sha256"], result.keyfile_sha256)
        self.assertNotIn("password", metadata)
        self.assertNotIn("keyfile_material", metadata)


if __name__ == "__main__":
    unittest.main()
