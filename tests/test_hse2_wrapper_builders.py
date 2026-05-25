import unittest

from high_security_encryptor.hse2 import (
    HSE2_KEYFILE_MIN_SIZE,
    HSE2_KDF_SALT_SIZE,
    b64decode_bytes,
    build_keyfile_wrapper,
    build_password_keyfile_wrapper,
    build_password_wrapper,
    build_wrapper_from_kek,
    generate_dek,
    generate_kek,
    generate_mek,
)


class HSE2WrapperBuilderTests(unittest.TestCase):
    def test_build_wrapper_from_kek_builds_record(self) -> None:
        built = build_wrapper_from_kek(
            wrapper_id="recovery-1",
            wrapper_type="keyfile",
            created_utc="2026-05-25T00:00:00Z",
            dek=generate_dek(),
            mek=generate_mek(),
            kek=generate_kek(),
            label="recovery keyfile",
            kdf_metadata={"algorithm": "test"},
        )
        data = built.record.to_dict()

        self.assertEqual(data["id"], "recovery-1")
        self.assertEqual(data["type"], "keyfile")
        self.assertEqual(data["label"], "recovery keyfile")
        self.assertEqual(data["kdf"], {"algorithm": "test"})
        self.assertTrue(b64decode_bytes(data["nonce"]))
        self.assertTrue(b64decode_bytes(data["wrapped_keys"]["dek"]))
        self.assertTrue(b64decode_bytes(data["wrapped_keys"]["mek"]))

    def test_build_password_wrapper_uses_password_type_and_kdf_metadata(self) -> None:
        built = build_password_wrapper(
            wrapper_id="password-1",
            created_utc="2026-05-25T00:00:00Z",
            password="password",
            dek=generate_dek(),
            mek=generate_mek(),
            profile_name="compatible",
            salt=b"s" * HSE2_KDF_SALT_SIZE,
            label="main password",
        )
        data = built.record.to_dict()

        self.assertEqual(data["type"], "password")
        self.assertEqual(data["kdf"]["profile"], "compatible")
        self.assertEqual(data["label"], "main password")

    def test_build_keyfile_wrapper_uses_keyfile_type(self) -> None:
        built = build_keyfile_wrapper(
            wrapper_id="keyfile-1",
            created_utc="2026-05-25T00:00:00Z",
            keyfile_bytes=b"k" * HSE2_KEYFILE_MIN_SIZE,
            dek=generate_dek(),
            mek=generate_mek(),
        )
        data = built.record.to_dict()

        self.assertEqual(data["type"], "keyfile")
        self.assertEqual(data["kdf"]["algorithm"], "sha256-domain-separated")
        self.assertEqual(data["kdf"]["keyfile_size"], HSE2_KEYFILE_MIN_SIZE)

    def test_build_password_keyfile_wrapper_uses_combined_type(self) -> None:
        built = build_password_keyfile_wrapper(
            wrapper_id="password-keyfile-1",
            created_utc="2026-05-25T00:00:00Z",
            password="password",
            keyfile_bytes=b"k" * HSE2_KEYFILE_MIN_SIZE,
            dek=generate_dek(),
            mek=generate_mek(),
            profile_name="compatible",
            salt=b"s" * HSE2_KDF_SALT_SIZE,
        )
        data = built.record.to_dict()

        self.assertEqual(data["type"], "password_keyfile")
        self.assertEqual(data["kdf"]["mode"], "password_keyfile")
        self.assertEqual(data["kdf"]["profile"], "compatible")


if __name__ == "__main__":
    unittest.main()
