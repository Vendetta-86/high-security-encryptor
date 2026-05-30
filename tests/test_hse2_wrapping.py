import unittest

from high_security_encryptor.hse2 import (
    HSE2_WRAP_AUTH_TAG_SIZE,
    HSE2_WRAP_NONCE_SIZE,
    HSE2ModelError,
    WrappedKeyBlob,
    generate_dek,
    generate_kek,
    generate_mek,
    key_confirmation_tag,
    unwrap_key_material,
    wrap_key_material,
)


class HSE2WrappingPrimitiveTests(unittest.TestCase):
    def test_wrap_and_unwrap_dek_round_trip(self) -> None:
        dek = generate_dek()
        kek = generate_kek()

        wrapped = wrap_key_material(dek, kek=kek)
        unwrapped = unwrap_key_material(wrapped, kek=kek, purpose="DEK")

        self.assertEqual(len(wrapped.nonce), HSE2_WRAP_NONCE_SIZE)
        self.assertEqual(len(wrapped.auth_tag), HSE2_WRAP_AUTH_TAG_SIZE)
        self.assertEqual(unwrapped.purpose, "DEK")
        self.assertEqual(unwrapped.as_bytes(), dek.as_bytes())

    def test_wrap_and_unwrap_mek_round_trip(self) -> None:
        mek = generate_mek()
        kek = generate_kek()

        wrapped = wrap_key_material(mek, kek=kek)
        unwrapped = unwrap_key_material(wrapped, kek=kek, purpose="MEK")

        self.assertEqual(unwrapped.purpose, "MEK")
        self.assertEqual(unwrapped.as_bytes(), mek.as_bytes())

    def test_wrong_kek_fails_authentication(self) -> None:
        dek = generate_dek()
        wrapped = wrap_key_material(dek, kek=generate_kek())

        with self.assertRaises(HSE2ModelError):
            unwrap_key_material(wrapped, kek=generate_kek(), purpose="DEK")

    def test_wrong_purpose_fails_associated_data_check(self) -> None:
        dek = generate_dek()
        kek = generate_kek()
        wrapped = wrap_key_material(dek, kek=kek)

        with self.assertRaises(HSE2ModelError):
            unwrap_key_material(wrapped, kek=kek, purpose="MEK")

    def test_tampered_auth_tag_fails(self) -> None:
        dek = generate_dek()
        kek = generate_kek()
        wrapped = wrap_key_material(dek, kek=kek)
        tampered = WrappedKeyBlob(
            nonce=wrapped.nonce,
            ciphertext=wrapped.ciphertext,
            auth_tag=bytes([wrapped.auth_tag[0] ^ 1]) + wrapped.auth_tag[1:],
        )

        with self.assertRaises(HSE2ModelError):
            unwrap_key_material(tampered, kek=kek, purpose="DEK")

    def test_wrapping_requires_kek(self) -> None:
        with self.assertRaises(HSE2ModelError):
            wrap_key_material(generate_dek(), kek=generate_dek())

    def test_unwrapping_requires_kek(self) -> None:
        dek = generate_dek()
        wrapped = wrap_key_material(dek, kek=generate_kek())

        with self.assertRaises(HSE2ModelError):
            unwrap_key_material(wrapped, kek=generate_dek(), purpose="DEK")

    def test_wrapped_blob_validates_lengths(self) -> None:
        with self.assertRaises(HSE2ModelError):
            WrappedKeyBlob(nonce=b"short", ciphertext=b"cipher", auth_tag=b"a" * HSE2_WRAP_AUTH_TAG_SIZE)

        with self.assertRaises(HSE2ModelError):
            WrappedKeyBlob(nonce=b"a" * HSE2_WRAP_NONCE_SIZE, ciphertext=b"", auth_tag=b"a" * HSE2_WRAP_AUTH_TAG_SIZE)

        with self.assertRaises(HSE2ModelError):
            WrappedKeyBlob(nonce=b"a" * HSE2_WRAP_NONCE_SIZE, ciphertext=b"cipher", auth_tag=b"short")

    def test_key_confirmation_tag_is_stable_for_same_context(self) -> None:
        kek = generate_kek()
        first = key_confirmation_tag(kek=kek, context=b"wrapper-1")
        second = key_confirmation_tag(kek=kek, context=b"wrapper-1")
        different_context = key_confirmation_tag(kek=kek, context=b"wrapper-2")

        self.assertEqual(first, second)
        self.assertNotEqual(first, different_context)

    def test_key_confirmation_requires_non_empty_context(self) -> None:
        with self.assertRaises(HSE2ModelError):
            key_confirmation_tag(kek=generate_kek(), context=b"")


if __name__ == "__main__":
    unittest.main()
