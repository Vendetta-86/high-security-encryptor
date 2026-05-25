from __future__ import annotations

import unittest

from high_security_encryptor.hse2.constants import AES_256_KEY_BYTES, GCM_NONCE_BYTES
from high_security_encryptor.hse2.keys import KeyBundle, generate_key_bundle
from high_security_encryptor.hse2.errors import HSE2KeyError


class HSE2KeyBundleTests(unittest.TestCase):
    def test_generated_key_bundle_has_expected_lengths(self) -> None:
        bundle = generate_key_bundle()

        self.assertEqual(len(bundle.dek), AES_256_KEY_BYTES)
        self.assertEqual(len(bundle.mek), AES_256_KEY_BYTES)
        self.assertEqual(len(bundle.payload_nonce_seed), AES_256_KEY_BYTES)
        self.assertEqual(len(bundle.manifest_nonce), GCM_NONCE_BYTES)

    def test_generated_key_bundles_are_random(self) -> None:
        first = generate_key_bundle()
        second = generate_key_bundle()

        self.assertNotEqual(first.dek, second.dek)
        self.assertNotEqual(first.mek, second.mek)
        self.assertNotEqual(first.payload_nonce_seed, second.payload_nonce_seed)
        self.assertNotEqual(first.manifest_nonce, second.manifest_nonce)

    def test_invalid_key_bundle_is_rejected(self) -> None:
        bundle = KeyBundle(
            dek=b"short",
            mek=b"0" * AES_256_KEY_BYTES,
            payload_nonce_seed=b"1" * AES_256_KEY_BYTES,
            manifest_nonce=b"2" * GCM_NONCE_BYTES,
        )

        with self.assertRaises(HSE2KeyError):
            bundle.validate()


if __name__ == "__main__":
    unittest.main()
