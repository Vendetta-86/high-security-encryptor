import unittest

from high_security_encryptor.hse2 import (
    EncryptedManifest,
    HSE2ModelError,
    b64decode_bytes,
    b64encode_bytes,
    decrypt_manifest,
    encrypt_manifest,
    encrypted_manifest_from_dict,
    generate_dek,
    generate_mek,
)


class HSE2ManifestCryptoTests(unittest.TestCase):
    def test_manifest_round_trips_with_mek(self) -> None:
        manifest = {
            "version": 1,
            "entries": [
                {"name": "file.txt", "size": 12, "chunks": [0]},
            ],
        }
        mek = generate_mek()

        encrypted = encrypt_manifest(manifest, mek=mek, context=b"header")
        recovered = decrypt_manifest(encrypted, mek=mek, context=b"header")

        self.assertEqual(recovered, manifest)
        self.assertNotEqual(b64decode_bytes(encrypted.ciphertext), b"file.txt")
        self.assertEqual(encrypted_manifest_from_dict(encrypted.to_dict()), encrypted)

    def test_manifest_decryption_rejects_wrong_mek(self) -> None:
        encrypted = encrypt_manifest({"entries": []}, mek=generate_mek())

        with self.assertRaises(HSE2ModelError):
            decrypt_manifest(encrypted, mek=generate_mek())

    def test_manifest_decryption_rejects_wrong_context(self) -> None:
        mek = generate_mek()
        encrypted = encrypt_manifest({"entries": []}, mek=mek, context=b"one")

        with self.assertRaises(HSE2ModelError):
            decrypt_manifest(encrypted, mek=mek, context=b"two")

    def test_manifest_encryption_requires_mek(self) -> None:
        with self.assertRaises(HSE2ModelError):
            encrypt_manifest({"entries": []}, mek=generate_dek())

    def test_manifest_decryption_requires_mek(self) -> None:
        encrypted = encrypt_manifest({"entries": []}, mek=generate_mek())

        with self.assertRaises(HSE2ModelError):
            decrypt_manifest(encrypted, mek=generate_dek())

    def test_manifest_must_be_dictionary(self) -> None:
        with self.assertRaises(HSE2ModelError):
            encrypt_manifest(["not", "dict"], mek=generate_mek())  # type: ignore[arg-type]

    def test_encrypted_manifest_rejects_invalid_lengths(self) -> None:
        with self.assertRaises(HSE2ModelError):
            EncryptedManifest(
                nonce=b64encode_bytes(b"short"),
                ciphertext=b64encode_bytes(b"ciphertext"),
                auth_tag=b64encode_bytes(b"t" * 16),
            )
        with self.assertRaises(HSE2ModelError):
            EncryptedManifest(
                nonce=b64encode_bytes(b"n" * 12),
                ciphertext=b64encode_bytes(b""),
                auth_tag=b64encode_bytes(b"t" * 16),
            )
        with self.assertRaises(HSE2ModelError):
            EncryptedManifest(
                nonce=b64encode_bytes(b"n" * 12),
                ciphertext=b64encode_bytes(b"ciphertext"),
                auth_tag=b64encode_bytes(b"short"),
            )

    def test_encrypted_manifest_from_dict_rejects_non_dict(self) -> None:
        with self.assertRaises(HSE2ModelError):
            encrypted_manifest_from_dict("not-dict")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
