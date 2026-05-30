import unittest

from high_security_encryptor.hse2 import (
    EncryptedPayloadChunk,
    HSE2ModelError,
    b64encode_bytes,
    decrypt_payload_chunk,
    encrypt_payload_chunk,
    encrypted_payload_chunk_from_dict,
    generate_dek,
    generate_mek,
)


class HSE2PayloadCryptoTests(unittest.TestCase):
    def test_payload_chunk_round_trips_with_dek(self) -> None:
        plaintext = b"chunk payload bytes"
        dek = generate_dek()

        encrypted = encrypt_payload_chunk(plaintext, dek=dek, index=7, context=b"payload")
        recovered = decrypt_payload_chunk(encrypted, dek=dek, context=b"payload")

        self.assertEqual(recovered, plaintext)
        self.assertEqual(encrypted.index, 7)
        self.assertNotEqual(encrypted.ciphertext, b64encode_bytes(plaintext))
        self.assertEqual(encrypted_payload_chunk_from_dict(encrypted.to_dict()), encrypted)

    def test_payload_chunk_decryption_rejects_wrong_dek(self) -> None:
        encrypted = encrypt_payload_chunk(b"chunk", dek=generate_dek(), index=0)

        with self.assertRaises(HSE2ModelError):
            decrypt_payload_chunk(encrypted, dek=generate_dek())

    def test_payload_chunk_decryption_rejects_wrong_context(self) -> None:
        dek = generate_dek()
        encrypted = encrypt_payload_chunk(b"chunk", dek=dek, index=0, context=b"one")

        with self.assertRaises(HSE2ModelError):
            decrypt_payload_chunk(encrypted, dek=dek, context=b"two")

    def test_payload_chunk_index_is_authenticated(self) -> None:
        dek = generate_dek()
        encrypted = encrypt_payload_chunk(b"chunk", dek=dek, index=1)
        tampered = EncryptedPayloadChunk(
            index=2,
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
            auth_tag=encrypted.auth_tag,
        )

        with self.assertRaises(HSE2ModelError):
            decrypt_payload_chunk(tampered, dek=dek)

    def test_payload_encryption_requires_dek(self) -> None:
        with self.assertRaises(HSE2ModelError):
            encrypt_payload_chunk(b"chunk", dek=generate_mek(), index=0)

    def test_payload_decryption_requires_dek(self) -> None:
        encrypted = encrypt_payload_chunk(b"chunk", dek=generate_dek(), index=0)

        with self.assertRaises(HSE2ModelError):
            decrypt_payload_chunk(encrypted, dek=generate_mek())

    def test_payload_plaintext_must_be_bytes_and_non_empty(self) -> None:
        with self.assertRaises(HSE2ModelError):
            encrypt_payload_chunk("not-bytes", dek=generate_dek(), index=0)  # type: ignore[arg-type]
        with self.assertRaises(HSE2ModelError):
            encrypt_payload_chunk(b"", dek=generate_dek(), index=0)

    def test_payload_index_must_be_valid(self) -> None:
        with self.assertRaises(HSE2ModelError):
            encrypt_payload_chunk(b"chunk", dek=generate_dek(), index=-1)
        with self.assertRaises(HSE2ModelError):
            encrypt_payload_chunk(b"chunk", dek=generate_dek(), index="0")  # type: ignore[arg-type]

    def test_encrypted_payload_chunk_rejects_invalid_lengths(self) -> None:
        with self.assertRaises(HSE2ModelError):
            EncryptedPayloadChunk(
                index=0,
                nonce=b64encode_bytes(b"short"),
                ciphertext=b64encode_bytes(b"ciphertext"),
                auth_tag=b64encode_bytes(b"t" * 16),
            )
        with self.assertRaises(HSE2ModelError):
            EncryptedPayloadChunk(
                index=0,
                nonce=b64encode_bytes(b"n" * 12),
                ciphertext=b64encode_bytes(b""),
                auth_tag=b64encode_bytes(b"t" * 16),
            )
        with self.assertRaises(HSE2ModelError):
            EncryptedPayloadChunk(
                index=0,
                nonce=b64encode_bytes(b"n" * 12),
                ciphertext=b64encode_bytes(b"ciphertext"),
                auth_tag=b64encode_bytes(b"short"),
            )

    def test_encrypted_payload_chunk_from_dict_validates_shape(self) -> None:
        encrypted = encrypt_payload_chunk(b"chunk", dek=generate_dek(), index=0)
        data = encrypted.to_dict()

        self.assertEqual(encrypted_payload_chunk_from_dict(data), encrypted)
        with self.assertRaises(HSE2ModelError):
            encrypted_payload_chunk_from_dict("not-dict")  # type: ignore[arg-type]
        with self.assertRaises(HSE2ModelError):
            encrypted_payload_chunk_from_dict({"index": "0"})
        with self.assertRaises(HSE2ModelError):
            encrypted_payload_chunk_from_dict({"index": 0, "nonce": 1})


if __name__ == "__main__":
    unittest.main()
