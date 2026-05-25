import unittest

from high_security_encryptor.hse2 import (
    HSE2ModelError,
    WrappedKeyBlob,
    WrappedKeyPairBlobs,
    b64decode_bytes,
    b64encode_bytes,
    build_wrapper_record,
    generate_dek,
    generate_kek,
    generate_mek,
    get_kdf_profile,
    wrap_key_material,
    wrapped_blob_from_metadata,
    wrapped_blob_to_metadata,
)


class HSE2WrapperSerializationTests(unittest.TestCase):
    def test_base64_round_trip(self) -> None:
        raw = b"hello hse2"
        encoded = b64encode_bytes(raw)

        self.assertIsInstance(encoded, str)
        self.assertEqual(b64decode_bytes(encoded), raw)

    def test_invalid_base64_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            b64decode_bytes("not valid base64!", field_name="nonce")

    def test_non_bytes_base64_input_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            b64encode_bytes("not-bytes")  # type: ignore[arg-type]

    def test_wrapped_blob_metadata_round_trip(self) -> None:
        dek = generate_dek()
        kek = generate_kek()
        blob = wrap_key_material(dek, kek=kek)

        metadata = wrapped_blob_to_metadata(blob)
        restored = wrapped_blob_from_metadata(metadata)

        self.assertEqual(restored.nonce, blob.nonce)
        self.assertEqual(restored.ciphertext, blob.ciphertext)
        self.assertEqual(restored.auth_tag, blob.auth_tag)

    def test_wrapped_blob_metadata_rejects_invalid_lengths(self) -> None:
        with self.assertRaises(HSE2ModelError):
            wrapped_blob_from_metadata({"nonce": b64encode_bytes(b"short"), "ciphertext": b64encode_bytes(b"x"), "auth_tag": b64encode_bytes(b"a" * 16)})

    def test_wrapped_key_pair_requires_shared_nonce(self) -> None:
        dek = generate_dek()
        mek = generate_mek()
        kek = generate_kek()
        wrapped_dek = wrap_key_material(dek, kek=kek)
        wrapped_mek = wrap_key_material(mek, kek=kek)

        with self.assertRaises(HSE2ModelError):
            WrappedKeyPairBlobs(dek=wrapped_dek, mek=wrapped_mek)

    def test_build_wrapper_record_serializes_wrapped_keys(self) -> None:
        shared_nonce = b"n" * 12
        wrapped_dek = WrappedKeyBlob(nonce=shared_nonce, ciphertext=b"dek-cipher", auth_tag=b"d" * 16)
        wrapped_mek = WrappedKeyBlob(nonce=shared_nonce, ciphertext=b"mek-cipher", auth_tag=b"m" * 16)
        pair = WrappedKeyPairBlobs(dek=wrapped_dek, mek=wrapped_mek)
        record = build_wrapper_record(
            wrapper_id="password-1",
            wrapper_type="password",
            label="main password",
            created_utc="2026-05-25T00:00:00Z",
            wrapped_blobs=pair,
            auth_tag=b"t" * 16,
            kdf=get_kdf_profile("hardened").to_dict(salt="c2FsdA=="),
        )

        data = record.to_dict()

        self.assertEqual(data["id"], "password-1")
        self.assertEqual(data["type"], "password")
        self.assertEqual(data["label"], "main password")
        self.assertEqual(b64decode_bytes(data["nonce"]), shared_nonce)
        self.assertEqual(b64decode_bytes(data["wrapped_keys"]["dek"]), b"dek-cipher")
        self.assertEqual(b64decode_bytes(data["wrapped_keys"]["mek"]), b"mek-cipher")
        self.assertEqual(data["kdf"]["profile"], "hardened")

    def test_build_wrapper_record_keeps_dpapi_kdf_optional(self) -> None:
        shared_nonce = b"n" * 12
        pair = WrappedKeyPairBlobs(
            dek=WrappedKeyBlob(nonce=shared_nonce, ciphertext=b"dek", auth_tag=b"d" * 16),
            mek=WrappedKeyBlob(nonce=shared_nonce, ciphertext=b"mek", auth_tag=b"m" * 16),
        )
        record = build_wrapper_record(
            wrapper_id="dpapi-1",
            wrapper_type="dpapi",
            created_utc="2026-05-25T00:00:00Z",
            wrapped_blobs=pair,
            auth_tag=b"t" * 16,
        )

        self.assertNotIn("kdf", record.to_dict())


if __name__ == "__main__":
    unittest.main()
