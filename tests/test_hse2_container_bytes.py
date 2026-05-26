import unittest

from high_security_encryptor.hse2 import (
    HSE2ContainerBytes,
    HSE2Header,
    HSE2ModelError,
    PayloadLayout,
    attach_header_auth_tag,
    build_wrapper_from_kek,
    decode_container_bytes,
    decrypt_manifest,
    decrypt_payload_chunk,
    encode_container_bytes,
    encrypt_manifest,
    encrypt_payload_chunk,
    generate_dek,
    generate_kek,
    generate_mek,
    require_valid_header_auth_tag,
)


class HSE2ContainerBytesTests(unittest.TestCase):
    def _container_parts(self):
        dek = generate_dek()
        mek = generate_mek()
        wrapper = build_wrapper_from_kek(
            wrapper_id="keyfile-1",
            wrapper_type="keyfile",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            kek=generate_kek(),
            kdf_metadata={"algorithm": "test"},
        ).record
        manifest = encrypt_manifest({"entries": [{"name": "file.txt", "chunks": [0]}]}, mek=mek, context=b"container")
        chunk = encrypt_payload_chunk(b"payload bytes", dek=dek, index=0, context=b"container")
        header = attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-05-25T00:00:00Z",
                payload_layout=PayloadLayout(chunk_count=1, payload_offset=2048, footer_offset=4096),
                wrappers=(wrapper,),
            ),
            mek=mek,
        )
        return header, manifest, (chunk,), dek, mek

    def test_container_bytes_round_trips_components(self) -> None:
        header, manifest, chunks, dek, mek = self._container_parts()

        encoded = encode_container_bytes(header, manifest=manifest, payload_chunks=chunks)
        decoded = decode_container_bytes(encoded)

        self.assertIsInstance(decoded, HSE2ContainerBytes)
        self.assertEqual(decoded.header.to_dict(), header.to_dict())
        self.assertEqual(decoded.manifest, manifest)
        self.assertEqual(decoded.payload_chunks, chunks)
        require_valid_header_auth_tag(decoded.header, mek=mek)
        self.assertEqual(decrypt_manifest(decoded.manifest, mek=mek, context=b"container")["entries"][0]["name"], "file.txt")
        self.assertEqual(decrypt_payload_chunk(decoded.payload_chunks[0], dek=dek, context=b"container"), b"payload bytes")

    def test_decode_rejects_missing_body(self) -> None:
        header, _, _, _, _ = self._container_parts()

        from high_security_encryptor.hse2 import encode_header_frame

        with self.assertRaises(HSE2ModelError):
            decode_container_bytes(encode_header_frame(header))

    def test_decode_rejects_invalid_body_json(self) -> None:
        header, _, _, _, _ = self._container_parts()

        from high_security_encryptor.hse2 import encode_header_frame

        with self.assertRaises(HSE2ModelError):
            decode_container_bytes(encode_header_frame(header) + b"not-json")

    def test_decode_rejects_invalid_body_magic(self) -> None:
        header, manifest, chunks, _, _ = self._container_parts()
        encoded = encode_container_bytes(header, manifest=manifest, payload_chunks=chunks)

        tampered = encoded.replace(b"HSE2BODY\\n", b"BADBODY!\\n")
        with self.assertRaises(HSE2ModelError):
            decode_container_bytes(tampered)

    def test_decode_rejects_missing_manifest(self) -> None:
        header, _, _, _, _ = self._container_parts()

        from high_security_encryptor.hse2 import canonical_json_bytes, encode_header_frame

        body = canonical_json_bytes({"section_magic": "HSE2BODY\n", "payload_chunks": []})
        with self.assertRaises(HSE2ModelError):
            decode_container_bytes(encode_header_frame(header) + body)

    def test_decode_rejects_invalid_payload_chunks_shape(self) -> None:
        header, manifest, _, _, _ = self._container_parts()

        from high_security_encryptor.hse2 import canonical_json_bytes, encode_header_frame

        body = canonical_json_bytes({"section_magic": "HSE2BODY\n", "manifest": manifest.to_dict(), "payload_chunks": {}})
        with self.assertRaises(HSE2ModelError):
            decode_container_bytes(encode_header_frame(header) + body)


if __name__ == "__main__":
    unittest.main()
