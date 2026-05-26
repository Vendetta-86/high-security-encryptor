import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import (
    HSE2Header,
    HSE2ModelError,
    PayloadLayout,
    attach_header_auth_tag,
    build_wrapper_from_kek,
    decrypt_manifest,
    decrypt_payload_chunk,
    encrypt_manifest,
    encrypt_payload_chunk,
    generate_dek,
    generate_kek,
    generate_mek,
    read_container_bytes,
    read_hse2_container,
    require_valid_header_auth_tag,
    write_container_bytes,
    write_hse2_container,
)


class HSE2FileIOTests(unittest.TestCase):
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
        manifest = encrypt_manifest({"entries": [{"name": "file.txt", "chunks": [0]}]}, mek=mek, context=b"file")
        chunk = encrypt_payload_chunk(b"payload bytes", dek=dek, index=0, context=b"file")
        header = attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-05-25T00:00:00Z",
                payload_layout=PayloadLayout(chunk_count=1, payload_offset=2048, footer_offset=4096),
                wrappers=(wrapper,),
            ),
            mek=mek,
        )
        return header, manifest, (chunk,), dek, mek

    def test_write_and_read_raw_container_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2"

            write_container_bytes(path, b"raw-container")

            self.assertEqual(read_container_bytes(path), b"raw-container")

    def test_write_container_bytes_rejects_existing_target_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2"
            write_container_bytes(path, b"first")

            with self.assertRaises(HSE2ModelError):
                write_container_bytes(path, b"second")

            self.assertEqual(read_container_bytes(path), b"first")

    def test_write_container_bytes_allows_explicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2"
            write_container_bytes(path, b"first")

            write_container_bytes(path, b"second", overwrite=True)

            self.assertEqual(read_container_bytes(path), b"second")

    def test_write_container_bytes_rejects_empty_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2"

            with self.assertRaises(HSE2ModelError):
                write_container_bytes(path, b"")

    def test_read_container_bytes_rejects_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2"
            path.write_bytes(b"")

            with self.assertRaises(HSE2ModelError):
                read_container_bytes(path)

    def test_write_and_read_hse2_container(self) -> None:
        header, manifest, chunks, dek, mek = self._container_parts()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "nested" / "archive.hse2"

            write_hse2_container(path, header=header, manifest=manifest, payload_chunks=chunks)
            recovered = read_hse2_container(path)

            self.assertEqual(recovered.header.to_dict(), header.to_dict())
            self.assertEqual(recovered.manifest, manifest)
            self.assertEqual(recovered.payload_chunks, chunks)
            require_valid_header_auth_tag(recovered.header, mek=mek)
            self.assertEqual(decrypt_manifest(recovered.manifest, mek=mek, context=b"file")["entries"][0]["name"], "file.txt")
            self.assertEqual(decrypt_payload_chunk(recovered.payload_chunks[0], dek=dek, context=b"file"), b"payload bytes")


if __name__ == "__main__":
    unittest.main()
