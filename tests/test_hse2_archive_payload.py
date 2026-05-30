import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import (
    HSE2ModelError,
    build_payload_chunks_from_file,
    build_payload_chunks_from_files,
    decrypt_payload_chunk,
    generate_dek,
)


class HSE2ArchivePayloadTests(unittest.TestCase):
    def test_build_payload_chunks_from_file_splits_and_decrypts_chunks(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "payload.bin"
            path.write_bytes(b"abcdef")

            chunks = build_payload_chunks_from_file(path, dek=dek, chunk_size=2, context=b"archive")

            self.assertEqual([chunk.index for chunk in chunks], [0, 1, 2])
            recovered = b"".join(decrypt_payload_chunk(chunk, dek=dek, context=b"archive") for chunk in chunks)
            self.assertEqual(recovered, b"abcdef")

    def test_build_payload_chunks_from_file_respects_start_index(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "payload.bin"
            path.write_bytes(b"abcd")

            chunks = build_payload_chunks_from_file(path, dek=dek, start_index=5, chunk_size=2)

            self.assertEqual([chunk.index for chunk in chunks], [5, 6])

    def test_build_payload_chunks_from_files_uses_contiguous_indexes(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first.bin"
            second = Path(temp_dir) / "second.bin"
            first.write_bytes(b"abc")
            second.write_bytes(b"defg")

            chunks = build_payload_chunks_from_files((first, second), dek=dek, chunk_size=2)

            self.assertEqual([chunk.index for chunk in chunks], [0, 1, 2, 3])
            recovered = b"".join(decrypt_payload_chunk(chunk, dek=dek) for chunk in chunks)
            self.assertEqual(recovered, b"abcdefg")

    def test_build_payload_chunks_from_file_returns_no_chunks_for_empty_file(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "empty.bin"
            path.write_bytes(b"")

            self.assertEqual(build_payload_chunks_from_file(path, dek=dek), ())

    def test_build_payload_chunks_from_file_rejects_directory(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(HSE2ModelError):
                build_payload_chunks_from_file(Path(temp_dir), dek=dek)

    def test_build_payload_chunks_from_file_rejects_missing_file(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(HSE2ModelError):
                build_payload_chunks_from_file(Path(temp_dir) / "missing.bin", dek=dek)

    def test_build_payload_chunks_from_file_rejects_invalid_start_index(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "payload.bin"
            path.write_bytes(b"abc")
            with self.assertRaises(HSE2ModelError):
                build_payload_chunks_from_file(path, dek=dek, start_index=-1)

    def test_build_payload_chunks_from_file_rejects_invalid_chunk_size(self) -> None:
        dek = generate_dek()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "payload.bin"
            path.write_bytes(b"abc")
            with self.assertRaises(HSE2ModelError):
                build_payload_chunks_from_file(path, dek=dek, chunk_size=0)

    def test_build_payload_chunks_from_files_rejects_empty_sources(self) -> None:
        with self.assertRaises(HSE2ModelError):
            build_payload_chunks_from_files((), dek=generate_dek())


if __name__ == "__main__":
    unittest.main()
