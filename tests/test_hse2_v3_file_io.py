from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
    require_valid_header_auth_tag,
)
from high_security_encryptor.hse2.streaming_file_io import open_v3_container, write_v3_container


class HSE2V3FileIOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dek = generate_dek()
        self.mek = generate_mek()
        wrapper = build_wrapper_from_kek(
            wrapper_id="keyfile-1",
            wrapper_type="keyfile",
            created_utc="2026-10-28T00:00:00Z",
            dek=self.dek,
            mek=self.mek,
            kek=generate_kek(),
            kdf_metadata={"algorithm": "test"},
        ).record
        self.chunks = (
            encrypt_payload_chunk(b"hello", dek=self.dek, index=0),
            encrypt_payload_chunk(b" world", dek=self.dek, index=1),
        )
        self.manifest_value = {
            "format": "HSE2-archive-manifest-v1",
            "entries": [{"path": "hello.txt", "size": 11}],
            "payload_ranges": [{"path": "hello.txt", "start_chunk": 0, "chunk_count": 2}],
        }
        self.manifest = encrypt_manifest(self.manifest_value, mek=self.mek)
        self.header = attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-10-28T00:00:00Z",
                format_version=3,
                payload_layout=PayloadLayout(chunk_count=2, payload_offset=0, footer_offset=0),
                wrappers=(wrapper,),
            ),
            mek=self.mek,
        )

    def _authenticate_header(self, header: HSE2Header) -> None:
        require_valid_header_auth_tag(header, mek=self.mek)

    def _open_v3_container(self, path: Path):
        return open_v3_container(path, authenticate_header=self._authenticate_header)

    def test_path_round_trip_uses_streaming_reads_and_raw_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "nested" / "archive.hse2"
            write_v3_container(target, header=self.header, manifest=self.manifest, payload_chunks=iter(self.chunks))

            with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read is forbidden")):
                with self._open_v3_container(target) as reader:
                    self.assertEqual(reader.header.format_version, 3)
                    recovered_manifest = decrypt_manifest(reader.read_manifest(), mek=self.mek)
                    self.assertEqual(recovered_manifest, self.manifest_value)
                    recovered_chunks = list(reader.iter_payload_chunks())

            self.assertEqual(recovered_chunks, list(self.chunks))
            self.assertEqual(
                b"".join(decrypt_payload_chunk(chunk, dek=self.dek) for chunk in recovered_chunks),
                b"hello world",
            )

    def test_writer_consumes_payload_iterable_incrementally(self) -> None:
        yielded: list[int] = []

        def chunks():
            for index, chunk in enumerate(self.chunks):
                yielded.append(index)
                yield chunk

        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            write_v3_container(target, header=self.header, manifest=self.manifest, payload_chunks=chunks())

        self.assertEqual(yielded, [0, 1])

    def test_writer_rejects_missing_or_extra_chunks_without_committing(self) -> None:
        invalid_sequences = (self.chunks[:1], (*self.chunks, self.chunks[0]))
        for payload_chunks in invalid_sequences:
            with self.subTest(chunk_count=len(payload_chunks)):
                with tempfile.TemporaryDirectory() as temp_dir:
                    target = Path(temp_dir) / "archive.hse2"
                    with self.assertRaises(HSE2ModelError):
                        write_v3_container(
                            target,
                            header=self.header,
                            manifest=self.manifest,
                            payload_chunks=payload_chunks,
                        )
                    self.assertFalse(target.exists())
                    self.assertEqual(list(target.parent.iterdir()), [])

    def test_writer_refuses_existing_target_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            target.write_bytes(b"preserve me")

            with self.assertRaises(HSE2ModelError):
                write_v3_container(target, header=self.header, manifest=self.manifest, payload_chunks=self.chunks)

            self.assertEqual(target.read_bytes(), b"preserve me")
            self.assertEqual(sorted(path.name for path in target.parent.iterdir()), [target.name])

    def test_writer_overwrites_existing_target_only_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            target.write_bytes(b"old")

            write_v3_container(
                target,
                header=self.header,
                manifest=self.manifest,
                payload_chunks=self.chunks,
                overwrite=True,
            )

            with self._open_v3_container(target) as reader:
                self.assertEqual(reader.read_manifest(), self.manifest)
                self.assertEqual(list(reader.iter_payload_chunks()), list(self.chunks))
            self.assertEqual(sorted(path.name for path in target.parent.iterdir()), [target.name])

    def test_writer_commits_only_after_all_records_succeed(self) -> None:
        phases = (
            "write_v3_header_frame",
            "write_v3_manifest_record",
            "write_v3_payload_chunk_record",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp_dir:
                target = Path(temp_dir) / "archive.hse2"
                target.write_bytes(b"old complete archive")
                patch_target = f"high_security_encryptor.hse2.streaming_file_io.{phase}"
                with patch(patch_target, side_effect=OSError(f"injected {phase} failure")):
                    with self.assertRaises(OSError):
                        write_v3_container(
                            target,
                            header=self.header,
                            manifest=self.manifest,
                            payload_chunks=self.chunks,
                            overwrite=True,
                        )
                self.assertEqual(target.read_bytes(), b"old complete archive")
                self.assertEqual(sorted(path.name for path in target.parent.iterdir()), [target.name])

    def test_reader_requires_manifest_before_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            write_v3_container(target, header=self.header, manifest=self.manifest, payload_chunks=self.chunks)

            with self._open_v3_container(target) as reader:
                with self.assertRaises(HSE2ModelError):
                    next(reader.iter_payload_chunks())

    def test_reader_authenticates_header_before_body_access(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            write_v3_container(target, header=self.header, manifest=self.manifest, payload_chunks=self.chunks)
            body_reader = "high_security_encryptor.hse2.streaming_file_io.read_v3_manifest_record"

            def reject_header(_header: HSE2Header) -> None:
                raise HSE2ModelError("bad header auth")

            with patch(body_reader, side_effect=AssertionError("body must not be read")):
                with self.assertRaises(HSE2ModelError):
                    with open_v3_container(target, authenticate_header=reject_header):
                        self.fail("unauthenticated header must not expose the body")

    def test_reader_rejects_truncated_chunk_and_trailing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            write_v3_container(target, header=self.header, manifest=self.manifest, payload_chunks=self.chunks)
            with target.open("rb") as stream:
                complete = stream.read()

            for malformed in (complete[:-1], complete + b"trailing"):
                with self.subTest(length=len(malformed)):
                    target.write_bytes(malformed)
                    with self._open_v3_container(target) as reader:
                        reader.read_manifest()
                        with self.assertRaises(HSE2ModelError):
                            list(reader.iter_payload_chunks())

    def test_reader_allows_empty_payload_with_exact_eof(self) -> None:
        empty_header = attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-10-28T00:00:00Z",
                format_version=3,
                payload_layout=PayloadLayout(chunk_count=0, payload_offset=0, footer_offset=0),
                wrappers=self.header.wrappers,
            ),
            mek=self.mek,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "empty.hse2"
            write_v3_container(target, header=empty_header, manifest=self.manifest, payload_chunks=())
            with self._open_v3_container(target) as reader:
                reader.read_manifest()
                self.assertEqual(list(reader.iter_payload_chunks()), [])


if __name__ == "__main__":
    unittest.main()
