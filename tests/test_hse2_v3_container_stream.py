from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import struct
import tempfile
import unittest

from high_security_encryptor.atomic_io import atomic_output_path, write_bytes_atomically
from high_security_encryptor.hse2 import (
    HSE2Header,
    HSE2ModelError,
    PayloadLayout,
    attach_header_auth_tag,
    decode_header_frame,
    decrypt_manifest,
    decrypt_payload_chunk,
    encrypt_manifest,
    encrypt_payload_chunk,
    encode_header_frame,
    generate_dek,
    generate_mek,
    require_valid_header_auth_tag,
)
from high_security_encryptor.hse2.container_stream import (
    V3_CHUNK_MAGIC,
    V3_MANIFEST_MAGIC,
    V3_MAX_CHUNK_SIZE,
    V3_MAX_HEADER_SIZE,
    V3_MAX_MANIFEST_SIZE,
    read_v3_header_frame,
    read_v3_manifest_record,
    read_v3_payload_chunk_record,
    iter_v3_payload_chunk_records,
    require_v3_eof,
    write_v3_manifest_record,
    write_v3_payload_chunk_record,
    write_v3_header_frame,
)


class _ShortReader(BytesIO):
    def __init__(self, data: bytes, max_read: int = 3) -> None:
        super().__init__(data)
        self.max_read = max_read
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if size < 0:
            size = self.max_read
        return super().read(min(size, self.max_read))


class _ShortWriter(BytesIO):
    def __init__(self, max_write: int = 5) -> None:
        super().__init__()
        self.max_write = max_write

    def write(self, data: bytes | memoryview) -> int:
        return super().write(data[: self.max_write])


class HSE2V3ContainerStreamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mek = generate_mek()
        self.dek = generate_dek()
        self.manifest = encrypt_manifest({"entries": [{"path": "a.txt", "size": 5}]}, mek=self.mek)
        self.chunk = encrypt_payload_chunk(b"hello", dek=self.dek, index=0)

    def _v3_header(self) -> HSE2Header:
        return attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-10-28T00:00:00Z",
                format_version=3,
                payload_layout=PayloadLayout(chunk_count=1, payload_offset=0, footer_offset=0),
            ),
            mek=self.mek,
        )

    def test_v3_header_frame_round_trips_and_authenticates(self) -> None:
        header = self._v3_header()
        stream = BytesIO()

        write_v3_header_frame(stream, header)
        frame = stream.getvalue()
        stream.seek(0)
        raw_frame, recovered = read_v3_header_frame(stream)

        self.assertEqual(raw_frame, frame)
        self.assertEqual(recovered.to_dict(), header.to_dict())
        require_valid_header_auth_tag(recovered, mek=self.mek)

    def test_v3_header_reader_rejects_v2_preamble_and_header_version_mismatch(self) -> None:
        v2_header = HSE2Header(created_utc="2026-10-28T00:00:00Z")
        frame = bytearray(encode_header_frame(v2_header))
        frame[4] = 3

        with self.assertRaises(HSE2ModelError):
            read_v3_header_frame(BytesIO(frame))

    def test_v3_header_reader_rejects_oversized_length_before_reading_header(self) -> None:
        prefix = struct.pack(">4sBBHQ", b"HSE2", 3, 1, 0, V3_MAX_HEADER_SIZE + 1)
        reader = _ShortReader(prefix, max_read=64)

        with self.assertRaises(HSE2ModelError):
            read_v3_header_frame(reader)

        self.assertEqual(reader.read_sizes, [16])

    def test_v3_header_reader_rejects_truncated_header(self) -> None:
        frame = BytesIO()
        write_v3_header_frame(frame, self._v3_header())

        with self.assertRaises(HSE2ModelError):
            read_v3_header_frame(BytesIO(frame.getvalue()[:-1]))

    def test_v3_header_reader_rejects_noncanonical_json(self) -> None:
        frame = BytesIO()
        write_v3_header_frame(frame, self._v3_header())
        encoded = frame.getvalue()
        header_dict = json.loads(encoded[16:].decode("utf-8"))
        noncanonical = json.dumps(header_dict, indent=1).encode("utf-8")
        tampered = struct.pack(">4sBBHQ", b"HSE2", 3, 1, 0, len(noncanonical)) + noncanonical

        with self.assertRaises(HSE2ModelError):
            read_v3_header_frame(BytesIO(tampered))

    def test_existing_v2_header_codec_still_round_trips(self) -> None:
        header = HSE2Header(created_utc="2026-10-28T00:00:00Z")

        preamble, recovered, trailing = decode_header_frame(encode_header_frame(header) + b"v2-body")

        self.assertEqual(preamble.format_version, 2)
        self.assertEqual(recovered.to_dict(), header.to_dict())
        self.assertEqual(trailing, b"v2-body")

    def test_manifest_record_round_trips_as_raw_bytes(self) -> None:
        stream = BytesIO()

        write_v3_manifest_record(stream, self.manifest)
        encoded = stream.getvalue()
        stream.seek(0)
        recovered = read_v3_manifest_record(stream)

        self.assertEqual(encoded[:4], V3_MANIFEST_MAGIC)
        self.assertEqual(recovered, self.manifest)
        self.assertEqual(decrypt_manifest(recovered, mek=self.mek)["entries"][0]["path"], "a.txt")
        require_v3_eof(stream)

    def test_chunk_record_round_trips_and_authenticates_with_existing_aad(self) -> None:
        stream = BytesIO()

        write_v3_payload_chunk_record(stream, self.chunk)
        encoded = stream.getvalue()
        stream.seek(0)
        recovered = read_v3_payload_chunk_record(stream, expected_index=0, chunk_size=1024)

        self.assertEqual(encoded[:4], V3_CHUNK_MAGIC)
        self.assertEqual(recovered, self.chunk)
        self.assertEqual(decrypt_payload_chunk(recovered, dek=self.dek), b"hello")
        require_v3_eof(stream)

    def test_short_reads_are_completed(self) -> None:
        encoded = BytesIO()
        write_v3_payload_chunk_record(encoded, self.chunk)
        reader = _ShortReader(encoded.getvalue())

        recovered = read_v3_payload_chunk_record(reader, expected_index=0, chunk_size=1024)

        self.assertEqual(recovered, self.chunk)
        self.assertGreater(len(reader.read_sizes), 4)

    def test_short_writes_are_completed(self) -> None:
        writer = _ShortWriter()

        write_v3_payload_chunk_record(writer, self.chunk)

        reader = BytesIO(writer.getvalue())
        self.assertEqual(read_v3_payload_chunk_record(reader, expected_index=0, chunk_size=1024), self.chunk)
        require_v3_eof(reader)

    def test_chunk_reader_rejects_wrong_magic(self) -> None:
        stream = BytesIO(b"BAD!" + struct.pack(">QI", 0, 1) + bytes(12 + 1 + 16))

        with self.assertRaises(HSE2ModelError):
            read_v3_payload_chunk_record(stream, expected_index=0, chunk_size=1024)

    def test_chunk_reader_rejects_duplicate_or_skipped_index(self) -> None:
        encoded = BytesIO()
        write_v3_payload_chunk_record(encoded, self.chunk)
        data = bytearray(encoded.getvalue())
        data[4:12] = struct.pack(">Q", 1)

        with self.assertRaises(HSE2ModelError):
            read_v3_payload_chunk_record(BytesIO(data), expected_index=0, chunk_size=1024)

    def test_chunk_reader_rejects_length_above_declared_chunk_size(self) -> None:
        prefix = V3_CHUNK_MAGIC + struct.pack(">QI", 0, 6)

        with self.assertRaises(HSE2ModelError):
            read_v3_payload_chunk_record(BytesIO(prefix), expected_index=0, chunk_size=5)

    def test_chunk_reader_rejects_length_above_protocol_limit_before_reading_payload(self) -> None:
        prefix = V3_CHUNK_MAGIC + struct.pack(">QI", 0, V3_MAX_CHUNK_SIZE + 1)
        reader = _ShortReader(prefix, max_read=64)

        with self.assertRaises(HSE2ModelError):
            read_v3_payload_chunk_record(reader, expected_index=0, chunk_size=V3_MAX_CHUNK_SIZE)

        self.assertEqual(reader.read_sizes, [16])

    def test_manifest_reader_rejects_length_above_protocol_limit_before_reading_payload(self) -> None:
        prefix = V3_MANIFEST_MAGIC + struct.pack(">Q", V3_MAX_MANIFEST_SIZE + 1)
        reader = _ShortReader(prefix, max_read=64)

        with self.assertRaises(HSE2ModelError):
            read_v3_manifest_record(reader)

        self.assertEqual(reader.read_sizes, [12])

    def test_truncated_manifest_record_is_rejected_at_each_field_boundary(self) -> None:
        complete = BytesIO()
        write_v3_manifest_record(complete, self.manifest)
        encoded = complete.getvalue()

        for cut in (0, 1, 11, 12, 23, len(encoded) - 16, len(encoded) - 1):
            with self.subTest(cut=cut), self.assertRaises(HSE2ModelError):
                read_v3_manifest_record(BytesIO(encoded[:cut]))

    def test_truncated_chunk_record_is_rejected_at_each_field_boundary(self) -> None:
        complete = BytesIO()
        write_v3_payload_chunk_record(complete, self.chunk)
        encoded = complete.getvalue()

        for cut in (0, 1, 15, 16, 27, len(encoded) - 16, len(encoded) - 1):
            with self.subTest(cut=cut), self.assertRaises(HSE2ModelError):
                read_v3_payload_chunk_record(BytesIO(encoded[:cut]), expected_index=0, chunk_size=1024)

    def test_eof_check_rejects_trailing_bytes(self) -> None:
        with self.assertRaises(HSE2ModelError):
            require_v3_eof(BytesIO(b"unexpected"))

    def test_declared_chunk_sequence_reads_exact_count_and_eof(self) -> None:
        stream = BytesIO()
        write_v3_payload_chunk_record(stream, self.chunk)
        stream.seek(0)

        recovered = list(iter_v3_payload_chunk_records(stream, chunk_count=1, chunk_size=1024))

        self.assertEqual(recovered, [self.chunk])

    def test_declared_chunk_sequence_rejects_missing_record(self) -> None:
        with self.assertRaises(HSE2ModelError):
            list(iter_v3_payload_chunk_records(BytesIO(), chunk_count=1, chunk_size=1024))

    def test_declared_chunk_sequence_rejects_trailing_record_bytes(self) -> None:
        stream = BytesIO()
        write_v3_payload_chunk_record(stream, self.chunk)
        stream.write(b"trailing")
        stream.seek(0)

        with self.assertRaises(HSE2ModelError):
            list(iter_v3_payload_chunk_records(stream, chunk_count=1, chunk_size=1024))

    def test_atomic_output_replaces_target_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            target.write_bytes(b"old")

            write_bytes_atomically(target, b"complete")

            self.assertEqual(target.read_bytes(), b"complete")
            self.assertEqual(sorted(path.name for path in target.parent.iterdir()), [target.name])

    def test_atomic_output_preserves_target_and_cleans_temp_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "archive.hse2"
            target.write_bytes(b"old")

            with self.assertRaisesRegex(RuntimeError, "injected write failure"):
                with atomic_output_path(target) as temp_path:
                    temp_path.write_bytes(b"incomplete")
                    raise RuntimeError("injected write failure")

            self.assertEqual(target.read_bytes(), b"old")
            self.assertEqual(sorted(path.name for path in target.parent.iterdir()), [target.name])


if __name__ == "__main__":
    unittest.main()
