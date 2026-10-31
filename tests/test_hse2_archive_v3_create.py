from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from high_security_encryptor.hse2 import (
    HSE2UnlockFactors,
    HSE2ModelError,
    decrypt_manifest,
    decrypt_payload_chunk,
    read_hse2_container,
    require_valid_header_auth_tag,
    unlock_first_matching_wrapper,
)
from high_security_encryptor.hse2.streaming_file_io import open_v3_container
from high_security_encryptor.hse2.workflows import create_hse2_archive


class HSE2ArchiveV3CreateTests(unittest.TestCase):
    def _create_v3(self, *, roots: tuple[Path, ...], output: Path, chunk_size: int = 3):
        return create_hse2_archive(
            roots=roots,
            output_path=output,
            keyfile_bytes=b"k" * 32,
            chunk_size=chunk_size,
            container_format_version=3,
            created_utc="2026-10-28T00:00:00Z",
        )

    def _open_and_decrypt(self, path: Path):
        factors = HSE2UnlockFactors(keyfile_bytes=b"k" * 32)
        unlocked_holder = []

        def authenticate_header(header) -> None:
            unlocked = unlock_first_matching_wrapper(header.wrappers, factors=factors)
            require_valid_header_auth_tag(header, mek=unlocked.mek)
            unlocked_holder.append(unlocked)

        with open_v3_container(path, authenticate_header=authenticate_header) as reader:
            manifest = decrypt_manifest(reader.read_manifest(), mek=unlocked_holder[0].mek)
            chunks = tuple(reader.iter_payload_chunks())
            return reader.header, manifest, chunks, unlocked_holder[0]

    def test_v3_create_streams_empty_and_multiple_files_with_contiguous_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "empty.bin").write_bytes(b"")
            (root / "first.bin").write_bytes(b"abcde")
            nested = root / "nested"
            nested.mkdir()
            (nested / "second.bin").write_bytes(b"wxyz")
            output = Path(temp_dir) / "archive.hse2"

            with patch(
                "high_security_encryptor.hse2.workflows._build_payload_chunks",
                side_effect=AssertionError("v3 creation must not materialize all chunks"),
            ):
                result = self._create_v3(roots=(root,), output=output)

            header, manifest, chunks, unlocked = self._open_and_decrypt(output)
            self.assertEqual(result.payload_chunk_count, 4)
            self.assertEqual(header.format_version, 3)
            self.assertEqual(header.payload_layout.chunk_count, 4)
            self.assertEqual([chunk.index for chunk in chunks], list(range(4)))

            file_ranges = {item["path"]: item for item in manifest["payload_ranges"]}
            self.assertEqual(file_ranges["source/empty.bin"]["chunk_count"], 0)
            self.assertEqual(file_ranges["source/first.bin"]["start_chunk"], 0)
            self.assertEqual(file_ranges["source/first.bin"]["chunk_count"], 2)
            self.assertEqual(file_ranges["source/nested/second.bin"]["start_chunk"], 2)
            self.assertEqual(file_ranges["source/nested/second.bin"]["chunk_count"], 2)

            restored_bytes = {
                "source/empty.bin": b"",
                "source/first.bin": b"abcde",
                "source/nested/second.bin": b"wxyz",
            }
            for path_key, payload_range in file_ranges.items():
                start = payload_range["start_chunk"]
                end = start + payload_range["chunk_count"]
                plaintext = b"".join(
                    decrypt_payload_chunk(chunk, dek=unlocked.dek)
                    for chunk in chunks[start:end]
                )
                self.assertEqual(plaintext, restored_bytes[path_key])

    def test_v3_create_rejects_chunk_size_above_format_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"payload")

            with self.assertRaisesRegex(HSE2ModelError, "16 MiB"):
                self._create_v3(roots=(source,), output=Path(temp_dir) / "archive.hse2", chunk_size=16 * 1024 * 1024 + 1)

    def test_source_growth_after_planning_preserves_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"abc")
            output = Path(temp_dir) / "archive.hse2"
            output.write_bytes(b"old valid target")
            real_writer = __import__(
                "high_security_encryptor.hse2.workflows",
                fromlist=["write_v3_container"],
            ).write_v3_container

            def grow_source_then_write(path, **kwargs):
                source.write_bytes(b"grew after planning")
                return real_writer(path, **kwargs)

            with patch(
                "high_security_encryptor.hse2.workflows.write_v3_container",
                side_effect=grow_source_then_write,
            ):
                with self.assertRaisesRegex(HSE2ModelError, "changed after archive planning"):
                    create_hse2_archive(
                        roots=(source,),
                        output_path=output,
                        keyfile_bytes=b"k" * 32,
                        chunk_size=3,
                        container_format_version=3,
                        overwrite=True,
                        created_utc="2026-10-28T00:00:00Z",
                    )

            self.assertEqual(output.read_bytes(), b"old valid target")
            self.assertEqual(sorted(path.name for path in output.parent.iterdir()), [output.name, source.name])

    def test_default_v2_create_remains_readable_until_open_v3_is_integrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"legacy path")
            output = Path(temp_dir) / "archive-v2.hse2"

            create_hse2_archive(
                roots=(source,),
                output_path=output,
                keyfile_bytes=b"k" * 32,
                chunk_size=4,
                created_utc="2026-10-28T00:00:00Z",
            )

            self.assertEqual(read_hse2_container(output).header.format_version, 2)


if __name__ == "__main__":
    unittest.main()
