from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import os
import tempfile
import unittest

from high_security_encryptor.hse2 import (
    HSE2ModelError,
    HSE2UnlockFactors,
    decrypt_manifest,
    encrypt_manifest,
    read_hse2_container,
    require_valid_header_auth_tag,
    unlock_first_matching_wrapper,
)
from high_security_encryptor.hse2.streaming_file_io import open_v3_container, write_v3_container
from high_security_encryptor.hse2.workflows import (
    _preflight_restore_targets,
    create_hse2_archive,
    open_hse2_archive,
)


class HSE2ArchiveV3OpenTests(unittest.TestCase):
    def test_restore_preflight_rejects_case_colliding_targets_on_windows(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows path normalization is not active on this platform")
        cases = (
            (
                {"path": "Readme.txt", "kind": "file"},
                {"path": "README.TXT", "kind": "file"},
            ),
            (
                {"path": "A", "kind": "file"},
                {"path": "a/child.txt", "kind": "file"},
            ),
            (
                {"path": "a/child.txt", "kind": "file"},
                {"path": "A", "kind": "file"},
            ),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "restored"
            for entries in cases:
                with self.subTest(entries=entries), self.assertRaisesRegex(
                    HSE2ModelError, "restore target|restore path"
                ):
                    _preflight_restore_targets({"entries": list(entries)}, output_dir, overwrite=True)

    def _create_v3(self, roots: tuple[Path, ...], output: Path, *, overwrite: bool = False) -> None:
        create_hse2_archive(
            roots=roots,
            output_path=output,
            keyfile_bytes=b"k" * 32,
            chunk_size=3,
            container_format_version=3,
            overwrite=overwrite,
            created_utc="2026-10-28T00:00:00Z",
        )

    def _open(self, archive: Path, destination: Path, *, keyfile: bytes = b"k" * 32, overwrite: bool = False):
        return open_hse2_archive(
            input_path=archive,
            output_dir=destination,
            keyfile_bytes=keyfile,
            overwrite=overwrite,
        )

    def test_restore_temp_dir_is_used_for_v3_atomic_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source.bin"
            source.write_bytes(b"plaintext")
            archive = base / "archive.hse2"
            destination = base / "restored"
            temp_dir_path = base / "restore-temp"
            temp_dir_path.mkdir()
            self._create_v3((source,), archive)
            previous = os.environ.get("HSE2_RESTORE_TEMP_DIR")
            os.environ["HSE2_RESTORE_TEMP_DIR"] = str(temp_dir_path)
            try:
                self._open(archive, destination)
            finally:
                if previous is None:
                    os.environ.pop("HSE2_RESTORE_TEMP_DIR", None)
                else:
                    os.environ["HSE2_RESTORE_TEMP_DIR"] = previous

            self.assertEqual((destination / "source.bin").read_bytes(), b"plaintext")
            self.assertEqual(list(temp_dir_path.iterdir()), [])

    def test_invalid_restore_temp_dir_fails_before_creating_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source.bin"
            source.write_bytes(b"plaintext")
            archive = base / "archive.hse2"
            destination = base / "restored"
            self._create_v3((source,), archive)
            previous = os.environ.get("HSE2_RESTORE_TEMP_DIR")
            os.environ["HSE2_RESTORE_TEMP_DIR"] = str(base / "missing-temp")
            try:
                with self.assertRaisesRegex(HSE2ModelError, "existing directory"):
                    self._open(archive, destination)
            finally:
                if previous is None:
                    os.environ.pop("HSE2_RESTORE_TEMP_DIR", None)
                else:
                    os.environ["HSE2_RESTORE_TEMP_DIR"] = previous
            self.assertFalse(destination.exists())

    def test_restore_temp_dir_is_used_for_v2_atomic_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source.bin"
            source.write_bytes(b"legacy plaintext")
            archive = base / "archive-v2.hse2"
            destination = base / "restored"
            temp_dir_path = base / "restore-temp"
            temp_dir_path.mkdir()
            create_hse2_archive(
                roots=(source,), output_path=archive, keyfile_bytes=b"k" * 32,
                chunk_size=3, container_format_version=2, created_utc="2026-10-28T00:00:00Z",
            )
            previous = os.environ.get("HSE2_RESTORE_TEMP_DIR")
            os.environ["HSE2_RESTORE_TEMP_DIR"] = str(temp_dir_path)
            try:
                self._open(archive, destination)
            finally:
                if previous is None:
                    os.environ.pop("HSE2_RESTORE_TEMP_DIR", None)
                else:
                    os.environ["HSE2_RESTORE_TEMP_DIR"] = previous

            self.assertEqual((destination / "source.bin").read_bytes(), b"legacy plaintext")
            self.assertEqual(list(temp_dir_path.iterdir()), [])

    def _read_archive_parts(self, archive: Path):
        factors = HSE2UnlockFactors(keyfile_bytes=b"k" * 32)
        holder = []

        def authenticate(header) -> None:
            unlocked = unlock_first_matching_wrapper(header.wrappers, factors=factors)
            require_valid_header_auth_tag(header, mek=unlocked.mek)
            holder.append(unlocked)

        with open_v3_container(archive, authenticate_header=authenticate) as reader:
            encrypted_manifest = reader.read_manifest()
            chunks = tuple(reader.iter_payload_chunks())
            manifest = decrypt_manifest(encrypted_manifest, mek=holder[0].mek)
            return reader.header, encrypted_manifest, chunks, manifest, holder[0]

    def _rewrite_manifest(self, source: Path, target: Path, manifest_value: dict) -> None:
        header, _encrypted_manifest, chunks, _manifest, unlocked = self._read_archive_parts(source)
        write_v3_container(
            target,
            header=header,
            manifest=encrypt_manifest(manifest_value, mek=unlocked.mek),
            payload_chunks=chunks,
        )

    def test_v3_round_trip_restores_empty_and_multiple_files_across_chunk_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            (root / "nested").mkdir(parents=True)
            (root / "empty.bin").write_bytes(b"")
            (root / "first.bin").write_bytes(b"abcdef")
            (root / "nested" / "last.bin").write_bytes(b"wxyz")
            archive = Path(temp_dir) / "archive.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((root,), archive)

            result = self._open(archive, destination)

            self.assertEqual(result.payload_chunk_count, 4)
            self.assertEqual((destination / "source" / "empty.bin").read_bytes(), b"")
            self.assertEqual((destination / "source" / "first.bin").read_bytes(), b"abcdef")
            self.assertEqual((destination / "source" / "nested" / "last.bin").read_bytes(), b"wxyz")

    def test_wrong_key_fails_before_creating_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"secret")
            archive = Path(temp_dir) / "archive.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((source,), archive)

            with self.assertRaises(HSE2ModelError):
                self._open(archive, destination, keyfile=b"wrong key")

            self.assertFalse(destination.exists())

    def test_header_authentication_failure_fails_before_creating_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"secret")
            archive = Path(temp_dir) / "archive.hse2"
            damaged = Path(temp_dir) / "damaged.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((source,), archive)
            header, encrypted_manifest, chunks, _manifest, _unlocked = self._read_archive_parts(archive)
            auth_tag = header.header_auth_tag
            self.assertIsNotNone(auth_tag)
            replacement = ("A" if auth_tag[0] != "A" else "B") + auth_tag[1:]
            write_v3_container(
                damaged,
                header=replace(header, header_auth_tag=replacement),
                manifest=encrypted_manifest,
                payload_chunks=chunks,
            )

            with self.assertRaises(HSE2ModelError):
                self._open(damaged, destination)

            self.assertFalse(destination.exists())

    def test_invalid_traversal_path_is_rejected_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"secret")
            archive = Path(temp_dir) / "archive.hse2"
            malicious = Path(temp_dir) / "malicious.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((source,), archive)
            _header, _encrypted_manifest, _chunks, manifest, _unlocked = self._read_archive_parts(archive)
            manifest["entries"][0]["path"] = "../outside.bin"
            manifest["payload_ranges"][0]["path"] = "../outside.bin"
            self._rewrite_manifest(archive, malicious, manifest)

            with self.assertRaisesRegex(HSE2ModelError, "unsafe archive path"):
                self._open(malicious, destination)

            self.assertFalse(destination.exists())
            self.assertFalse((Path(temp_dir) / "outside.bin").exists())

    def test_noncanonical_path_is_rejected_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"secret")
            archive = Path(temp_dir) / "archive.hse2"
            malformed = Path(temp_dir) / "malformed.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((source,), archive)
            _header, _encrypted_manifest, _chunks, manifest, _unlocked = self._read_archive_parts(archive)
            manifest["entries"][0]["path"] = "./source.bin"
            manifest["payload_ranges"][0]["path"] = "./source.bin"
            self._rewrite_manifest(archive, malformed, manifest)

            with self.assertRaisesRegex(HSE2ModelError, "unsafe archive path"):
                self._open(malformed, destination)

            self.assertFalse(destination.exists())

    def test_invalid_manifest_chunk_range_is_rejected_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"payload")
            archive = Path(temp_dir) / "archive.hse2"
            malformed = Path(temp_dir) / "malformed.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((source,), archive)
            _header, _encrypted_manifest, _chunks, manifest, _unlocked = self._read_archive_parts(archive)
            manifest["payload_ranges"][0]["chunk_count"] = 0
            self._rewrite_manifest(archive, malformed, manifest)

            with self.assertRaisesRegex(HSE2ModelError, "chunk_count does not match file size"):
                self._open(malformed, destination)

            self.assertFalse(destination.exists())

    def test_manifest_boolean_integer_fields_are_rejected_before_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"x")
            archive = Path(temp_dir) / "archive.hse2"
            self._create_v3((source,), archive)

            for section, field in (
                ("entries", "size"),
                ("payload_ranges", "size"),
                ("payload_ranges", "start_chunk"),
                ("payload_ranges", "chunk_count"),
            ):
                with self.subTest(section=section, field=field):
                    malformed = Path(temp_dir) / f"malformed-{section}-{field}.hse2"
                    destination = Path(temp_dir) / f"restore-{section}-{field}"
                    _header, _encrypted_manifest, _chunks, manifest, _unlocked = self._read_archive_parts(archive)
                    manifest[section][0][field] = True
                    self._rewrite_manifest(archive, malformed, manifest)

                    with self.assertRaises(HSE2ModelError):
                        self._open(malformed, destination)

                    self.assertFalse(destination.exists())

    def test_tampered_last_chunk_keeps_earlier_complete_file_and_discards_failed_file_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            root.mkdir()
            (root / "a.bin").write_bytes(b"first")
            (root / "b.bin").write_bytes(b"second")
            archive = Path(temp_dir) / "archive.hse2"
            damaged = Path(temp_dir) / "damaged.hse2"
            destination = Path(temp_dir) / "restored"
            self._create_v3((root,), archive)
            data = bytearray(archive.read_bytes())
            data[-1] ^= 0x01
            damaged.write_bytes(data)

            with self.assertRaises(HSE2ModelError):
                self._open(damaged, destination)

            self.assertEqual((destination / "source" / "a.bin").read_bytes(), b"first")
            self.assertFalse((destination / "source" / "b.bin").exists())
            self.assertEqual(sorted(path.name for path in (destination / "source").iterdir()), ["a.bin"])

    def test_truncation_and_trailing_bytes_fail_without_committing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"payload spanning chunks")
            archive = Path(temp_dir) / "archive.hse2"
            self._create_v3((source,), archive)
            valid = archive.read_bytes()

            for suffix, altered in (("truncated", valid[:-4]), ("trailing", valid + b"extra")):
                with self.subTest(suffix=suffix):
                    damaged = Path(temp_dir) / f"{suffix}.hse2"
                    destination = Path(temp_dir) / f"restored-{suffix}"
                    damaged.write_bytes(altered)
                    with self.assertRaises(HSE2ModelError):
                        self._open(damaged, destination)
                    self.assertFalse((destination / "source.bin").exists())

    def test_overwrite_false_preserves_existing_file_and_true_replaces_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"archive bytes")
            archive = Path(temp_dir) / "archive.hse2"
            self._create_v3((source,), archive)
            destination = Path(temp_dir) / "restored"
            target = destination / "source.bin"
            target.parent.mkdir()
            target.write_bytes(b"existing bytes")

            with self.assertRaisesRegex(HSE2ModelError, "already exists"):
                self._open(archive, destination)
            self.assertEqual(target.read_bytes(), b"existing bytes")

            self._open(archive, destination, overwrite=True)
            self.assertEqual(target.read_bytes(), b"archive bytes")

    def test_v2_open_path_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(b"legacy bytes")
            archive = Path(temp_dir) / "archive-v2.hse2"
            destination = Path(temp_dir) / "restored"
            create_hse2_archive(
                roots=(source,),
                output_path=archive,
                keyfile_bytes=b"k" * 32,
                chunk_size=3,
                created_utc="2026-10-28T00:00:00Z",
            )

            self.assertEqual(read_hse2_container(archive).header.format_version, 2)
            self._open(archive, destination)
            self.assertEqual((destination / "source.bin").read_bytes(), b"legacy bytes")


if __name__ == "__main__":
    unittest.main()
