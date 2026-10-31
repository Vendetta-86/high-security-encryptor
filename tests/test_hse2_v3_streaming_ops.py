from __future__ import annotations

from io import BytesIO
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from high_security_encryptor.hse2.access_management import (
    DESTROY_ACCESS_CONFIRMATION_PHRASE,
    add_hse2_wrapper,
    destroy_hse2_access,
    list_hse2_wrappers,
    remove_hse2_wrapper,
)
from high_security_encryptor.hse2.container_stream import read_v3_header_frame
from high_security_encryptor.hse2.container_codec import HSE2_PREAMBLE_STRUCT
from high_security_encryptor.hse2.header_backup import (
    export_header_backup_from_container,
    read_header_backup,
    read_header_backup_metadata,
    restore_container_header_from_backup,
)
from high_security_encryptor.hse2.models import HSE2ModelError
from high_security_encryptor.hse2.streaming_file_io import open_v3_container
from high_security_encryptor.hse2.workflows import create_hse2_archive, open_hse2_archive


class HSE2V3StreamingOperationsTests(unittest.TestCase):
    def _create_v3(self, base: Path) -> tuple[Path, Path]:
        root = base / "source"
        root.mkdir()
        (root / "payload.bin").write_bytes(b"payload bytes" * 1000)
        keyfile = base / "archive.key"
        keyfile.write_bytes(b"k" * 32)
        archive = base / "archive.hse2"
        create_hse2_archive(
            roots=(root,),
            output_path=archive,
            keyfile_bytes=keyfile.read_bytes(),
            chunk_size=97,
            container_format_version=3,
            created_utc="2026-10-28T00:00:00Z",
        )
        return archive, keyfile

    def _body(self, path: Path) -> tuple[bytes, int]:
        data = path.read_bytes()
        _magic, version, _encoding, _reserved, header_length = HSE2_PREAMBLE_STRUCT.unpack(
            data[: HSE2_PREAMBLE_STRUCT.size]
        )
        if version == 2:
            offset = HSE2_PREAMBLE_STRUCT.size + header_length
        else:
            with BytesIO(data) as stream:
                read_v3_header_frame(stream)
                offset = stream.tell()
        return data[offset:], offset

    def _authenticate(self, path: Path, keyfile: bytes) -> None:
        from high_security_encryptor.hse2 import (
            HSE2UnlockFactors,
            require_valid_header_auth_tag,
            unlock_first_matching_wrapper,
        )

        def authenticate(header) -> None:
            unlocked = unlock_first_matching_wrapper(
                header.wrappers,
                factors=HSE2UnlockFactors(keyfile_bytes=keyfile),
            )
            require_valid_header_auth_tag(header, mek=unlocked.mek)

        with open_v3_container(path, authenticate_header=authenticate) as reader:
            reader.read_manifest()

    def test_list_v3_wrappers_reads_header_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive, _keyfile = self._create_v3(Path(temp_dir))
            with patch(
                "pathlib.Path.read_bytes",
                side_effect=AssertionError("v3 wrapper list must not decode the body"),
            ):
                result = list_hse2_wrappers(archive)
            self.assertEqual(len(result.wrappers), 1)
            self.assertEqual(result.wrappers[0].type, "keyfile")

    def test_add_and_remove_wrapper_preserve_body_and_authenticate_updated_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, keyfile = self._create_v3(base)
            added = base / "added.hse2"
            removed = base / "removed.hse2"
            original_body, original_offset = self._body(archive)
            keyfile_bytes = keyfile.read_bytes()
            original_read_bytes = Path.read_bytes

            def reject_whole_archive_read(path: Path) -> bytes:
                if path == archive:
                    raise AssertionError("wrapper operations must stream the archive body")
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", reject_whole_archive_read):
                add_hse2_wrapper(
                    archive,
                    added,
                    wrapper_id="password-2",
                    new_password="second secret",  # pragma: allowlist secret
                    unlock_keyfile_bytes=keyfile_bytes,
                    created_utc="2026-10-28T00:01:00Z",
                )
            added_body, added_offset = self._body(added)
            self.assertEqual(added_body, original_body)
            self.assertNotEqual(added_offset, original_offset)
            self.assertEqual(len(list_hse2_wrappers(added).wrappers), 2)
            self._authenticate(added, keyfile_bytes)
            restored = base / "restored-with-new-password"
            open_hse2_archive(input_path=added, output_dir=restored, password="second secret")  # pragma: allowlist secret
            self.assertEqual((restored / "source" / "payload.bin").read_bytes(), b"payload bytes" * 1000)

            with patch.object(Path, "read_bytes", reject_whole_archive_read):
                remove_hse2_wrapper(
                    added,
                    removed,
                    wrapper_id="password-2",
                    keyfile_bytes=keyfile_bytes,
                )
            self.assertEqual(self._body(removed)[0], original_body)
            self.assertEqual(len(list_hse2_wrappers(removed).wrappers), 1)
            self._authenticate(removed, keyfile_bytes)

    def test_destroy_access_preserves_v3_body_and_writes_authenticated_destroyed_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, keyfile = self._create_v3(base)
            destroyed = base / "destroyed.hse2"
            body, _ = self._body(archive)

            keyfile_bytes = keyfile.read_bytes()
            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("destroy access must stream the archive body"),
            ):
                result = destroy_hse2_access(
                    archive,
                    destroyed,
                    confirmation_phrase=DESTROY_ACCESS_CONFIRMATION_PHRASE,
                    keyfile_bytes=keyfile_bytes,
                )

            self.assertEqual(result.removed_wrapper_count, 1)
            self.assertEqual(self._body(destroyed)[0], body)
            listed = list_hse2_wrappers(destroyed)
            self.assertTrue(listed.access_destroyed)
            self.assertEqual(listed.wrappers, ())

    def test_rewrap_replaces_last_wrapper_atomically_and_preserves_v3_body(self) -> None:
        from high_security_encryptor.hse2.access_management import rewrap_hse2_wrapper

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, old_keyfile = self._create_v3(base)
            old_wrapper_id = list_hse2_wrappers(archive).wrappers[0].id
            rotated = base / "rotated.hse2"
            source_body, _source_offset = self._body(archive)

            result = rewrap_hse2_wrapper(
                archive,
                rotated,
                replaced_wrapper_id=old_wrapper_id,
                new_wrapper_id=old_wrapper_id,
                new_password="replacement password",  # pragma: allowlist secret
                unlock_keyfile_bytes=old_keyfile.read_bytes(),
            )

            self.assertEqual(result.original_wrapper_count, 1)
            self.assertEqual(result.resulting_wrapper_count, 1)
            self.assertEqual(self._body(rotated)[0], source_body)
            self.assertEqual(tuple(item.id for item in list_hse2_wrappers(rotated).wrappers), (old_wrapper_id,))
            with self.assertRaises(HSE2ModelError):
                open_hse2_archive(input_path=rotated, output_dir=base / "old-key-fails", keyfile_bytes=old_keyfile.read_bytes())
            restored = base / "new-password-opens"
            open_hse2_archive(input_path=rotated, output_dir=restored, password="replacement password")  # pragma: allowlist secret
            self.assertEqual((restored / "source" / "payload.bin").read_bytes(), b"payload bytes" * 1000)

    def test_failed_rewrap_preserves_existing_target_and_cleans_temp_file(self) -> None:
        from high_security_encryptor.hse2.access_management import rewrap_hse2_wrapper

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, keyfile = self._create_v3(base)
            wrapper_id = list_hse2_wrappers(archive).wrappers[0].id
            target = base / "failed-rewrap.hse2"
            target.write_bytes(b"old target")

            with patch(
                "high_security_encryptor.hse2.access_management.write_v3_header_frame",
                side_effect=HSE2ModelError("injected rewrap write failure"),
            ):
                with self.assertRaisesRegex(HSE2ModelError, "injected rewrap write failure"):
                    rewrap_hse2_wrapper(
                        archive, target, replaced_wrapper_id=wrapper_id, new_wrapper_id="password-2",
                        new_password="replacement password", unlock_keyfile_bytes=keyfile.read_bytes(), overwrite=True,  # pragma: allowlist secret
                    )

            self.assertEqual(target.read_bytes(), b"old target")
            self.assertEqual(list(base.glob(f".{target.name}.*.tmp")), [])

    def test_failed_rewrap_preserves_existing_target_and_cleans_staging_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, keyfile = self._create_v3(base)
            target = base / "failed.hse2"
            target.write_bytes(b"old target")

            with patch(
                "high_security_encryptor.hse2.access_management.write_v3_header_frame",
                side_effect=HSE2ModelError("injected header write failure"),
            ):
                with self.assertRaisesRegex(HSE2ModelError, "injected header write failure"):
                    add_hse2_wrapper(
                        archive,
                        target,
                        wrapper_id="password-2",
                        new_password="second secret",  # pragma: allowlist secret
                        unlock_keyfile_bytes=keyfile.read_bytes(),
                        overwrite=True,
                    )

            self.assertEqual(target.read_bytes(), b"old target")
            self.assertEqual(list(base.glob(f".{target.name}.*.tmp")), [])

    def test_v3_header_backup_streams_digest_and_restores_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, keyfile = self._create_v3(base)
            backup = base / "archive.header-backup"
            restored = base / "restored.hse2"
            original_body, body_offset = self._body(archive)
            with patch(
                "high_security_encryptor.hse2.header_backup.read_container_bytes",
                side_effect=AssertionError("path backup operations must stream the container body"),
            ):
                header, metadata = export_header_backup_from_container(
                    container_path=archive,
                    backup_path=backup,
                )
                self.assertEqual(metadata.format, "HSE2-header-backup-metadata-v3")
                self.assertEqual(metadata.body_offset, body_offset)
                self.assertEqual(metadata.body_size, len(original_body))
                self.assertEqual(metadata.body_sha256, hashlib.sha256(original_body).hexdigest())
            damaged = base / "damaged-header.hse2"
            damaged_bytes = bytearray(archive.read_bytes())
            damaged_bytes[HSE2_PREAMBLE_STRUCT.size + 5] ^= 0x01
            damaged.write_bytes(damaged_bytes)
            with patch(
                "high_security_encryptor.hse2.header_backup.read_container_bytes",
                side_effect=lambda path: (_ for _ in ()).throw(AssertionError("container body must not be read whole"))
                if Path(path) == damaged
                else Path(path).read_bytes(),
            ):
                restore_container_header_from_backup(
                    container_path=damaged,
                    backup_path=backup,
                    output_path=restored,
                )

            self.assertEqual(self._body(restored)[0], original_body)
            self.assertEqual(read_header_backup(backup), header)
            self._authenticate(restored, keyfile.read_bytes())

    def test_v3_backup_restore_rejects_body_tamper_without_creating_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            archive, _keyfile = self._create_v3(base)
            backup = base / "archive.header-backup"
            damaged = base / "damaged.hse2"
            output = base / "restored.hse2"
            export_header_backup_from_container(container_path=archive, backup_path=backup)
            data = bytearray(archive.read_bytes())
            data[-1] ^= 0x01
            damaged.write_bytes(data)
            output.write_bytes(b"previous output")

            with self.assertRaisesRegex(HSE2ModelError, "digest"):
                restore_container_header_from_backup(
                    container_path=damaged,
                    backup_path=backup,
                    output_path=output,
                    overwrite=True,
                )

            self.assertEqual(output.read_bytes(), b"previous output")

    def test_v2_header_backup_metadata_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "legacy.bin"
            source.write_bytes(b"legacy body")
            archive = base / "archive-v2.hse2"
            create_hse2_archive(
                roots=(source,),
                output_path=archive,
                keyfile_bytes=b"k" * 32,
                chunk_size=3,
                created_utc="2026-10-28T00:00:00Z",
            )
            backup = base / "archive.header-backup"
            export_header_backup_from_container(container_path=archive, backup_path=backup)
            restored = base / "restored.hse2"
            metadata = read_header_backup_metadata(backup)
            self.assertEqual(metadata.format, "HSE2-header-backup-metadata-v1")
            restore_container_header_from_backup(
                container_path=archive,
                backup_path=backup,
                output_path=restored,
            )
            self.assertEqual(self._body(restored)[0], self._body(archive)[0])


if __name__ == "__main__":
    unittest.main()
