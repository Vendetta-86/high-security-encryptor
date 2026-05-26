import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import (
    HSE2Header,
    HSE2ModelError,
    PayloadLayout,
    attach_header_auth_tag,
    build_wrapper_from_kek,
    encode_container_bytes,
    export_header_backup_bytes,
    generate_dek,
    generate_kek,
    generate_mek,
    encrypt_manifest,
    encrypt_payload_chunk,
    read_header_backup,
    require_valid_header_auth_tag,
    restore_header_from_backup_bytes,
    write_header_backup,
)


class HSE2HeaderBackupTests(unittest.TestCase):
    def _header(self):
        mek = generate_mek()
        dek = generate_dek()
        wrapper = build_wrapper_from_kek(
            wrapper_id="keyfile-1",
            wrapper_type="keyfile",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            kek=generate_kek(),
            kdf_metadata={"algorithm": "test"},
        ).record
        header = attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-05-25T00:00:00Z",
                payload_layout=PayloadLayout(chunk_count=1, payload_offset=2048, footer_offset=4096),
                wrappers=(wrapper,),
            ),
            mek=mek,
        )
        return header, dek, mek

    def test_header_backup_bytes_round_trip(self) -> None:
        header, _, mek = self._header()

        backup = export_header_backup_bytes(header)
        restored = restore_header_from_backup_bytes(backup)

        self.assertEqual(restored.to_dict(), header.to_dict())
        require_valid_header_auth_tag(restored, mek=mek)

    def test_header_backup_path_round_trip(self) -> None:
        header, _, mek = self._header()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2.header"

            write_header_backup(path, header)
            restored = read_header_backup(path)

            self.assertEqual(restored.to_dict(), header.to_dict())
            require_valid_header_auth_tag(restored, mek=mek)

    def test_header_backup_requires_auth_tag(self) -> None:
        header = HSE2Header(created_utc="2026-05-25T00:00:00Z")

        with self.assertRaises(HSE2ModelError):
            export_header_backup_bytes(header)

    def test_restore_rejects_full_container_body(self) -> None:
        header, dek, mek = self._header()
        manifest = encrypt_manifest({"entries": []}, mek=mek, context=b"backup")
        chunk = encrypt_payload_chunk(b"payload", dek=dek, index=0, context=b"backup")
        full_container = encode_container_bytes(header, manifest=manifest, payload_chunks=(chunk,))

        with self.assertRaises(HSE2ModelError):
            restore_header_from_backup_bytes(full_container)

    def test_restore_rejects_missing_header_auth_tag(self) -> None:
        header = HSE2Header(created_utc="2026-05-25T00:00:00Z")

        from high_security_encryptor.hse2 import encode_header_frame

        with self.assertRaises(HSE2ModelError):
            restore_header_from_backup_bytes(encode_header_frame(header))


if __name__ == "__main__":
    unittest.main()
