from __future__ import annotations

import random
import unittest

from high_security_encryptor.hse2.container_v5_credentials import (
    V5CredentialSlot,
    create_v5_credentials,
    unlock_v5_credentials,
)
from high_security_encryptor.hse2.container_v5_descriptor import (
    V5_DESCRIPTOR_OVERHEAD,
    V5_MAX_FILES_PER_VIEW,
    V5_MAX_PATH_BYTES,
    V5ChunkReference,
    V5FileEntry,
    V5ViewDescriptor,
    _descriptor_aad,
    open_v5_descriptor,
    seal_v5_descriptor,
)
from high_security_encryptor.hse2.container_v5_crypto import (
    V5_GCM_NONCE_SIZE,
    V5_HKDF_SALT_SIZE,
    V5_MAX_DESCRIPTOR_SIZE,
    V5_MAX_LIVE_CHUNKS_PER_VIEW,
    V5Sealed,
    derive_v5_key,
    open_v5,
    seal_v5,
)
from high_security_encryptor.hse2.container_v5_header import (
    V5_FOOTER_SIZE,
    V5_HEADER_SIZE,
    V5Footer,
    V5FooterEntry,
    V5PublicHeader,
)
from high_security_encryptor.hse2.container_v5_records import (
    V5_RECORD_OVERHEAD,
    open_v5_record,
    seal_v5_record,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V5CodecTests(unittest.TestCase):
    def test_v5_hkdf_and_gcm_deterministic_vector(self) -> None:
        root = bytes(range(32))
        salt = bytes(range(32, 64))
        info = b"HSE2:v5:test-vector:v1"
        key = derive_v5_key(root_key=root, salt=salt, info=info)
        sealed = seal_v5(key=key, nonce=bytes(range(12)), plaintext=b"v5 vector", aad=b"HSE2:v5:test:aad")
        self.assertEqual(open_v5(key=key, sealed=sealed, aad=b"HSE2:v5:test:aad"), b"v5 vector")
        self.assertEqual(key.hex(), "ebc6c259dd4d83a0222b4c347de7576d6b7340b47d599d94096ae9fb1ddc00c2")
        self.assertEqual(sealed.ciphertext.hex(), "dbb33f61a30f46af38")
        self.assertEqual(sealed.tag.hex(), "81ba9a4c135d832feb9dbee602700976")
        with self.assertRaises(HSE2ModelError):
            open_v5(key=key, sealed=sealed, aad=b"changed")

    def test_public_header_round_trip_and_rejects_unknown_version_or_flags(self) -> None:
        slot0 = V5CredentialSlot(1, bytes(16), bytes(12), bytes(32), bytes(16))
        slot1 = V5CredentialSlot(1, bytes([1]) * 16, bytes([1]) * 12,
                                 bytes([1]) * 32, bytes([1]) * 16)
        header = V5PublicHeader(bytes(range(16)), (slot0, slot1))
        encoded = header.to_bytes()
        self.assertEqual(len(encoded), V5_HEADER_SIZE)
        self.assertEqual(V5PublicHeader.from_bytes(encoded), header)
        for offset, value in ((4, 4), (5, 1), (6, 1), (7, 1)):
            malformed = bytearray(encoded)
            malformed[offset] = value
            with self.subTest(offset=offset), self.assertRaises(HSE2ModelError):
                V5PublicHeader.from_bytes(bytes(malformed))
        with self.assertRaises(HSE2ModelError):
            V5PublicHeader.from_bytes(encoded[:-1])

    def test_footer_bounds_and_descriptor_overlap_are_rejected(self) -> None:
        views = (V5FooterEntry(V5_HEADER_SIZE, 60, 1), V5FooterEntry(V5_HEADER_SIZE + 60, 60, 1))
        footer = V5Footer(views)
        file_size = V5_HEADER_SIZE + 120 + V5_FOOTER_SIZE
        self.assertEqual(len(footer.to_bytes()), V5_FOOTER_SIZE)
        self.assertEqual(V5Footer.from_bytes(footer.to_bytes(), file_size=file_size), footer)

        overlapping = V5Footer((views[0], V5FooterEntry(V5_HEADER_SIZE + 30, 60, 1)))
        with self.assertRaisesRegex(HSE2ModelError, "overlap"):
            V5Footer.from_bytes(overlapping.to_bytes(), file_size=file_size)
        out_of_bounds = V5Footer((views[0], V5FooterEntry(file_size, 60, 1)))
        with self.assertRaisesRegex(HSE2ModelError, "bounds"):
            V5Footer.from_bytes(out_of_bounds.to_bytes(), file_size=file_size)
        with self.assertRaises(HSE2ModelError):
            V5FooterEntry(0, 60, 0)
        with self.assertRaises(HSE2ModelError):
            V5FooterEntry(1 << 64, 60, 1)

    def test_v5_credentials_unlock_only_the_bound_view(self) -> None:
        archive_id = bytes(range(16))
        slots, roots = create_v5_credentials("first view secret", "second view secret", archive_id=archive_id)
        self.assertEqual(V5CredentialSlot.from_bytes(slots[0].to_bytes()), slots[0])
        self.assertEqual(unlock_v5_credentials("first view secret", slots, archive_id=archive_id), (0, roots[0]))
        self.assertEqual(unlock_v5_credentials("second view secret", slots, archive_id=archive_id), (1, roots[1]))
        with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
            unlock_v5_credentials("wrong secret", slots, archive_id=archive_id)
        with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
            unlock_v5_credentials("first view secret", slots, archive_id=b"x" * 16)
        with self.assertRaises(HSE2ModelError):
            create_v5_credentials("same secret", "same secret", archive_id=archive_id)

    def test_variable_record_authenticates_view_sequence_offset_and_length(self) -> None:
        root = bytes(range(32))
        archive_id = bytes(range(16))
        plaintext = b"small v5 payload"
        blob = seal_v5_record(root_key=root, archive_id=archive_id, slot=1, sequence=7,
                              offset=4096, plaintext=plaintext)
        self.assertEqual(len(blob), V5_RECORD_OVERHEAD + len(plaintext))
        self.assertEqual(open_v5_record(root_key=root, archive_id=archive_id, slot=1, sequence=7,
                                        offset=4096, plaintext_length=len(plaintext), blob=blob), plaintext)
        for position in (0, V5_HKDF_SALT_SIZE,
                         V5_HKDF_SALT_SIZE + V5_GCM_NONCE_SIZE, len(blob) - 1):
            damaged = bytearray(blob)
            damaged[position] ^= 1
            with self.subTest(damaged_component=position), self.assertRaisesRegex(
                HSE2ModelError, "authentication failed"
            ):
                open_v5_record(
                    root_key=root, archive_id=archive_id, slot=1, sequence=7,
                    offset=4096, plaintext_length=len(plaintext), blob=bytes(damaged),
                )
        for view, sequence, offset, archive in ((0, 7, 4096, archive_id),
                                                (1, 8, 4096, archive_id),
                                                (1, 7, 4097, archive_id),
                                                (1, 7, 4096, b"x" * 16)):
            with self.subTest(view=view, sequence=sequence, offset=offset), self.assertRaises(HSE2ModelError):
                open_v5_record(root_key=root, archive_id=archive, slot=view, sequence=sequence,
                               offset=offset, plaintext_length=len(plaintext), blob=blob)
        with self.assertRaises(HSE2ModelError):
            open_v5_record(root_key=root, archive_id=archive_id, slot=1, sequence=7, offset=4096,
                           plaintext_length=len(plaintext) + 1, blob=blob)
        with self.assertRaises(HSE2ModelError):
            seal_v5_record(root_key=root, archive_id=archive_id, slot=1, sequence=0, offset=0, plaintext=b"")

    def test_record_round_trips_deterministic_varied_lengths_and_locations(self) -> None:
        rng = random.Random(0x56355243)
        root = bytes(range(32))
        archive_id = bytes(range(16))
        boundary_lengths = (1, 15, 16, 17, 1023, 1024, 1025, 65535, 65536, 65537,
                            1_048_575, 1_048_576)
        for index in range(48):
            slot = index % 2
            sequence = index * 3
            offset = V5_HEADER_SIZE + index * 8192
            length = boundary_lengths[index] if index < len(boundary_lengths) else 1 + rng.randrange(8192)
            plaintext = rng.randbytes(length)
            with self.subTest(index=index, length=len(plaintext)):
                blob = seal_v5_record(
                    root_key=root, archive_id=archive_id, slot=slot, sequence=sequence,
                    offset=offset, plaintext=plaintext,
                )
                self.assertEqual(
                    open_v5_record(
                        root_key=root, archive_id=archive_id, slot=slot, sequence=sequence,
                        offset=offset, plaintext_length=len(plaintext), blob=blob,
                    ),
                    plaintext,
                )

    def test_manifest_round_trips_seeded_file_chunk_shapes(self) -> None:
        rng = random.Random(0x56354D46)
        root = bytes(range(32))
        archive_id = bytes(range(16))
        cursor = V5_HEADER_SIZE
        sequence = 0
        files = []
        for file_index in range(48):
            chunks = []
            file_size = 0
            chunk_count = 0 if file_index % 7 == 0 else 1 + rng.randrange(3)
            for _ in range(chunk_count):
                length = 1 + rng.randrange(4096)
                chunks.append(V5ChunkReference(sequence, cursor, length))
                cursor += V5_RECORD_OVERHEAD + length
                file_size += length
                sequence += 1
            files.append(V5FileEntry(
                f"folder-{file_index:03}/file-{file_index:03}.bin", file_size, tuple(chunks)
            ))

        descriptor = V5ViewDescriptor(1, 3, sequence, tuple(files))
        blob = seal_v5_descriptor(
            root_key=root, archive_id=archive_id, view=descriptor, offset=cursor
        )
        decoded = open_v5_descriptor(
            root_key=root, archive_id=archive_id, slot=1, generation=3,
            offset=cursor, blob=blob,
        )
        self.assertEqual(decoded, descriptor)
        self.assertTrue(any(not item.chunks for item in decoded.files))
        self.assertGreater(len(blob), V5_DESCRIPTOR_OVERHEAD)

    def test_empty_and_populated_descriptors_are_compact_and_authenticated(self) -> None:
        root = bytes(range(32))
        archive_id = bytes(range(16))
        empty = V5ViewDescriptor(slot=0, generation=1, next_sequence=0, files=())
        empty_blob = seal_v5_descriptor(root_key=root, archive_id=archive_id, view=empty, offset=4096)
        self.assertLess(len(empty_blob), 1024)
        self.assertEqual(open_v5_descriptor(root_key=root, archive_id=archive_id, slot=0,
                                            generation=1, offset=4096, blob=empty_blob), empty)

        populated = V5ViewDescriptor(
            slot=1, generation=1, next_sequence=1,
            files=(V5FileEntry("note.txt", 3, (V5ChunkReference(0, V5_HEADER_SIZE, 3),)),),
        )
        blob = seal_v5_descriptor(root_key=root, archive_id=archive_id, view=populated, offset=4096)
        self.assertEqual(open_v5_descriptor(root_key=root, archive_id=archive_id, slot=1,
                                            generation=1, offset=4096, blob=blob), populated)
        with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
            open_v5_descriptor(root_key=root, archive_id=archive_id, slot=1,
                               generation=1, offset=4097, blob=blob)
        damaged = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
            open_v5_descriptor(root_key=root, archive_id=archive_id, slot=1,
                               generation=1, offset=4096, blob=damaged)
        for position in (0, V5_HKDF_SALT_SIZE,
                         V5_HKDF_SALT_SIZE + V5_GCM_NONCE_SIZE, len(blob) - 1):
            damaged = bytearray(blob)
            damaged[position] ^= 1
            with self.subTest(damaged_descriptor_component=position), self.assertRaisesRegex(
                HSE2ModelError, "authentication failed"
            ):
                open_v5_descriptor(
                    root_key=root, archive_id=archive_id, slot=1, generation=1,
                    offset=4096, blob=bytes(damaged),
                )
        with self.assertRaises(HSE2ModelError):
            seal_v5_descriptor(root_key=root, archive_id=archive_id, view=empty, offset=1 << 64)

    def test_descriptor_rejects_overlapping_chunks_and_file_size_mismatch(self) -> None:
        root = bytes(range(32))
        archive_id = bytes(range(16))
        bad_views = (
            V5ViewDescriptor(0, 1, 2, (V5FileEntry("a", 4, (
                V5ChunkReference(0, V5_HEADER_SIZE, 3),
                V5ChunkReference(1, V5_HEADER_SIZE + 62, 1),
            )),)),
            V5ViewDescriptor(0, 1, 1, (V5FileEntry("a", 4, (
                V5ChunkReference(0, V5_HEADER_SIZE, 3),
            )),)),
            V5ViewDescriptor(0, 1, 0, (V5FileEntry("bad\x00path", 0, ()),)),
            V5ViewDescriptor(0, 1, 0, (
                V5FileEntry("z.txt", 0, ()), V5FileEntry("a.txt", 0, ()),
            )),
            V5ViewDescriptor(0, 1, 0, (
                V5FileEntry("A.txt", 0, ()), V5FileEntry("a.txt", 0, ()),
            )),
            V5ViewDescriptor(0, 1, 0, (
                V5FileEntry("folder", 0, ()), V5FileEntry("folder/child", 0, ()),
            )),
            V5ViewDescriptor(0, 1, 1, (
                V5FileEntry("a", 1, (V5ChunkReference(0, V5_HEADER_SIZE, 1),)),
                V5FileEntry("b", 1, (V5ChunkReference(0, V5_HEADER_SIZE + 61, 1),)),
            )),
            V5ViewDescriptor(0, 1, 2, (V5FileEntry("a", 2, (
                V5ChunkReference(1, V5_HEADER_SIZE, 1),
                V5ChunkReference(0, V5_HEADER_SIZE + 61, 1),
            )),)),
            V5ViewDescriptor(0, 1, 0, (V5FileEntry("e\u0301.txt", 0, ()),)),
        )
        for view in bad_views:
            with self.subTest(view=view), self.assertRaises(HSE2ModelError):
                seal_v5_descriptor(root_key=root, archive_id=archive_id, view=view, offset=4096)

    def test_descriptor_enforces_file_path_and_live_chunk_limits(self) -> None:
        root = bytes(range(32))
        archive_id = bytes(range(16))
        empty_file = V5FileEntry("empty.txt", 0, ())
        too_many_files = V5ViewDescriptor(
            0, 1, 0, (empty_file,) * (V5_MAX_FILES_PER_VIEW + 1)
        )
        with self.assertRaisesRegex(HSE2ModelError, "file list"):
            seal_v5_descriptor(root_key=root, archive_id=archive_id, view=too_many_files, offset=4096)

        too_long_path = V5ViewDescriptor(
            0, 1, 0, (V5FileEntry("a" * (V5_MAX_PATH_BYTES + 1), 0, ()),)
        )
        with self.assertRaises(HSE2ModelError):
            seal_v5_descriptor(root_key=root, archive_id=archive_id, view=too_long_path, offset=4096)

        chunk_count = V5_MAX_LIVE_CHUNKS_PER_VIEW + 1
        chunks = tuple(
            V5ChunkReference(index, V5_HEADER_SIZE + index * 61, 1)
            for index in range(chunk_count)
        )
        too_many_chunks = V5ViewDescriptor(
            0, 1, chunk_count,
            (V5FileEntry("many-chunks.bin", chunk_count, chunks),),
        )
        descriptor_offset = V5_HEADER_SIZE + chunk_count * 61
        with self.assertRaisesRegex(HSE2ModelError, "live chunk limit"):
            seal_v5_descriptor(
                root_key=root, archive_id=archive_id, view=too_many_chunks,
                offset=descriptor_offset,
            )

    def test_bounded_deterministic_malformed_input_fuzz(self) -> None:
        rng = random.Random(0x48534532)
        root = bytes(range(32))
        archive_id = bytes(range(16))
        footer_size = V5_HEADER_SIZE + 2 * 60 + V5_FOOTER_SIZE

        for index in range(64):
            with self.subTest(kind="header", index=index), self.assertRaises(HSE2ModelError):
                V5PublicHeader.from_bytes(rng.randbytes(V5_HEADER_SIZE))
            with self.subTest(kind="footer", index=index), self.assertRaises(HSE2ModelError):
                V5Footer.from_bytes(rng.randbytes(V5_FOOTER_SIZE), file_size=footer_size)
            malformed_descriptor = rng.randbytes(rng.randrange(0, 512))
            with self.subTest(kind="descriptor", index=index), self.assertRaises(HSE2ModelError):
                open_v5_descriptor(
                    root_key=root, archive_id=archive_id, slot=index % 2, generation=1,
                    offset=4096, blob=malformed_descriptor,
                )

        with self.assertRaises(HSE2ModelError):
            open_v5_descriptor(
                root_key=root, archive_id=archive_id, slot=0, generation=1, offset=4096,
                blob=bytes(V5_MAX_DESCRIPTOR_SIZE + 1),
            )

    def test_authenticated_malformed_manifests_are_rejected(self) -> None:
        root = bytes(range(32))
        archive_id = bytes(range(16))
        offset = V5_HEADER_SIZE
        salt = bytes(range(32))
        nonce = bytes(range(V5_GCM_NONCE_SIZE))
        info = b"HSE2:v5:view:0:descriptor:1:v1"

        def seal_manifest(plaintext: bytes) -> bytes:
            blob_length = V5_DESCRIPTOR_OVERHEAD + len(plaintext)
            key = derive_v5_key(root_key=root, salt=salt, info=info)
            sealed = seal_v5(
                key=key,
                nonce=nonce,
                plaintext=plaintext,
                aad=_descriptor_aad(archive_id, 0, 1, offset, blob_length),
            )
            return salt + nonce + sealed.ciphertext + sealed.tag

        duplicate_key = b'{"files":[],"generation":1,"next_sequence":0,"schema":1,"slot":0,"slot":0}'
        over_nested = b'{"x":' + b"[" * 33 + b"0" + b"]" * 33 + b"}"
        bad_path = (
            b'{"files":[{"chunks":[],"path":"../escape","size":0}],'
            b'"generation":1,"next_sequence":0,"schema":1,"slot":0}'
        )
        for plaintext in (b"{", duplicate_key, over_nested, bad_path):
            with self.subTest(manifest_prefix=plaintext[:24]), self.assertRaisesRegex(
                HSE2ModelError, "v5 descriptor authentication failed"
            ):
                open_v5_descriptor(
                    root_key=root,
                    archive_id=archive_id,
                    slot=0,
                    generation=1,
                    offset=offset,
                    blob=seal_manifest(plaintext),
                )


if __name__ == "__main__":
    unittest.main()
