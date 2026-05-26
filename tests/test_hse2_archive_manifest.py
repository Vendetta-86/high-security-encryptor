import unittest

from high_security_encryptor.hse2 import (
    HSE2ArchiveEntry,
    HSE2ModelError,
    archive_manifest_digest,
    build_archive_manifest,
)


class HSE2ArchiveManifestTests(unittest.TestCase):
    def test_build_archive_manifest_sorts_entries_by_path(self) -> None:
        manifest = build_archive_manifest(
            (
                HSE2ArchiveEntry(path="z/file.txt", kind="file", size=10, modified_utc="2026-05-25T00:00:02Z"),
                HSE2ArchiveEntry(path="a", kind="directory"),
                HSE2ArchiveEntry(path="a/file.txt", kind="file", size=5, modified_utc="2026-05-25T00:00:01Z"),
            )
        )

        self.assertEqual(manifest["format"], "HSE2-archive-manifest-v1")
        self.assertEqual([entry["path"] for entry in manifest["entries"]], ["a", "a/file.txt", "z/file.txt"])
        self.assertEqual(manifest["entries"][0], {"path": "a", "kind": "directory", "size": 0})

    def test_archive_manifest_digest_is_deterministic(self) -> None:
        entries_a = (
            HSE2ArchiveEntry(path="b.txt", kind="file", size=2),
            HSE2ArchiveEntry(path="a.txt", kind="file", size=1),
        )
        entries_b = tuple(reversed(entries_a))

        self.assertEqual(archive_manifest_digest(entries_a), archive_manifest_digest(entries_b))

    def test_build_archive_manifest_rejects_empty_entries(self) -> None:
        with self.assertRaises(HSE2ModelError):
            build_archive_manifest(())

    def test_archive_entry_rejects_absolute_path(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2ArchiveEntry(path="/absolute.txt", kind="file")

    def test_archive_entry_rejects_parent_segments(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2ArchiveEntry(path="../outside.txt", kind="file")

    def test_archive_entry_rejects_windows_separators(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2ArchiveEntry(path="folder\\file.txt", kind="file")

    def test_archive_entry_rejects_unknown_kind(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2ArchiveEntry(path="item", kind="symlink")

    def test_archive_entry_rejects_negative_size(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2ArchiveEntry(path="item", kind="file", size=-1)

    def test_archive_entry_rejects_directory_size(self) -> None:
        with self.assertRaises(HSE2ModelError):
            HSE2ArchiveEntry(path="folder", kind="directory", size=1)

    def test_build_archive_manifest_rejects_duplicate_paths(self) -> None:
        with self.assertRaises(HSE2ModelError):
            build_archive_manifest(
                (
                    HSE2ArchiveEntry(path="a.txt", kind="file", size=1),
                    HSE2ArchiveEntry(path="a.txt", kind="file", size=2),
                )
            )


if __name__ == "__main__":
    unittest.main()
