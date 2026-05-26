import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import (
    HSE2ModelError,
    build_archive_entries_from_root,
    build_archive_entries_from_roots,
)


class HSE2ArchiveTraversalTests(unittest.TestCase):
    def test_build_archive_entries_from_single_file_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "file.txt"
            file_path.write_bytes(b"hello")

            entries = build_archive_entries_from_root(file_path)

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].path, "file.txt")
            self.assertEqual(entries[0].kind, "file")
            self.assertEqual(entries[0].size, 5)
            self.assertTrue(entries[0].modified_utc.endswith("Z"))

    def test_build_archive_entries_from_directory_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "b.txt").write_bytes(b"bb")
            (nested / "a.txt").write_bytes(b"a")

            entries = build_archive_entries_from_root(root)

            self.assertEqual([entry.path for entry in entries], ["root", "root/b.txt", "root/nested", "root/nested/a.txt"])
            by_path = {entry.path: entry for entry in entries}
            self.assertEqual(by_path["root"].kind, "directory")
            self.assertEqual(by_path["root"].size, 0)
            self.assertEqual(by_path["root/b.txt"].kind, "file")
            self.assertEqual(by_path["root/b.txt"].size, 2)
            self.assertEqual(by_path["root/nested/a.txt"].size, 1)

    def test_build_archive_entries_from_multiple_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "b.txt"
            second = Path(temp_dir) / "a.txt"
            first.write_bytes(b"b")
            second.write_bytes(b"aa")

            entries = build_archive_entries_from_roots((first, second))

            self.assertEqual([entry.path for entry in entries], ["a.txt", "b.txt"])

    def test_build_archive_entries_from_roots_rejects_empty_roots(self) -> None:
        with self.assertRaises(HSE2ModelError):
            build_archive_entries_from_roots(())

    def test_build_archive_entries_from_root_rejects_missing_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(HSE2ModelError):
                build_archive_entries_from_root(Path(temp_dir) / "missing.txt")


if __name__ == "__main__":
    unittest.main()
