import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import HSE2ModelError, build_archive_plan_summary


class HSE2ArchivePlanTests(unittest.TestCase):
    def test_build_archive_plan_summary_counts_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"a")
            (nested / "b.txt").write_bytes(b"bb")

            summary = build_archive_plan_summary((root,))

            self.assertEqual(summary["format"], "HSE2-archive-manifest-v1")
            self.assertEqual(summary["root_count"], 1)
            self.assertEqual(summary["entry_count"], 4)
            self.assertEqual(summary["file_count"], 2)
            self.assertEqual(summary["directory_count"], 2)
            self.assertEqual(summary["total_file_size"], 3)
            self.assertEqual([entry["path"] for entry in summary["entries"]], ["root", "root/a.txt", "root/nested", "root/nested/b.txt"])

    def test_build_archive_plan_summary_supports_multiple_file_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "b.txt"
            second = Path(temp_dir) / "a.txt"
            first.write_bytes(b"bb")
            second.write_bytes(b"a")

            summary = build_archive_plan_summary((first, second))

            self.assertEqual(summary["root_count"], 2)
            self.assertEqual(summary["entry_count"], 2)
            self.assertEqual(summary["file_count"], 2)
            self.assertEqual(summary["directory_count"], 0)
            self.assertEqual(summary["total_file_size"], 3)
            self.assertEqual([entry["path"] for entry in summary["entries"]], ["a.txt", "b.txt"])

    def test_build_archive_plan_summary_rejects_empty_roots(self) -> None:
        with self.assertRaises(HSE2ModelError):
            build_archive_plan_summary(())


if __name__ == "__main__":
    unittest.main()
