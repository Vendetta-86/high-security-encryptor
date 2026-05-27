import unittest

from high_security_encryptor.hse2 import (
    HSE2ArchiveEntry,
    HSE2ModelError,
    build_archive_assembly_plan,
    build_archive_payload_plan,
)


class HSE2ArchiveAssemblyPlanTests(unittest.TestCase):
    def test_payload_plan_maps_files_to_contiguous_chunk_ranges(self) -> None:
        entries = (
            HSE2ArchiveEntry("dir", "directory"),
            HSE2ArchiveEntry("dir/b.bin", "file", size=5),
            HSE2ArchiveEntry("a.bin", "file", size=9),
        )

        ranges = build_archive_payload_plan(entries, chunk_size=4)

        self.assertEqual([item.to_dict() for item in ranges], [
            {"path": "a.bin", "size": 9, "start_chunk": 0, "chunk_count": 3},
            {"path": "dir/b.bin", "size": 5, "start_chunk": 3, "chunk_count": 2},
        ])

    def test_payload_plan_assigns_zero_chunks_to_empty_files(self) -> None:
        entries = (
            HSE2ArchiveEntry("empty.bin", "file", size=0),
            HSE2ArchiveEntry("next.bin", "file", size=1),
        )

        ranges = build_archive_payload_plan(entries, chunk_size=4)

        self.assertEqual([item.to_dict() for item in ranges], [
            {"path": "empty.bin", "size": 0, "start_chunk": 0, "chunk_count": 0},
            {"path": "next.bin", "size": 1, "start_chunk": 0, "chunk_count": 1},
        ])

    def test_assembly_plan_reports_manifest_and_payload_summary(self) -> None:
        entries = (
            HSE2ArchiveEntry("folder", "directory"),
            HSE2ArchiveEntry("folder/file.bin", "file", size=8),
        )

        plan = build_archive_assembly_plan(entries, chunk_size=3)

        self.assertEqual(plan["format"], "HSE2-archive-assembly-plan-v1")
        self.assertEqual(plan["chunk_size"], 3)
        self.assertEqual(plan["entry_count"], 2)
        self.assertEqual(plan["file_count"], 1)
        self.assertEqual(plan["payload_chunk_count"], 3)
        self.assertEqual(plan["payload_ranges"], [
            {"path": "folder/file.bin", "size": 8, "start_chunk": 0, "chunk_count": 3},
        ])

    def test_payload_plan_rejects_invalid_chunk_size(self) -> None:
        entries = (HSE2ArchiveEntry("file.bin", "file", size=1),)

        with self.assertRaises(HSE2ModelError):
            build_archive_payload_plan(entries, chunk_size=0)


if __name__ == "__main__":
    unittest.main()
