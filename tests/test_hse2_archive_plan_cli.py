import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_archive_plan_cli import _digest_mismatch_message, main


class HSE2ArchivePlanCliTests(unittest.TestCase):
    def test_archive_plan_digest_mismatch_message_includes_expected_and_actual(self) -> None:
        expected = "0" * 64
        actual = "f" * 64

        message = _digest_mismatch_message(expected, actual)

        self.assertEqual(
            message,
            "hse2-plan-archive: plan digest mismatch "
            f"expected={expected} actual={actual}",
        )
        self.assertNotIn("\n", message)

    def test_archive_plan_cli_reports_metadata_only_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"a")
            (nested / "b.txt").write_bytes(b"bb")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--root", str(root), "--chunk-size", "2"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-plan-archive")
            self.assertTrue(payload["experimental"])
            self.assertEqual(payload["format"], "HSE2-archive-assembly-plan-v1")
            self.assertEqual(payload["root_count"], 1)
            self.assertEqual(payload["entry_count"], 4)
            self.assertEqual(payload["file_count"], 2)
            self.assertEqual(payload["chunk_size"], 2)
            self.assertEqual(payload["payload_chunk_count"], 2)
            self.assertIsNone(payload["output_path"])
            self.assertEqual(len(payload["plan_digest_sha256"]), 64)
            self.assertEqual(
                [entry["path"] for entry in payload["entries"]],
                ["root", "root/a.txt", "root/nested", "root/nested/b.txt"],
            )
            self.assertEqual(payload["payload_ranges"], [
                {"path": "root/a.txt", "size": 1, "start_chunk": 0, "chunk_count": 1},
                {"path": "root/nested/b.txt", "size": 2, "start_chunk": 1, "chunk_count": 1},
            ])

    def test_archive_plan_cli_can_write_metadata_only_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            output = Path(temp_dir) / "reports" / "plan.json"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--output",
                    str(output),
                ])

            self.assertEqual(exit_code, 0)
            stdout_payload = json.loads(stdout.getvalue())
            file_payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(stdout_payload, file_payload)
            self.assertEqual(file_payload["output_path"], str(output))
            self.assertEqual(file_payload["payload_ranges"], [
                {"path": "root/a.txt", "size": 3, "start_chunk": 0, "chunk_count": 2},
            ])

    def test_archive_plan_cli_compact_stdout_keeps_report_pretty(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            output = Path(temp_dir) / "plan.json"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--output",
                    str(output),
                    "--compact",
                ])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue().count("\n"), 1)
            self.assertNotIn("\n  ", stdout.getvalue())
            self.assertIn("\n  ", output.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(stdout.getvalue()), json.loads(output.read_text(encoding="utf-8")))

    def test_archive_plan_digest_ignores_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            first_stdout = io.StringIO()
            second_stdout = io.StringIO()

            with contextlib.redirect_stdout(first_stdout):
                first_exit = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--output",
                    str(Path(temp_dir) / "first.json"),
                ])
            with contextlib.redirect_stdout(second_stdout):
                second_exit = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--output",
                    str(Path(temp_dir) / "second.json"),
                ])

            self.assertEqual(first_exit, 0)
            self.assertEqual(second_exit, 0)
            first_payload = json.loads(first_stdout.getvalue())
            second_payload = json.loads(second_stdout.getvalue())
            self.assertNotEqual(first_payload["output_path"], second_payload["output_path"])
            self.assertEqual(first_payload["plan_digest_sha256"], second_payload["plan_digest_sha256"])
            self.assertEqual(len(first_payload["plan_digest_sha256"]), 64)

    def test_archive_plan_cli_accepts_matching_expected_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            baseline_stdout = io.StringIO()
            checked_stdout = io.StringIO()

            with contextlib.redirect_stdout(baseline_stdout):
                baseline_exit = main(["--root", str(root), "--chunk-size", "2"])
            digest = json.loads(baseline_stdout.getvalue())["plan_digest_sha256"]

            with contextlib.redirect_stdout(checked_stdout):
                checked_exit = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--expect-digest",
                    digest.upper(),
                ])

            self.assertEqual(baseline_exit, 0)
            self.assertEqual(checked_exit, 0)
            self.assertEqual(json.loads(checked_stdout.getvalue())["plan_digest_sha256"], digest)

    def test_archive_plan_cli_reports_expected_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            expected_digest = "0" * 64
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main([
                    "--root",
                    str(root),
                    "--chunk-size",
                    "2",
                    "--expect-digest",
                    expected_digest,
                ])

            actual_digest = json.loads(stdout.getvalue())["plan_digest_sha256"]
            self.assertEqual(exit_code, 3)
            self.assertEqual(len(actual_digest), 64)
            self.assertEqual(
                stderr.getvalue().strip(),
                _digest_mismatch_message(expected_digest, actual_digest),
            )
            self.assertEqual(stderr.getvalue().count("\n"), 1)

    def test_archive_plan_cli_rejects_malformed_expected_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                short_exit = main([
                    "--root",
                    str(root),
                    "--expect-digest",
                    "abc",
                ])

            self.assertEqual(short_exit, 2)
            self.assertIn("expected digest must be a 64-character", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                invalid_hex_exit = main([
                    "--root",
                    str(root),
                    "--expect-digest",
                    "g" * 64,
                ])

            self.assertEqual(invalid_hex_exit, 2)
            self.assertIn("hexadecimal SHA-256", stderr.getvalue())

    def test_archive_plan_cli_reports_invalid_chunk_size(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir()
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(["--root", str(root), "--chunk-size", "0"])

            self.assertEqual(exit_code, 2)
            self.assertIn("hse2-plan-archive:", stderr.getvalue())
            self.assertIn("chunk_size must be positive", stderr.getvalue())

    def test_archive_plan_cli_reports_missing_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(["--root", str(missing)])

            self.assertEqual(exit_code, 2)
            self.assertIn("hse2-plan-archive:", stderr.getvalue())
            self.assertIn("archive root does not exist", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
