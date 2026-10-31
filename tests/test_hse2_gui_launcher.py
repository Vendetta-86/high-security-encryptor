"""Smoke tests for the standalone HSE2 GUI launcher module."""

from __future__ import annotations

import contextlib
import inspect
import io
import json
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor import hse2_gui_launcher
from high_security_encryptor.hse2_gui_launcher import HSE2ExperimentalApp, _build_hse2_result_summary, _invoke_hse2_gui_command, _quote_argv, main
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_gui_tab import HSE2GuiTabState, build_hse2_command_from_tab_state
from high_security_encryptor.hse2_quickstart_gui_tab import HSE2QuickstartTab, build_hse2_quickstart_tab


class HSE2GuiLauncherTests(unittest.TestCase):
    def test_launcher_symbols_import_without_opening_window(self) -> None:
        self.assertIsNotNone(hse2_gui_launcher)
        self.assertTrue(callable(main))
        self.assertTrue(callable(HSE2ExperimentalApp))
        self.assertTrue(callable(HSE2QuickstartTab))
        self.assertTrue(callable(build_hse2_quickstart_tab))

    def test_launcher_wires_quickstart_tab_to_sequential_runner(self) -> None:
        init_source = inspect.getsource(HSE2ExperimentalApp.__init__)
        runner_source = inspect.getsource(HSE2ExperimentalApp._execute_quickstart_steps)
        self.assertIn("_run_quickstart_steps", init_source)
        self.assertIn("invoke_cli_command", runner_source)
        self.assertIn("result.exit_code != 0", runner_source)

    def test_inspect_summary_reports_safe_metadata(self) -> None:
        summary = _build_hse2_result_summary(
            json.dumps(
                {
                    "command": "hse2-inspect",
                    "input_path": "archive.hse2",
                    "format_version": 2,
                    "container_size": 4096,
                    "wrapper_count": 1,
                    "wrapper_types": ["keyfile"],
                    "payload_chunk_count": 3,
                    "manifest_encrypted": True,
                    "access_destroyed": False,
                }
            )
        )

        self.assertIn("hse2-inspect", summary)
        self.assertIn("format_version：2", summary)
        self.assertIn("wrapper_count：1", summary)
        self.assertIn("wrapper_types：keyfile", summary)
        self.assertIn("payload_chunk_count：3", summary)
        self.assertIn("manifest_encrypted：true", summary)
        self.assertIn("access_destroyed：false", summary)

    def test_wrapper_list_summary_formats_table(self) -> None:
        summary = _build_hse2_result_summary(
            json.dumps(
                {
                    "command": "hse2-wrapper list",
                    "input_path": "archive.hse2",
                    "access_destroyed": False,
                    "wrapper_count": 1,
                    "wrappers": [
                        {
                            "id": "keyfile-1",
                            "type": "keyfile",
                            "label": "primary keyfile",
                            "kdf_profile": None,
                            "has_kdf": False,
                            "created_utc": "2026-06-07T00:00:00Z",
                        }
                    ],
                }
            )
        )

        self.assertIn("结果摘要", summary)
        self.assertIn("wrapper_count：1", summary)
        self.assertIn("Wrapper 列表", summary)
        self.assertIn("keyfile-1 | keyfile | primary keyfile", summary)

    def test_access_destroy_summary_warns_irreversible(self) -> None:
        summary = _build_hse2_result_summary(
            json.dumps(
                {
                    "command": "hse2-access destroy",
                    "input_path": "archive.hse2",
                    "output_path": "disabled.hse2",
                    "removed_wrapper_count": 2,
                    "access_destroyed": True,
                    "container_written": True,
                }
            )
        )

        self.assertIn("hse2-access destroy", summary)
        self.assertIn("已移除 wrapper 数：2", summary)
        self.assertIn("数据不可再恢复", summary)

    def test_header_backup_export_is_dispatched_through_gui_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            (root / "payload.txt").write_text("backup fixture", encoding="utf-8")
            keyfile = base / "recovery.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            backup = base / "archive.hse2.header"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                create_exit = create_main([
                    "--root", str(root), "--output", str(container), "--keyfile", str(keyfile),
                ])
            self.assertEqual(create_exit, 0)

            result = _invoke_hse2_gui_command([
                "hse2-header-backup", "export", "--input", str(container), "--output", str(backup),
            ])

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(backup.exists())
            self.assertTrue(json.loads(result.stdout)["header_backup_written"])

    def test_archive_create_is_dispatched_through_gui_helper_and_inspectable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source"
            source.mkdir()
            (source / "payload.txt").write_bytes(b"gui archive wizard")
            keyfile = base / "recovery.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            argv = build_hse2_command_from_tab_state(
                HSE2GuiTabState(
                    action="archive-create",
                    root_path=str(source),
                    output_path=str(container),
                    keyfile_path=str(keyfile),
                    archive_format_version="3",
                    archive_chunk_size=64,
                    archive_pad_last_chunk=True,
                    archive_validate_after_create=True,
                )
            )

            create_result = _invoke_hse2_gui_command(argv)
            inspect_result = _invoke_hse2_gui_command(["hse2-inspect", "--input", str(container)])

            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertTrue(container.exists())
            create_payload = json.loads(create_result.stdout)
            self.assertTrue(create_payload["post_create_validation"]["ok"])
            self.assertFalse(create_payload["post_create_validation"]["plaintext_written"])
            self.assertEqual(inspect_result.exit_code, 0, inspect_result.stderr)
            inspect_payload = json.loads(inspect_result.stdout)
            self.assertEqual(inspect_payload["format_version"], 3)
            self.assertEqual(inspect_payload["payload_layout"]["padding_mode"], "last-chunk-to-chunk-size")

    def test_wrapper_remove_summary_reports_remaining_count(self) -> None:
        summary = _build_hse2_result_summary(
            json.dumps(
                {
                    "command": "hse2-wrapper remove",
                    "input_path": "archive.hse2",
                    "output_path": "removed.hse2",
                    "removed_wrapper_id": "password-2",
                    "unlocked_wrapper_type": "keyfile",
                    "original_wrapper_count": 2,
                    "remaining_wrapper_count": 1,
                    "container_written": True,
                }
            )
        )

        self.assertIn("已移除 wrapper：password-2", summary)
        self.assertIn("剩余 wrapper 数：1", summary)
        self.assertIn("已写出容器：true", summary)

    def test_archive_open_is_dispatched_and_restores_created_v3_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source"
            source.mkdir()
            expected = b"restored through the GUI open action"
            (source / "payload.txt").write_bytes(expected)
            keyfile = base / "recovery.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            output_dir = base / "restored"
            create_result = _invoke_hse2_gui_command(
                build_hse2_command_from_tab_state(
                    HSE2GuiTabState(
                        action="archive-create", root_path=str(source), output_path=str(container),
                        keyfile_path=str(keyfile), archive_format_version="3",
                    )
                )
            )
            open_result = _invoke_hse2_gui_command(
                build_hse2_command_from_tab_state(
                    HSE2GuiTabState(
                        action="archive-open", input_path=str(container), output_path=str(output_dir),
                        keyfile_path=str(keyfile),
                    )
                )
            )
            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertEqual(open_result.exit_code, 0, open_result.stderr)
            restored_files = list(output_dir.rglob("payload.txt"))
            self.assertEqual(len(restored_files), 1)
            self.assertEqual(restored_files[0].read_bytes(), expected)

    def test_result_summary_ignores_non_json_stdout(self) -> None:
        self.assertEqual(_build_hse2_result_summary("not json"), "")

    def test_quote_argv_handles_spaces(self) -> None:
        self.assertEqual(
            _quote_argv(["hse2-validate", "--config", "C:/tmp/my config.json"]),
            "hse2-validate --config 'C:/tmp/my config.json'",
        )

    def test_quote_argv_handles_empty_args(self) -> None:
        self.assertEqual(_quote_argv([]), "")


if __name__ == "__main__":
    unittest.main()
