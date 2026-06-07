"""Smoke tests for the standalone HSE2 GUI launcher module."""

from __future__ import annotations

import inspect
import json
import unittest

from high_security_encryptor import hse2_gui_launcher
from high_security_encryptor.hse2_gui_launcher import HSE2ExperimentalApp, _build_hse2_result_summary, _quote_argv, main
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
