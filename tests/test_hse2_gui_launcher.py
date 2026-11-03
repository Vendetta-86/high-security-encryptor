"""Smoke tests for the standalone HSE2 GUI launcher module."""

from __future__ import annotations

import contextlib
import inspect
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from high_security_encryptor import hse2_gui_launcher
from high_security_encryptor.gui import GuiCommandResult
from high_security_encryptor.hse2_gui_launcher import HSE2ExperimentalApp, _build_archive_open_confirmation, _build_hse2_result_summary, _invoke_hse2_gui_command, _quote_argv, main
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2.container_v4_workflows import create_v4_archive
from high_security_encryptor.hse2.container_v5_workflows import create_v5_archive
from high_security_encryptor.hse2_gui_tab import HSE2GuiTabState, build_hse2_command_from_tab_state, build_hse2_plan_from_tab_state
from high_security_encryptor.hse2_quickstart_gui_tab import HSE2QuickstartTab, build_hse2_quickstart_tab


class HSE2GuiLauncherTests(unittest.TestCase):
    def test_launcher_symbols_import_without_opening_window(self) -> None:
        self.assertIsNotNone(hse2_gui_launcher)
        self.assertTrue(callable(main))
        self.assertTrue(callable(HSE2ExperimentalApp))
        self.assertTrue(callable(HSE2QuickstartTab))
        self.assertTrue(callable(build_hse2_quickstart_tab))

    def test_launcher_smoke_test_verifies_v4_actions_without_creating_a_window(self) -> None:
        with patch("high_security_encryptor.hse2_gui_launcher.tk.Tk") as create_root:
            self.assertEqual(main(["--smoke-test"]), 0)
            create_root.assert_not_called()

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

    def test_archive_open_confirmation_previews_metadata_and_disclaims_authentication(self) -> None:
        preview = _build_archive_open_confirmation(
            {
                "input_path": "archive.hse2", "format_version": 3, "container_size": 4096,
                "wrapper_count": 2, "wrapper_types": ["password", "keyfile"],
                "payload_chunk_count": 7, "access_destroyed": False,
            },
            ["hse2-open", "--input", "archive.hse2", "--output-dir", "restored"],
        )
        self.assertIn("恢复位置：restored", preview)
        self.assertIn("格式版本：3", preview)
        self.assertIn("Wrapper 数：2（password, keyfile）", preview)
        self.assertIn("不代表认证通过", preview)
        self.assertIn("打开前完整校验", preview)

    def test_archive_open_preview_is_read_only_and_cancel_stops_before_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source"
            source.mkdir()
            (source / "payload.txt").write_bytes(b"preview-only test")
            keyfile = base / "recovery.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(create_main([
                    "--root", str(source), "--output", str(container), "--keyfile", str(keyfile),
                ]), 0)
            output_dir = base / "restored"
            plan = build_hse2_plan_from_tab_state(
                HSE2GuiTabState(
                    action="archive-open", input_path=str(container), output_path=str(output_dir),
                    keyfile_path=str(keyfile),
                )
            )

            class PreviewProbe:
                log: list[str] = []

                def _append_log(self, value: str) -> None:
                    self.log.append(value)

            probe = PreviewProbe()
            with patch("high_security_encryptor.hse2_gui_launcher.messagebox.askyesno", return_value=False) as ask:
                self.assertFalse(HSE2ExperimentalApp._confirm_archive_open(probe, plan))
            self.assertFalse(output_dir.exists())
            self.assertIn("格式版本：2", ask.call_args.args[1])
            self.assertTrue(any("hse2-inspect" in item for item in probe.log))

    def test_archive_validation_summary_reports_authentication_without_plaintext(self) -> None:
        summary = _build_hse2_result_summary(
            json.dumps({
                "command": "hse2-archive-validate", "input_path": "archive.hse2", "format_version": 3,
                "wrapper_type": "keyfile", "entry_count": 2, "payload_chunk_count": 4,
                "payload_authenticated": True, "plaintext_written": False,
            })
        )
        self.assertIn("payload_authenticated：true", summary)
        self.assertIn("plaintext_written：false", summary)

    def test_archive_create_summary_shows_validation_backup_and_next_steps(self) -> None:
        summary = _build_hse2_result_summary(
            json.dumps({
                "command": "hse2-create", "container_written": True, "output_path": "archive.hse2",
                "format_version": 3, "wrapper_type": "password_keyfile", "file_count": 2,
                "payload_chunk_count": 4, "post_create_validation": {"ok": True},
                "header_backup_path": "archive.hse2.header",
            })
        )
        self.assertIn("创建后认证校验：true", summary)
        self.assertIn("建议 header backup：archive.hse2.header", summary)
        self.assertIn("解密并打开 HSE2 归档", summary)
        self.assertIn("不替代密码或 keyfile", summary)

    def test_archive_create_followup_prepares_restore_action_after_confirmation(self) -> None:
        class TabProbe:
            prepared: tuple[str, str] | None = None

            def prepare_archive_open(self, input_path: str, wrapper_type: str) -> None:
                self.prepared = input_path, wrapper_type

        class AppProbe:
            hse2_tab = TabProbe()
            log: list[str] = []

            def _append_log(self, value: str) -> None:
                self.log.append(value)

        probe = AppProbe()
        plan = build_hse2_plan_from_tab_state(
            HSE2GuiTabState(action="archive-create", root_path="source", output_path="archive.hse2", keyfile_path="k")
        )
        result = GuiCommandResult(
            exit_code=0,
            stdout=json.dumps({
                "command": "hse2-create", "container_written": True,
                "output_path": "archive.hse2", "wrapper_type": "keyfile",
            }),
            stderr="",
        )
        with patch("high_security_encryptor.hse2_gui_launcher.messagebox.askyesno", return_value=True), \
                patch("high_security_encryptor.hse2_gui_launcher.messagebox.showinfo"):
            HSE2ExperimentalApp._offer_archive_open_followup(probe, plan, result)
        self.assertEqual(probe.hse2_tab.prepared, ("archive.hse2", "keyfile"))

    def test_archive_create_followup_is_suppressed_on_failure_or_failed_validation(self) -> None:
        class TabProbe:
            prepared = False

            def prepare_archive_open(self, input_path: str, wrapper_type: str) -> None:
                self.prepared = True

        class AppProbe:
            hse2_tab = TabProbe()

        probe = AppProbe()
        plan = build_hse2_plan_from_tab_state(
            HSE2GuiTabState(action="archive-create", root_path="source", output_path="archive.hse2", keyfile_path="k")
        )
        payload = json.dumps({
            "container_written": True, "output_path": "archive.hse2", "wrapper_type": "keyfile",
            "post_create_validation": {"ok": False},
        })
        failed = GuiCommandResult(exit_code=3, stdout=payload, stderr="failed")
        with patch("high_security_encryptor.hse2_gui_launcher.messagebox.askyesno") as ask:
            HSE2ExperimentalApp._offer_archive_open_followup(probe, plan, failed)
            HSE2ExperimentalApp._offer_archive_open_followup(
                probe, plan, GuiCommandResult(exit_code=0, stdout=payload, stderr="")
            )
        ask.assert_not_called()
        self.assertFalse(probe.hse2_tab.prepared)

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
            validate_result = _invoke_hse2_gui_command(
                ["hse2-archive-validate", "--input", str(container), "--keyfile", str(keyfile)]
            )

            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertTrue(container.exists())
            create_payload = json.loads(create_result.stdout)
            self.assertTrue(create_payload["post_create_validation"]["ok"])
            self.assertFalse(create_payload["post_create_validation"]["plaintext_written"])
            self.assertEqual(inspect_result.exit_code, 0, inspect_result.stderr)
            inspect_payload = json.loads(inspect_result.stdout)
            self.assertEqual(inspect_payload["format_version"], 3)
            self.assertEqual(inspect_payload["payload_layout"]["padding_mode"], "last-chunk-to-chunk-size")
            self.assertEqual(validate_result.exit_code, 0, validate_result.stderr)
            self.assertTrue(json.loads(validate_result.stdout)["payload_authenticated"])

    def test_typed_password_create_stays_out_of_argv_logs_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = base / "source"
            source.mkdir()
            expected = b"created with in-memory GUI password"
            (source / "payload.txt").write_bytes(expected)
            container = base / "typed-password.hse2"
            password = "typed-password-secret"
            plan = build_hse2_plan_from_tab_state(
                HSE2GuiTabState(
                    action="archive-create", root_path=str(source), output_path=str(container),
                    archive_password=password, archive_password_confirmation=password,
                )
            )
            self.assertNotIn(password, " ".join(plan.argv))
            self.assertNotIn(password, repr(plan))

            create_result = _invoke_hse2_gui_command(plan)
            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertNotIn(password, create_result.stdout)
            self.assertNotIn(password, create_result.stderr)
            self.assertTrue(container.exists())

            restored = base / "restored"
            open_plan = build_hse2_plan_from_tab_state(
                HSE2GuiTabState(
                    action="archive-open", input_path=str(container), output_path=str(restored),
                    archive_password=password,
                )
            )
            self.assertNotIn(password, " ".join(open_plan.argv))
            open_result = _invoke_hse2_gui_command(open_plan)
            self.assertEqual(open_result.exit_code, 0, open_result.stderr)
            self.assertNotIn(password, open_result.stdout + open_result.stderr)
            restored_files = list(restored.rglob("payload.txt"))
            self.assertEqual(len(restored_files), 1)
            self.assertEqual(restored_files[0].read_bytes(), expected)

            validate_plan = build_hse2_plan_from_tab_state(
                HSE2GuiTabState(action="archive-validate", input_path=str(container), archive_password=password)
            )
            self.assertNotIn(password, " ".join(validate_plan.argv))
            validation_result = _invoke_hse2_gui_command(validate_plan)
            self.assertEqual(validation_result.exit_code, 0, validation_result.stderr)
            self.assertNotIn(password, validation_result.stdout + validation_result.stderr)
            self.assertTrue(json.loads(validation_result.stdout)["payload_authenticated"])

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
                        keyfile_path=str(keyfile), archive_validate_before_open=True,
                    )
                )
            )
            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertEqual(open_result.exit_code, 0, open_result.stderr)
            self.assertTrue(json.loads(open_result.stdout)["pre_open_validation"]["ok"])
            restored_files = list(output_dir.rglob("payload.txt"))
            self.assertEqual(len(restored_files), 1)
            self.assertEqual(restored_files[0].read_bytes(), expected)

    def test_v4_gui_create_and_open_keep_passwords_out_of_cli_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            primary = base / "primary.bin"
            secondary = base / "secondary.bin"
            primary_bytes = b"primary view GUI smoke"
            secondary_bytes = b"secondary view GUI smoke"
            primary.write_bytes(primary_bytes)
            secondary.write_bytes(secondary_bytes)
            container = base / "candidate.v4"
            primary_password, secondary_password = "p-gui-test-secret", "s-gui-test-secret"
            create_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v4-create", output_path=str(container), capacity_records=2,
                primary_file_spec=f"primary.bin={primary}", secondary_file_spec=f"secondary.bin={secondary}",
                primary_password=primary_password, primary_password_confirmation=primary_password,
                secondary_password=secondary_password, secondary_password_confirmation=secondary_password,
            ))
            create_result = _invoke_hse2_gui_command(create_plan)
            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertNotIn(primary_password, create_result.stdout + create_result.stderr)
            self.assertNotIn(secondary_password, create_result.stdout + create_result.stderr)
            restored = base / "restored-primary"
            open_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v4-open", input_path=str(container), output_path=str(restored),
                archive_password=primary_password,
            ))
            open_result = _invoke_hse2_gui_command(open_plan)
            self.assertEqual(open_result.exit_code, 0, open_result.stderr)
            self.assertEqual((restored / "primary.bin").read_bytes(), primary_bytes)
            replacement = base / "replacement.bin"
            replacement_bytes = b"replacement view from GUI smoke"
            replacement.write_bytes(replacement_bytes)
            updated_container = base / "updated.v4"
            replace_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v4-replace", input_path=str(container), output_path=str(updated_container),
                replace_file_spec=f"primary.bin={replacement}", archive_password=primary_password,
            ))
            replace_result = _invoke_hse2_gui_command(replace_plan)
            self.assertEqual(replace_result.exit_code, 0, replace_result.stderr)
            restored_replacement = base / "restored-replacement"
            verify_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v4-open", input_path=str(updated_container), output_path=str(restored_replacement),
                archive_password=primary_password,
            ))
            verify_result = _invoke_hse2_gui_command(verify_plan)
            self.assertEqual(verify_result.exit_code, 0, verify_result.stderr)
            self.assertEqual((restored_replacement / "primary.bin").read_bytes(), replacement_bytes)
            self.assertTrue(container.exists())

    def test_v5_gui_create_open_replace_and_compact_keep_passwords_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            primary = base / "primary.txt"
            secondary = base / "secondary.txt"
            replacement = base / "replacement.txt"
            primary.write_bytes(b"GUI primary original")
            secondary.write_bytes(b"GUI secondary stays")
            replacement.write_bytes(b"GUI primary updated")
            archive = base / "created-v5.hse2"
            updated = base / "updated-v5.hse2"
            compacted = base / "compacted-v5.hse2"
            primary_password, secondary_password = "v5-primary-test", "v5-secondary-test"

            create_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v5-create", output_path=str(archive),
                primary_file_spec=f"primary.txt={primary}", secondary_file_spec=f"secondary.txt={secondary}",
                primary_password=primary_password, primary_password_confirmation=primary_password,
                secondary_password=secondary_password, secondary_password_confirmation=secondary_password,
            ))
            create_result = _invoke_hse2_gui_command(create_plan)
            self.assertEqual(create_result.exit_code, 0, create_result.stderr)
            self.assertNotIn(primary_password, create_result.stdout + create_result.stderr)
            self.assertNotIn(secondary_password, create_result.stdout + create_result.stderr)

            primary_restore = base / "primary-restore"
            secondary_restore = base / "secondary-restore"
            for password, output_dir, expected in (
                (primary_password, primary_restore, b"GUI primary original"),
                (secondary_password, secondary_restore, b"GUI secondary stays"),
            ):
                plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                    action="v5-open", input_path=str(archive), output_path=str(output_dir), archive_password=password,
                ))
                result = _invoke_hse2_gui_command(plan)
                self.assertEqual(result.exit_code, 0, result.stderr)
                self.assertTrue(any(path.read_bytes() == expected for path in output_dir.rglob("*.txt")))

            replace_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v5-replace", input_path=str(archive), output_path=str(updated),
                replace_file_spec=f"replacement.txt={replacement}", archive_password=primary_password,
            ))
            replace_result = _invoke_hse2_gui_command(replace_plan)
            self.assertEqual(replace_result.exit_code, 0, replace_result.stderr)

            compact_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v5-compact", input_path=str(updated), output_path=str(compacted),
                primary_password=primary_password, secondary_password=secondary_password,
            ))
            compact_result = _invoke_hse2_gui_command(compact_plan)
            self.assertEqual(compact_result.exit_code, 0, compact_result.stderr)
            self.assertNotIn(primary_password, compact_result.stdout + compact_result.stderr)
            self.assertNotIn(secondary_password, compact_result.stdout + compact_result.stderr)

            peer_restore = base / "peer-after-compact"
            peer_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v5-open", input_path=str(compacted), output_path=str(peer_restore),
                archive_password=secondary_password,
            ))
            peer_result = _invoke_hse2_gui_command(peer_plan)
            self.assertEqual(peer_result.exit_code, 0, peer_result.stderr)
            self.assertEqual((peer_restore / "secondary.txt").read_bytes(), b"GUI secondary stays")

    def test_v5_confirmation_discloses_format_limits_and_empty_replacement(self) -> None:
        plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
            action="v5-replace", input_path="old.hse2", output_path="new.hse2", archive_password="secret",
        ))
        with patch("high_security_encryptor.hse2_gui_launcher.messagebox.askyesno", return_value=True) as ask:
            self.assertTrue(HSE2ExperimentalApp._confirm_v5_action(object(), plan))
        message = ask.call_args.args[1]
        self.assertIn("目标视图将被清空", message)
        self.assertIn("不承诺可否认性", message)
        self.assertIn("old.hse2", message)
        self.assertIn("new.hse2", message)

    def test_v5_open_confirmation_shows_preview_and_blocks_existing_target(self) -> None:
        plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
            action="v5-open", input_path="archive.hse2", output_path="restore",
            archive_password="private-view-password",
        ))
        log = []
        app = type("FakeApp", (), {"_append_log": lambda _self, text: log.append(text)})()
        preview_json = json.dumps({
            "command": "hse2 v5-preview", "view_slot": 0, "view_generation": 1,
            "file_count": 1, "plaintext_bytes": 42, "chunk_count": 1,
            "output_dir": "restore", "output_exists": False,
            "available_bytes": 1000, "enough_space": True,
        })
        with patch(
            "high_security_encryptor.hse2_gui_launcher._invoke_hse2_gui_command",
            return_value=GuiCommandResult(0, preview_json, ""),
        ) as invoke, patch(
            "high_security_encryptor.hse2_gui_launcher.messagebox.askyesno", return_value=True,
        ) as ask:
            self.assertTrue(HSE2ExperimentalApp._confirm_v5_action(app, plan))
        preview_plan = invoke.call_args.args[0]
        self.assertEqual(preview_plan.action, "v5-preview")
        self.assertEqual(preview_plan.secret_inputs, ("private-view-password",))
        self.assertNotIn("private-view-password", " ".join(preview_plan.argv))
        self.assertIn("42 字节", ask.call_args.args[1])
        self.assertTrue(any("结果摘要" in line for line in log))

        occupied_json = json.dumps({**json.loads(preview_json), "output_exists": True})
        with patch(
            "high_security_encryptor.hse2_gui_launcher._invoke_hse2_gui_command",
            return_value=GuiCommandResult(0, occupied_json, ""),
        ), patch(
            "high_security_encryptor.hse2_gui_launcher.messagebox.askyesno",
        ) as ask_again, patch(
            "high_security_encryptor.hse2_gui_launcher.messagebox.showerror",
        ) as showerror:
            self.assertFalse(HSE2ExperimentalApp._confirm_v5_action(app, plan))
        ask_again.assert_not_called()
        showerror.assert_called_once()

    def test_v5_password_update_confirmation_explains_copy_and_distinct_password_rule(self) -> None:
        plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
            action="v5-password-update", input_path="archive.hse2", output_path="updated.hse2",
            current_view_password="old-password", new_view_password="new-password",
            new_view_password_confirmation="new-password",
        ))
        with patch("high_security_encryptor.hse2_gui_launcher.messagebox.askyesno", return_value=True) as ask:
            self.assertTrue(HSE2ExperimentalApp._confirm_v5_action(object(), plan))
        confirmation = ask.call_args.args[1]
        self.assertIn("另一视图口令不同", confirmation)
        self.assertIn("原输入档案仍可用旧口令打开", confirmation)
        self.assertIn("archive.hse2", confirmation)
        self.assertIn("updated.hse2", confirmation)

    def test_v5_password_update_gui_command_keeps_passwords_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            primary = base / "primary.txt"
            peer = base / "peer.txt"
            archive = base / "source.hse2"
            output = base / "updated.hse2"
            primary.write_bytes(b"primary")
            peer.write_bytes(b"peer")
            create_v5_archive(
                output_path=archive,
                view_passwords=("old-primary", "peer-password"),
                view_files=((('primary.txt', primary),), (('peer.txt', peer),)),
            )
            plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v5-password-update", input_path=str(archive), output_path=str(output),
                current_view_password="old-primary", new_view_password="new-primary",
                new_view_password_confirmation="new-primary",
            ))

            result = _invoke_hse2_gui_command(plan)

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertNotIn("old-primary", result.stdout + result.stderr)
            self.assertNotIn("new-primary", result.stdout + result.stderr)
            self.assertTrue(archive.exists())
            self.assertTrue(output.exists())

    def test_gui_v4_to_v5_export_keeps_passwords_private_and_both_views_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            primary = base / "primary.txt"
            secondary = base / "secondary.txt"
            primary.write_bytes(b"GUI migrated primary")
            secondary.write_bytes(b"GUI migrated secondary")
            source = base / "source-v4.hse2"
            output = base / "exported-v5.hse2"
            passwords = ("GUI-v4-primary-pass", "GUI-v4-secondary-pass")
            create_v4_archive(
                output_path=source, view_passwords=passwords,
                view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
                capacity_records=2,
            )
            plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v4-to-v5", input_path=str(source), output_path=str(output),
                primary_password=passwords[0], secondary_password=passwords[1],
            ))
            result = _invoke_hse2_gui_command(plan)
            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertNotIn(passwords[0], result.stdout + result.stderr)
            self.assertNotIn(passwords[1], result.stdout + result.stderr)

            restored = base / "restored-primary"
            open_plan = build_hse2_plan_from_tab_state(HSE2GuiTabState(
                action="v5-open", input_path=str(output), output_path=str(restored), archive_password=passwords[0],
            ))
            open_result = _invoke_hse2_gui_command(open_plan)
            self.assertEqual(open_result.exit_code, 0, open_result.stderr)
            self.assertEqual((restored / "primary.txt").read_bytes(), b"GUI migrated primary")

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
