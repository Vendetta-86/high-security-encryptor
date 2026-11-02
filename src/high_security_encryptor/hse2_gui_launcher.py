"""Standalone launcher for the experimental HSE2 GUI tab."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import argparse
import io
import json
import shlex
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Callable
from unittest.mock import patch

from .gui import GuiCommandResult, invoke_cli_command
from .hse2_access_cli import main as hse2_access_main
from .hse2_create_cli import main as hse2_create_main
from .hse2_open_cli import main as hse2_open_main
from .hse2_archive_validate_cli import main as hse2_archive_validate_main
from .hse2_gui_actions import HSE2GuiCommandPlan
from .hse2_gui_tab import build_hse2_experimental_tab, hse2_gui_action_display_values
from .hse2_header_backup_cli import main as hse2_header_backup_main
from .hse2_inspect_cli import main as hse2_inspect_main
from .hse2_quickstart_gui_tab import build_hse2_quickstart_tab
from .hse2_quickstart_wizard import HSE2QuickstartCommandStep, HSE2QuickstartWorkspace
from .hse2_wrapper_cli import main as hse2_wrapper_main


StandaloneCliMain = Callable[..., int]

HSE2_STANDALONE_HELPER_COMMANDS: dict[str, StandaloneCliMain] = {
    "hse2-create": hse2_create_main,
    "hse2-open": hse2_open_main,
    "hse2-archive-validate": hse2_archive_validate_main,
    "hse2-wrapper": hse2_wrapper_main,
    "hse2-access": hse2_access_main,
    "hse2-inspect": hse2_inspect_main,
    "hse2-header-backup": hse2_header_backup_main,
}


class HSE2ExperimentalApp(ttk.Frame):
    """Small standalone window for explicit HSE2 workflows."""

    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=12)
        self.master = master
        self.master.title("HSE2 实验工具")
        self.master.minsize(860, 560)
        self._is_busy = False

        self.pack(fill=tk.BOTH, expand=True)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=0, sticky="nsew")
        build_hse2_quickstart_tab(notebook, self._handle_quickstart_created, self._run_quickstart_steps)
        self.hse2_tab = build_hse2_experimental_tab(notebook, self._run_hse2_command)

        log_frame = ttk.LabelFrame(self, text="执行日志", padding=8)
        log_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log.grid(row=0, column=0, sticky="nsew")

    def _handle_quickstart_created(self, workspace: HSE2QuickstartWorkspace, message: str) -> None:
        self._append_log(f"{message}\n")
        self._append_log(f"下一步：可点击“一键执行三步”，或打开命令清单手动执行：{workspace.command_notes}\n\n")

    def _run_quickstart_steps(self, steps: tuple[HSE2QuickstartCommandStep, ...]) -> None:
        if self._is_busy:
            messagebox.showinfo("正在执行", "已有任务正在执行，请等待完成。")
            return
        if not steps:
            messagebox.showerror("执行失败", "没有可执行的 HSE2 入门步骤。")
            return
        self._is_busy = True
        self.after(10, lambda: self._execute_quickstart_steps(steps))

    def _execute_quickstart_steps(self, steps: tuple[HSE2QuickstartCommandStep, ...]) -> None:
        try:
            for index, step in enumerate(steps, start=1):
                self._append_log(f"\n[{index}/{len(steps)}] {step.name}\n")
                self._append_log(f"$ high-security-encryptor {_quote_argv(list(step.argv))}\n")
                result = invoke_cli_command(list(step.argv))
                if result.stdout:
                    self._append_log(result.stdout)
                if result.stderr:
                    self._append_log(result.stderr)
                self._append_log(f"退出码：{result.exit_code}\n")
                if result.exit_code != 0:
                    messagebox.showerror("执行失败", f"HSE2 入门步骤失败：{step.name}。请查看日志。")
                    return
            messagebox.showinfo("执行完成", "HSE2 入门三步已完成。")
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports user-facing errors.
            self._append_log(f"异常：{exc}\n")
            messagebox.showerror("执行失败", str(exc))
        finally:
            self._is_busy = False

    def _run_hse2_command(self, plan: HSE2GuiCommandPlan) -> None:
        if self._is_busy:
            messagebox.showinfo("正在执行", "已有任务正在执行，请等待完成。")
            return
        self._is_busy = True
        argv = list(plan.argv)
        self._append_log(f"$ high-security-encryptor {_quote_argv(argv)}\n")
        self.after(10, lambda: self._execute(plan))

    def _execute(self, plan: HSE2GuiCommandPlan) -> None:
        try:
            if plan.action == "archive-open" and not self._confirm_archive_open(plan):
                return
            if plan.action in {"v4-create", "v4-open", "v4-replace"} and not self._confirm_v4_action(plan):
                return
            if plan.action in {"v5-create", "v5-open", "v5-replace", "v5-compact", "v4-to-v5"} and not self._confirm_v5_action(plan):
                return
            result = _invoke_hse2_gui_command(plan)
            if result.stdout:
                self._append_log(result.stdout)
                summary = _build_hse2_result_summary(result.stdout)
                if summary:
                    self._append_log(summary)
            if result.stderr:
                self._append_log(result.stderr)
            self._append_log(f"\n退出码：{result.exit_code}\n")
            if result.exit_code != 0:
                messagebox.showerror("执行失败", "HSE2 实验命令执行失败，请查看日志。")
            else:
                self._offer_archive_open_followup(plan, result)
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports user-facing errors.
            self._append_log(f"异常：{exc}\n")
            messagebox.showerror("执行失败", str(exc))
        finally:
            self._is_busy = False

    def _offer_archive_open_followup(self, plan: HSE2GuiCommandPlan, result: GuiCommandResult) -> None:
        if plan.action != "archive-create" or result.exit_code != 0:
            return
        payload = _parse_json_stdout(result.stdout)
        if not isinstance(payload, dict) or not payload.get("container_written"):
            return
        validation = payload.get("post_create_validation")
        if isinstance(validation, dict) and validation.get("ok") is False:
            return
        archive_path = payload.get("output_path")
        if not isinstance(archive_path, str) or not archive_path:
            return
        prompt = (
            "归档已创建。是否继续到恢复步骤？\n\n"
            f"归档：{archive_path}\n"
            "下一步会要求选择恢复目录、确认解锁方式，并在恢复前预览容器元数据。"
        )
        if not messagebox.askyesno("继续 HSE2 恢复向导", prompt):
            return
        self.hse2_tab.prepare_archive_open(archive_path, str(payload.get("wrapper_type", "")))
        self._append_log("\n已切换到归档恢复步骤；请确认解锁方式并选择恢复目录。\n")
        messagebox.showinfo("HSE2 恢复向导", "归档路径已填入。请确认解锁方式、选择恢复目录，然后运行操作。")

    def _confirm_archive_open(self, plan: HSE2GuiCommandPlan) -> bool:
        argv = list(plan.argv)
        input_path = _option_value(argv, "--input")
        if not input_path:
            messagebox.showerror("无法预览归档", "恢复操作缺少输入容器路径。")
            return False
        inspect_result = _invoke_hse2_gui_command(["hse2-inspect", "--input", input_path])
        if inspect_result.stdout:
            self._append_log(inspect_result.stdout)
            summary = _build_hse2_result_summary(inspect_result.stdout)
            if summary:
                self._append_log(summary)
        if inspect_result.stderr:
            self._append_log(inspect_result.stderr)
        if inspect_result.exit_code != 0:
            self._append_log("\n元数据预览失败，已取消恢复。\n")
            messagebox.showerror("无法预览归档", "只读元数据检查失败，未开始恢复。请查看日志。")
            return False
        payload = _parse_json_stdout(inspect_result.stdout)
        if not isinstance(payload, dict):
            self._append_log("\n元数据预览结果无法解析，已取消恢复。\n")
            messagebox.showerror("无法预览归档", "元数据检查未返回有效结果，未开始恢复。")
            return False
        preview = _build_archive_open_confirmation(payload, argv)
        if not messagebox.askyesno("确认恢复 HSE2 归档", preview):
            self._append_log("\n用户取消恢复操作。\n")
            return False
        return True

    def _confirm_v4_action(self, plan: HSE2GuiCommandPlan) -> bool:
        argv = list(plan.argv)
        input_path = _option_value(argv, "--input")
        output_path = _option_value(argv, "--output-dir") or _option_value(argv, "--output")
        if plan.action == "v4-create":
            output_path = output_path or _option_value(argv, "--output")
            records = _option_value(argv, "--capacity-records")
            if not output_path or not records:
                messagebox.showerror("无法确认 v4 操作", "创建操作缺少输出路径或固定记录容量。")
                return False
            try:
                size_mib = 128 + int(records)
            except ValueError:
                messagebox.showerror("无法确认 v4 操作", "固定记录容量无效。")
                return False
            return messagebox.askyesno(
                "确认创建实验性 HSE2 v4",
                f"将创建新的双视图 v4 容器。\n\n输出：{output_path}\n固定容量：{records} 条记录（约 {size_mib} MiB）\n\n"
                "此实验格式不保证可否认性。确认后才会执行。",
            )
        if not input_path or not output_path:
            messagebox.showerror("无法确认 v4 操作", "操作缺少输入容器或输出路径。")
            return False
        description = "恢复密码对应的一个视图到新目录" if plan.action == "v4-open" else "使用密码对应的视图创建一个新容器副本"
        return messagebox.askyesno(
            "确认实验性 HSE2 v4 操作",
            f"{description}。\n\n输入：{input_path}\n输出：{output_path}\n\n"
            "此实验格式不保证可否认性。确认后才会执行。",
        )

    def _confirm_v5_action(self, plan: HSE2GuiCommandPlan) -> bool:
        argv = list(plan.argv)
        input_path = _option_value(argv, "--input")
        output_path = _option_value(argv, "--output-dir") or _option_value(argv, "--output")
        action_details = {
            "v5-create": ("创建一个公开披露双视图的紧凑 v5 容器。", "创建实验性 HSE2 v5"),
            "v5-open": ("恢复密码对应的一个 v5 视图到新目录。", "恢复实验性 HSE2 v5 视图"),
            "v5-replace": ("将密码对应视图写入一个新容器副本；原容器和另一视图会保留。", "替换实验性 HSE2 v5 视图"),
            "v5-compact": ("使用两个视图密码重建新容器，以回收历史记录占用空间。", "压缩实验性 HSE2 v5"),
            "v4-to-v5": ("使用两个视图密码将 v4 两个视图显式导出到一个新的 v5 容器。", "导出 HSE2 v4 到 v5"),
        }
        description, title = action_details[plan.action]
        if plan.action == "v5-create":
            if not output_path:
                messagebox.showerror("无法确认 v5 操作", "创建操作缺少输出路径。")
                return False
        elif not input_path or not output_path:
            messagebox.showerror("无法确认 v5 操作", "操作缺少输入容器或输出路径。")
            return False
        elif plan.action == "v5-replace" and "--file" not in argv:
            description += " 未指定文件映射，目标视图将被清空。"
        if plan.action == "v5-open":
            preview_plan = HSE2GuiCommandPlan(
                action="v5-preview",
                argv=("hse2", "v5-preview", "--input", input_path, "--output-dir", output_path),
                description="v5 恢复预览",
                secret_inputs=plan.secret_inputs,
            )
            preview_result = _invoke_hse2_gui_command(preview_plan)
            if preview_result.exit_code != 0:
                if preview_result.stderr:
                    self._append_log(preview_result.stderr)
                messagebox.showerror("恢复预览失败", "无法认证所选 v5 视图或读取目标信息；未开始恢复。")
                return False
            preview_payload = _parse_json_stdout(preview_result.stdout)
            if not isinstance(preview_payload, dict):
                messagebox.showerror("恢复预览失败", "无法读取 v5 恢复预览结果；未开始恢复。")
                return False
            if preview_payload.get("output_exists") or preview_payload.get("enough_space") is False:
                summary = _build_hse2_result_summary(preview_result.stdout)
                if summary:
                    self._append_log(summary)
                messagebox.showerror("无法恢复 v5 视图", "恢复目录已存在或目标磁盘空间不足；未开始恢复。")
                return False
            summary = _build_hse2_result_summary(preview_result.stdout)
            if summary:
                self._append_log(summary)
                description += "\n\n" + summary.strip()
        paths = f"\n\n输出：{output_path}"
        if input_path:
            paths = f"\n\n输入：{input_path}" + paths
        return messagebox.askyesno(
            title,
            f"{description}{paths}\n\n"
            "v5 是实验格式，公开披露双视图，不承诺可否认性。确认后才会执行。",
        )

    def _append_log(self, text: str) -> None:
        self.log.insert(tk.END, text)
        self.log.see(tk.END)


def _invoke_hse2_gui_command(command: list[str] | HSE2GuiCommandPlan) -> GuiCommandResult:
    """Dispatch GUI-built HSE2 commands to the correct in-process CLI entrypoint."""

    plan = command if isinstance(command, HSE2GuiCommandPlan) else None
    argv = list(plan.argv) if plan is not None else command
    if argv and argv[0] == "hse2" and plan is not None and plan.secret_inputs:
        from . import cli as cli_module

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        secret_iterator = iter(plan.secret_inputs)
        with (
            redirect_stdout(stdout_buffer),
            redirect_stderr(stderr_buffer),
            patch("high_security_encryptor.cli.getpass.getpass", side_effect=lambda _prompt="": next(secret_iterator)),
        ):
            exit_code = cli_module.main(argv)
        return GuiCommandResult(exit_code=exit_code, stdout=stdout_buffer.getvalue(), stderr=stderr_buffer.getvalue())
    if argv and argv[0] in HSE2_STANDALONE_HELPER_COMMANDS:
        return _invoke_standalone_helper(
            HSE2_STANDALONE_HELPER_COMMANDS[argv[0]], argv[1:],
            password_override=plan.secret_input if plan is not None else None,
        )
    return invoke_cli_command(argv)


def _invoke_standalone_helper(
    main_func: StandaloneCliMain, argv: list[str], *, password_override: str | None = None
) -> GuiCommandResult:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        if password_override is None:
            exit_code = main_func(argv)
        else:
            exit_code = main_func(argv, password_override=password_override)
    return GuiCommandResult(
        exit_code=exit_code,
        stdout=stdout_buffer.getvalue(),
        stderr=stderr_buffer.getvalue(),
    )


def _build_hse2_result_summary(stdout: str) -> str:
    """Build a readable GUI summary for supported HSE2 JSON stdout payloads."""

    payload = _parse_json_stdout(stdout)
    if not isinstance(payload, dict):
        return ""
    command = payload.get("command")
    if command == "hse2-create":
        return _summarize_archive_create(payload)
    if command == "hse2-inspect":
        return _summarize_inspect(payload)
    if command == "hse2-archive-validate":
        return _summarize_archive_validation(payload)
    if command in {"hse2 v5-verify", "hse2 v5-preview"}:
        return _summarize_v5_result(payload)
    if command == "hse2-wrapper list":
        return _summarize_wrapper_list(payload)
    if command == "hse2-wrapper remove":
        return _summarize_wrapper_remove(payload)
    if command == "hse2-access destroy":
        return _summarize_access_destroy(payload)
    return ""


def _summarize_archive_create(payload: dict[str, Any]) -> str:
    validation = payload.get("post_create_validation")
    validation_status = (
        _format_bool(validation.get("ok")) if isinstance(validation, dict) else "未运行"
    )
    backup_path = payload.get("header_backup_path") or "未提供"
    next_steps = (
        "下一步：导出并妥善保存 header backup；然后选择“解密并打开 HSE2 归档”，"
        "预览确认后即可恢复。"
    ) if payload.get("container_written") else ""
    lines = [
        "\n结果摘要：\n",
        f"- 输出归档：{payload.get('output_path', '')}\n",
        f"- 格式版本：{payload.get('format_version', '')}\n",
        f"- Wrapper 类型：{payload.get('wrapper_type', '')}\n",
        f"- 文件数：{payload.get('file_count', '')}\n",
        f"- Payload 块数：{payload.get('payload_chunk_count', '')}\n",
        f"- 创建后认证校验：{validation_status}\n",
        f"- 建议 header backup：{backup_path}\n",
    ]
    if next_steps:
        lines.extend([f"- {next_steps}\n", "- Header backup 用于恢复容器 header 元数据，不替代密码或 keyfile。\n"])
    return "".join(lines)


def _parse_json_stdout(stdout: str) -> Any:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _option_value(argv: list[str], option: str) -> str | None:
    try:
        return argv[argv.index(option) + 1]
    except (ValueError, IndexError):
        return None


def _build_archive_open_confirmation(payload: dict[str, Any], argv: list[str]) -> str:
    wrapper_types = payload.get("wrapper_types")
    if isinstance(wrapper_types, list):
        wrapper_types_text = ", ".join(str(item) for item in wrapper_types) or "无"
    else:
        wrapper_types_text = str(wrapper_types or "无")
    return "\n".join(
        [
            "即将恢复以下 HSE2 归档：",
            f"输入容器：{payload.get('input_path', '')}",
            f"恢复位置：{_option_value(argv, '--output-dir') or ''}",
            f"格式版本：{payload.get('format_version', '未知')}",
            f"容器大小：{payload.get('container_size', '未知')} 字节",
            f"Wrapper 数：{payload.get('wrapper_count', '未知')}（{wrapper_types_text}）",
            f"Payload 块数：{payload.get('payload_chunk_count', '未知')}",
            f"访问已禁用：{_format_bool(payload.get('access_destroyed'))}",
            "",
            "此预览只读取未解锁元数据，不代表认证通过，也不会显示加密的文件名。",
            "恢复操作仍会验证归档认证信息；可另选打开前完整校验以避免失败时留下恢复文件。",
            "是否继续？",
        ]
    )
def _summarize_inspect(payload: dict[str, Any]) -> str:
    wrapper_types = payload.get("wrapper_types")
    if isinstance(wrapper_types, list):
        wrapper_types_text = ", ".join(str(item) for item in wrapper_types) or "none"
    else:
        wrapper_types_text = str(wrapper_types or "none")
    return "".join(
        [
            "\n结果摘要：\n",
            f"- 命令：{payload.get('command', 'hse2-inspect')}\n",
            f"- 容器：{payload.get('input_path', '')}\n",
            f"- format_version：{payload.get('format_version', '')}\n",
            f"- container_size：{payload.get('container_size', '')}\n",
            f"- wrapper_count：{payload.get('wrapper_count', '')}\n",
            f"- wrapper_types：{wrapper_types_text}\n",
            f"- payload_chunk_count：{payload.get('payload_chunk_count', '')}\n",
            f"- manifest_encrypted：{_format_bool(payload.get('manifest_encrypted'))}\n",
            f"- access_destroyed：{_format_bool(payload.get('access_destroyed'))}\n",
        ]
    )


def _summarize_archive_validation(payload: dict[str, Any]) -> str:
    return "".join(
        [
            "\n结果摘要：\n",
            f"- 命令：{payload.get('command', 'hse2-archive-validate')}\n",
            f"- 容器：{payload.get('input_path', '')}\n",
            f"- format_version：{payload.get('format_version', '')}\n",
            f"- wrapper_type：{payload.get('wrapper_type', '')}\n",
            f"- entry_count：{payload.get('entry_count', '')}\n",
            f"- payload_chunk_count：{payload.get('payload_chunk_count', '')}\n",
            f"- payload_authenticated：{_format_bool(payload.get('payload_authenticated'))}\n",
            f"- plaintext_written：{_format_bool(payload.get('plaintext_written'))}\n",
        ]
    )


def _summarize_v5_result(payload: dict[str, Any]) -> str:
    lines = [
        "\n结果摘要：\n",
        f"- 操作：{payload.get('command', '')}\n",
        f"- 视图：{payload.get('view_slot', '')}（generation {payload.get('view_generation', '')}）\n",
        f"- 文件数：{payload.get('file_count', '')}\n",
        f"- 明文总大小：{payload.get('plaintext_bytes', '')} 字节\n",
        f"- 活动块数：{payload.get('chunk_count', payload.get('authenticated_chunks', ''))}\n",
    ]
    if payload.get("command") == "hse2 v5-verify":
        lines.extend([
            f"- 活动记录认证：{_format_bool(payload.get('payload_authenticated'))}\n",
            f"- 明文写出：{_format_bool(payload.get('plaintext_written'))}\n",
        ])
    else:
        available = payload.get("available_bytes")
        available_text = "未知" if available is None else f"{available} 字节"
        enough_space = payload.get("enough_space")
        enough_text = "未知" if enough_space is None else _format_bool(enough_space)
        lines.extend([
            f"- 恢复目录：{payload.get('output_dir', '')}\n",
            f"- 目标目录已存在：{_format_bool(payload.get('output_exists'))}\n",
            f"- 目标卷可用空间：{available_text}\n",
            f"- 当前空间足够：{enough_text}\n",
        ])
    return "".join(lines)


def _summarize_wrapper_list(payload: dict[str, Any]) -> str:
    wrappers = payload.get("wrappers")
    if not isinstance(wrappers, list):
        wrappers = []
    lines = [
        "\n结果摘要：\n",
        f"- 命令：{payload.get('command', 'hse2-wrapper list')}\n",
        f"- 容器：{payload.get('input_path', '')}\n",
        f"- access_destroyed：{_format_bool(payload.get('access_destroyed'))}\n",
        f"- wrapper_count：{payload.get('wrapper_count', len(wrappers))}\n",
    ]
    if not wrappers:
        lines.append("- wrapper 列表：空\n")
        return "".join(lines)
    lines.extend([
        "\nWrapper 列表：\n",
        "ID | Type | Label | KDF | Created UTC\n",
        "--- | --- | --- | --- | ---\n",
    ])
    for wrapper in wrappers:
        if not isinstance(wrapper, dict):
            continue
        lines.append(
            " | ".join(
                [
                    str(wrapper.get("id", "")),
                    str(wrapper.get("type", "")),
                    str(wrapper.get("label") or ""),
                    str(wrapper.get("kdf_profile") or ("yes" if wrapper.get("has_kdf") else "")),
                    str(wrapper.get("created_utc", "")),
                ]
            )
            + "\n"
        )
    return "".join(lines)


def _summarize_wrapper_remove(payload: dict[str, Any]) -> str:
    return "".join(
        [
            "\n结果摘要：\n",
            f"- 命令：{payload.get('command', 'hse2-wrapper remove')}\n",
            f"- 输入容器：{payload.get('input_path', '')}\n",
            f"- 输出容器：{payload.get('output_path', '')}\n",
            f"- 已移除 wrapper：{payload.get('removed_wrapper_id', '')}\n",
            f"- 解锁 wrapper 类型：{payload.get('unlocked_wrapper_type', '')}\n",
            f"- 原 wrapper 数：{payload.get('original_wrapper_count', '')}\n",
            f"- 剩余 wrapper 数：{payload.get('remaining_wrapper_count', '')}\n",
            f"- 已写出容器：{_format_bool(payload.get('container_written'))}\n",
        ]
    )


def _summarize_access_destroy(payload: dict[str, Any]) -> str:
    return "".join(
        [
            "\n结果摘要：\n",
            f"- 命令：{payload.get('command', 'hse2-access destroy')}\n",
            f"- 输入容器：{payload.get('input_path', '')}\n",
            f"- 输出容器：{payload.get('output_path', '')}\n",
            f"- 已移除 wrapper 数：{payload.get('removed_wrapper_count', '')}\n",
            f"- access_destroyed：{_format_bool(payload.get('access_destroyed'))}\n",
            f"- 已写出容器：{_format_bool(payload.get('container_written'))}\n",
            "- 警告：该输出容器已移除所有解锁 wrapper，数据不可再恢复。\n",
        ]
    )


def _format_bool(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


def main(argv: list[str] | None = None) -> int:
    """Launch the standalone HSE2 experimental GUI."""

    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-gui")
    parser.add_argument("--smoke-test", action="store_true", help="Verify GUI modules and v4 actions without opening a window.")
    args = parser.parse_args(argv)
    if args.smoke_test:
        required = ("实验性 HSE2 v4 双视图创建", "实验性 HSE2 v4 单视图恢复", "实验性 HSE2 v4 单视图替换")
        labels = hse2_gui_action_display_values()
        if any(label not in labels for label in required):
            raise RuntimeError("HSE2 v4 GUI actions are unavailable")
        return 0

    root = tk.Tk()
    HSE2ExperimentalApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    main()
