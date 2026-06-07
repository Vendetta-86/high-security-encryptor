"""Standalone launcher for the experimental HSE2 GUI tab."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import shlex
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable

from .gui import GuiCommandResult, invoke_cli_command
from .hse2_access_cli import main as hse2_access_main
from .hse2_gui_tab import build_hse2_experimental_tab
from .hse2_quickstart_gui_tab import build_hse2_quickstart_tab
from .hse2_quickstart_wizard import HSE2QuickstartCommandStep, HSE2QuickstartWorkspace
from .hse2_wrapper_cli import main as hse2_wrapper_main


StandaloneCliMain = Callable[[list[str] | None], int]

HSE2_STANDALONE_HELPER_COMMANDS: dict[str, StandaloneCliMain] = {
    "hse2-wrapper": hse2_wrapper_main,
    "hse2-access": hse2_access_main,
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
        build_hse2_experimental_tab(notebook, self._run_hse2_command)

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

    def _run_hse2_command(self, argv: list[str]) -> None:
        if self._is_busy:
            messagebox.showinfo("正在执行", "已有任务正在执行，请等待完成。")
            return
        self._is_busy = True
        self._append_log(f"$ high-security-encryptor {_quote_argv(argv)}\n")
        self.after(10, lambda: self._execute(argv))

    def _execute(self, argv: list[str]) -> None:
        try:
            result = _invoke_hse2_gui_command(argv)
            if result.stdout:
                self._append_log(result.stdout)
            if result.stderr:
                self._append_log(result.stderr)
            self._append_log(f"\n退出码：{result.exit_code}\n")
            if result.exit_code != 0:
                messagebox.showerror("执行失败", "HSE2 实验命令执行失败，请查看日志。")
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports user-facing errors.
            self._append_log(f"异常：{exc}\n")
            messagebox.showerror("执行失败", str(exc))
        finally:
            self._is_busy = False

    def _append_log(self, text: str) -> None:
        self.log.insert(tk.END, text)
        self.log.see(tk.END)


def _invoke_hse2_gui_command(argv: list[str]) -> GuiCommandResult:
    """Dispatch GUI-built HSE2 commands to the correct in-process CLI entrypoint."""

    if argv and argv[0] in HSE2_STANDALONE_HELPER_COMMANDS:
        return _invoke_standalone_helper(HSE2_STANDALONE_HELPER_COMMANDS[argv[0]], argv[1:])
    return invoke_cli_command(argv)


def _invoke_standalone_helper(main_func: StandaloneCliMain, argv: list[str]) -> GuiCommandResult:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        exit_code = main_func(argv)
    return GuiCommandResult(
        exit_code=exit_code,
        stdout=stdout_buffer.getvalue(),
        stderr=stderr_buffer.getvalue(),
    )


def _quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


def main() -> None:
    """Launch the standalone HSE2 experimental GUI."""

    root = tk.Tk()
    HSE2ExperimentalApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
