"""Standalone launcher for the experimental HSE2 GUI tab."""

from __future__ import annotations

import shlex
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from .gui import invoke_cli_command
from .hse2_gui_tab import build_hse2_experimental_tab


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
        build_hse2_experimental_tab(notebook, self._run_hse2_command)

        log_frame = ttk.LabelFrame(self, text="执行日志", padding=8)
        log_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log.grid(row=0, column=0, sticky="nsew")

    def _run_hse2_command(self, argv: list[str]) -> None:
        if self._is_busy:
            messagebox.showinfo("正在执行", "已有任务正在执行，请等待完成。")
            return
        self._is_busy = True
        self._append_log(f"$ high-security-encryptor {_quote_argv(argv)}\n")
        self.after(10, lambda: self._execute(argv))

    def _execute(self, argv: list[str]) -> None:
        try:
            result = invoke_cli_command(argv)
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


def _quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


def main() -> None:
    """Launch the standalone HSE2 experimental GUI."""

    root = tk.Tk()
    HSE2ExperimentalApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
