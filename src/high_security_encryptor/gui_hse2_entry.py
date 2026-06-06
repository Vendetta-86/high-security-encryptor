"""Main GUI entry point with a visible HSE2 experimental launcher button."""

from __future__ import annotations

import argparse
import tkinter as tk
from tkinter import scrolledtext, ttk

from . import gui

HSE2_GUI_BUTTON_TEXT = "打开 HSE2 实验工具"


class HighSecurityEncryptorWithHSE2App(gui.HighSecurityEncryptorApp):
    """Main GUI variant that exposes the standalone HSE2 experimental window."""

    def _build_log(self) -> None:
        log_frame = ttk.Frame(self, padding=(0, 10, 0, 0))
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        button_row = ttk.Frame(log_frame)
        button_row.grid(row=0, column=0, sticky="ew")
        ttk.Label(button_row, text="运行结果").pack(side=tk.LEFT)
        ttk.Button(button_row, text="清空结果", command=self._clear_log).pack(side=tk.RIGHT)
        ttk.Button(
            button_row,
            text=HSE2_GUI_BUTTON_TEXT,
            command=self._open_hse2_experimental_gui,
        ).pack(side=tk.RIGHT, padx=(0, 8))

        self.log_text = scrolledtext.ScrolledText(log_frame, height=16, wrap=tk.WORD)
        self.log_text.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

    def _open_hse2_experimental_gui(self) -> None:
        from .hse2_gui_entry import open_hse2_experimental_window

        open_hse2_experimental_window(self.master)


def main(argv: list[str] | None = None) -> int:
    """Run the main GUI application with the HSE2 launcher button enabled."""

    parser = argparse.ArgumentParser(prog="high-security-encryptor-gui")
    parser.add_argument("--smoke-test", action="store_true", help="验证 GUI 依赖并退出。")
    args = parser.parse_args(argv)
    if args.smoke_test:
        gui.smoke_test()
        return 0

    root = gui.create_gui_root()
    HighSecurityEncryptorWithHSE2App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
