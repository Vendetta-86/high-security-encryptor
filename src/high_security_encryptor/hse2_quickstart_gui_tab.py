"""Tkinter quickstart tab for HSE2 experimental workflows."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .hse2_quickstart_wizard import HSE2QuickstartWorkspace, create_hse2_quickstart_workspace

NotifyQuickstart = Callable[[HSE2QuickstartWorkspace, str], None]


class HSE2QuickstartTab(ttk.Frame):
    """Small guided entry point that creates local quickstart files."""

    def __init__(self, master: tk.Misc, notify: NotifyQuickstart | None = None) -> None:
        super().__init__(master, padding=12)
        self._notify = notify
        self.columnconfigure(1, weight=1)

        self.base_dir = tk.StringVar()
        self.keyfile_size = tk.IntVar(value=32)
        self.overwrite = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="选择一个空目录，然后生成 HSE2 入门文件。")
        self._build_widgets()

    def _build_widgets(self) -> None:
        ttk.Label(
            self,
            text=(
                "HSE2 入门向导：生成一个本地测试工作区，包括示例文件、随机 keyfile、"
                "三份 JSON 配置和命令清单。向导不会自动执行加密或解密。"
            ),
            wraplength=780,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        ttk.Label(self, text="工作目录").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.base_dir).grid(row=1, column=1, sticky="ew", padx=(8, 8), pady=4)
        ttk.Button(self, text="选择目录", command=self._browse_base_dir).grid(row=1, column=2, pady=4)

        ttk.Label(self, text="keyfile 大小").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Spinbox(self, from_=16, to=1048576, textvariable=self.keyfile_size, width=12).grid(
            row=2,
            column=1,
            sticky="w",
            padx=(8, 8),
            pady=4,
        )

        ttk.Checkbutton(self, text="允许覆盖已有入门文件", variable=self.overwrite).grid(
            row=3,
            column=1,
            sticky="w",
            pady=(6, 0),
        )
        ttk.Button(self, text="生成 HSE2 入门文件", command=self.create_quickstart).grid(
            row=4,
            column=0,
            sticky="w",
            pady=(14, 0),
        )
        ttk.Label(self, textvariable=self.status, wraplength=780, justify=tk.LEFT).grid(
            row=5,
            column=0,
            columnspan=3,
            sticky="ew",
            pady=(12, 0),
        )

    def create_quickstart(self) -> None:
        try:
            base_dir = _require_directory_text(self.base_dir.get())
            workspace = create_hse2_quickstart_workspace(
                base_dir,
                keyfile_size=int(self.keyfile_size.get()),
                overwrite=bool(self.overwrite.get()),
            )
        except (OSError, ValueError) as exc:
            self.status.set(f"生成失败：{exc}")
            messagebox.showerror("HSE2 入门向导", str(exc))
            return
        message = _format_success_message(workspace)
        self.status.set(message)
        if self._notify is not None:
            self._notify(workspace, message)

    def _browse_base_dir(self) -> None:
        path = filedialog.askdirectory(title="选择 HSE2 入门工作目录")
        if path:
            self.base_dir.set(path)


def build_hse2_quickstart_tab(notebook: ttk.Notebook, notify: NotifyQuickstart | None = None) -> HSE2QuickstartTab:
    """Create and add the quickstart tab to a notebook."""

    tab = HSE2QuickstartTab(notebook, notify)
    notebook.add(tab, text="HSE2 入门向导")
    return tab


def _require_directory_text(value: str) -> Path:
    normalized = value.strip()
    if not normalized:
        raise ValueError("请选择 HSE2 入门工作目录。")
    return Path(normalized)


def _format_success_message(workspace: HSE2QuickstartWorkspace) -> str:
    return (
        "HSE2 入门文件已生成。\n"
        f"示例文件：{workspace.sample_input}\n"
        f"keyfile：{workspace.keyfile}\n"
        f"加密配置：{workspace.encrypt_config}\n"
        f"校验配置：{workspace.validate_config}\n"
        f"解密配置：{workspace.decrypt_config}\n"
        f"命令清单：{workspace.command_notes}"
    )
