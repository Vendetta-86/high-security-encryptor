"""Reusable Tkinter tab component for explicit HSE2 workflows.

The component is intentionally isolated from the main GUI module so that the HSE2
experimental UI can be reviewed and tested before being wired into the existing
large Tkinter application.
"""

from __future__ import annotations

from dataclasses import dataclass
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE
from .hse2_gui_actions import HSE2_GUI_ACTION_LABELS, build_hse2_gui_command


RunCommand = Callable[[list[str]], None]


@dataclass(frozen=True)
class HSE2GuiTabState:
    """Serializable field values collected by the HSE2 experimental tab."""

    action: str
    config_path: str = ""
    input_path: str = ""
    output_path: str = ""
    size: int = 32
    force: bool = False
    scope: str = "current_user"
    validation_report_output: str = ""
    validation_summary_only: bool = False
    validation_exit_code_on_failure: bool = False
    wrapper_id: str = ""
    password_file: str = ""
    keyfile_path: str = ""
    allow_dpapi: bool = False
    access_confirmation_phrase: str = ""


def build_hse2_command_from_tab_state(state: HSE2GuiTabState) -> list[str]:
    """Convert HSE2 tab state into a CLI argument list."""

    plan = build_hse2_gui_command(
        action=state.action,
        config_path=state.config_path,
        input_path=state.input_path,
        output_path=state.output_path,
        size=state.size,
        force=state.force,
        scope=state.scope,
        validation_report_output=state.validation_report_output,
        validation_summary_only=state.validation_summary_only,
        validation_exit_code_on_failure=state.validation_exit_code_on_failure,
        wrapper_id=state.wrapper_id,
        password_file=state.password_file,
        keyfile_path=state.keyfile_path,
        allow_dpapi=state.allow_dpapi,
        access_confirmation_phrase=state.access_confirmation_phrase,
    )
    return list(plan.argv)


class HSE2ExperimentalTab(ttk.Frame):
    """Compact experimental HSE2 tab that delegates execution to an injected runner."""

    def __init__(self, master: tk.Misc, run_command: RunCommand) -> None:
        super().__init__(master, padding=12)
        self._run_command = run_command
        self.columnconfigure(1, weight=1)

        self.action = tk.StringVar(value="encrypt-config")
        self.config_path = tk.StringVar()
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.size = tk.IntVar(value=32)
        self.force = tk.BooleanVar(value=False)
        self.scope = tk.StringVar(value="current_user")
        self.validation_report_output = tk.StringVar()
        self.validation_summary_only = tk.BooleanVar(value=False)
        self.validation_exit_code_on_failure = tk.BooleanVar(value=False)
        self.wrapper_id = tk.StringVar()
        self.password_file = tk.StringVar()
        self.keyfile_path = tk.StringVar()
        self.allow_dpapi = tk.BooleanVar(value=False)
        self.access_confirmation_phrase = tk.StringVar()

        self._build_widgets()

    def state(self) -> HSE2GuiTabState:
        """Return current widget state as a serializable object."""

        return HSE2GuiTabState(
            action=self.action.get(),
            config_path=self.config_path.get(),
            input_path=self.input_path.get(),
            output_path=self.output_path.get(),
            size=int(self.size.get()),
            force=bool(self.force.get()),
            scope=self.scope.get(),
            validation_report_output=self.validation_report_output.get(),
            validation_summary_only=bool(self.validation_summary_only.get()),
            validation_exit_code_on_failure=bool(self.validation_exit_code_on_failure.get()),
            wrapper_id=self.wrapper_id.get(),
            password_file=self.password_file.get(),
            keyfile_path=self.keyfile_path.get(),
            allow_dpapi=bool(self.allow_dpapi.get()),
            access_confirmation_phrase=self.access_confirmation_phrase.get(),
        )

    def build_command(self) -> list[str]:
        """Build CLI argv from the current tab state."""

        return build_hse2_command_from_tab_state(self.state())

    def run_selected_action(self) -> None:
        """Build and run the selected HSE2 action through the injected GUI runner."""

        if not self._confirm_destructive_action():
            return
        self._run_command(self.build_command())

    def _build_widgets(self) -> None:
        ttk.Label(
            self,
            text=(
                "HSE2 实验入口：本页只构造并运行现有 CLI 命令，不在 GUI 层重写加密逻辑。"
                "请先准备对应 JSON 配置、keyfile 或 .hse2 容器路径。"
            ),
            wraplength=780,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        _add_choice_row(self, 1, "操作", self.action, tuple(HSE2_GUI_ACTION_LABELS.keys()))
        _add_path_row(self, 2, "配置文件", self.config_path, self._browse_config)
        _add_path_row(self, 3, "输入文件 / .hse2 容器", self.input_path, self._browse_input)
        _add_path_row(self, 4, "输出文件", self.output_path, self._browse_output, save=True)
        _add_path_row(self, 5, "校验报告保存到", self.validation_report_output, self._browse_validation_report, save=True)

        ttk.Label(self, text="keyfile 大小").grid(row=6, column=0, sticky="w", pady=4)
        ttk.Spinbox(self, from_=16, to=1048576, textvariable=self.size, width=12).grid(
            row=6,
            column=1,
            sticky="w",
            padx=(8, 8),
            pady=4,
        )
        _add_choice_row(self, 7, "DPAPI scope", self.scope, ("current_user", "local_machine"))
        _add_text_row(self, 8, "wrapper id", self.wrapper_id)
        _add_path_row(self, 9, "密码文件", self.password_file, self._browse_password_file)
        _add_path_row(self, 10, "keyfile", self.keyfile_path, self._browse_keyfile)
        _add_text_row(self, 11, "永久禁用访问确认短语", self.access_confirmation_phrase)

        ttk.Label(
            self,
            text=f"危险操作确认短语：{DESTROY_ACCESS_CONFIRMATION_PHRASE}",
            wraplength=780,
            justify=tk.LEFT,
        ).grid(row=12, column=0, columnspan=3, sticky="ew", pady=(6, 0))

        options = ttk.Frame(self)
        options.grid(row=13, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(options, text="允许覆盖输出文件", variable=self.force).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(options, text="HSE2 校验只输出摘要", variable=self.validation_summary_only).pack(
            side=tk.LEFT,
            padx=(0, 12),
        )
        ttk.Checkbutton(
            options,
            text="HSE2 校验失败时返回失败状态",
            variable=self.validation_exit_code_on_failure,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(options, text="允许 DPAPI 解锁 wrapper", variable=self.allow_dpapi).pack(side=tk.LEFT)

        ttk.Button(self, text="运行 HSE2 实验操作", command=self.run_selected_action).grid(
            row=14,
            column=0,
            sticky="w",
            pady=(14, 0),
        )

    def _confirm_destructive_action(self) -> bool:
        action = self.action.get()
        if action == "wrapper-remove":
            return messagebox.askyesno(
                "确认移除 wrapper",
                "该操作会写出一个移除指定 wrapper 的新 HSE2 容器。请确认已保留可用访问方式。是否继续？",
            )
        if action == "access-destroy":
            return messagebox.askyesno(
                "确认永久禁用访问",
                "该操作会写出一个移除全部 wrapper 且标记 access_destroyed 的新 HSE2 容器。数据将无法再解锁。是否继续？",
            )
        return True

    def _browse_config(self) -> None:
        _browse_open(self.config_path, [("JSON 文件", "*.json"), ("所有文件", "*.*")])

    def _browse_input(self) -> None:
        _browse_open(self.input_path, [("HSE2 容器", "*.hse2"), ("所有文件", "*.*")])

    def _browse_output(self) -> None:
        _browse_save(self.output_path, "")

    def _browse_validation_report(self) -> None:
        _browse_save(self.validation_report_output, ".json")

    def _browse_password_file(self) -> None:
        _browse_open(self.password_file, [("文本文件", "*.txt"), ("所有文件", "*.*")])

    def _browse_keyfile(self) -> None:
        _browse_open(self.keyfile_path, [("所有文件", "*.*")])


def build_hse2_experimental_tab(notebook: ttk.Notebook, run_command: RunCommand) -> HSE2ExperimentalTab:
    """Create and add the HSE2 experimental tab to a notebook."""

    tab = HSE2ExperimentalTab(notebook, run_command)
    notebook.add(tab, text="HSE2 实验")
    return tab


def _add_choice_row(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, values: tuple[str, ...]) -> None:
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
    ttk.Combobox(parent, textvariable=variable, values=values, state="readonly").grid(
        row=row,
        column=1,
        sticky="ew",
        padx=(8, 8),
        pady=4,
    )


def _add_text_row(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
    ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=4)


def _add_path_row(
    parent: ttk.Frame,
    row: int,
    label: str,
    variable: tk.StringVar,
    browse_command: Callable[[], None],
    *,
    save: bool = False,
) -> None:
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
    ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=(8, 8), pady=4)
    ttk.Button(parent, text="保存到" if save else "选择", command=browse_command).grid(row=row, column=2, pady=4)


def _browse_open(variable: tk.StringVar, filetypes: list[tuple[str, str]]) -> None:
    path = filedialog.askopenfilename(title="选择文件", filetypes=filetypes)
    if path:
        variable.set(path)


def _browse_save(variable: tk.StringVar, default_extension: str) -> None:
    path = filedialog.asksaveasfilename(
        title="选择保存位置",
        defaultextension=default_extension,
        filetypes=[("所有文件", "*.*")],
    )
    if path:
        variable.set(path)
