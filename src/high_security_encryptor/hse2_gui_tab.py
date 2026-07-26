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
FieldWidgets = tuple[tk.Widget, ...]


HSE2_GUI_FIELD_VISIBILITY: dict[str, frozenset[str]] = {
    "encrypt-config": frozenset({"config_path"}),
    "decrypt-config": frozenset({"config_path"}),
    "validate": frozenset(
        {
            "config_path",
            "validation_report_output",
            "validation_summary_only",
            "validation_exit_code_on_failure",
        }
    ),
    "inspect": frozenset({"input_path"}),
    "rotate-keyfile": frozenset({"config_path"}),
    "generate-keyfile": frozenset({"output_path", "size", "force"}),
    "dpapi-protect": frozenset({"input_path", "output_path", "scope", "force"}),
    "wrapper-list": frozenset({"input_path"}),
    "wrapper-remove": frozenset(
        {"input_path", "output_path", "wrapper_id", "password_file", "keyfile_path", "allow_dpapi", "force"}
    ),
    "access-destroy": frozenset(
        {"input_path", "output_path", "access_confirmation_phrase", "danger_text", "force"}
    ),
}

_OPTION_FIELD_ORDER = (
    "force",
    "validation_summary_only",
    "validation_exit_code_on_failure",
    "allow_dpapi",
)


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


def hse2_gui_action_display_values() -> tuple[str, ...]:
    """Return localized action labels for the HSE2 action combobox."""

    return tuple(HSE2_GUI_ACTION_LABELS[action] for action in HSE2_GUI_FIELD_VISIBILITY)


def hse2_gui_action_key_from_display(value: str) -> str:
    """Resolve a localized action label or stable action key to the stable action key."""

    normalized = value.strip()
    if normalized in HSE2_GUI_FIELD_VISIBILITY:
        return normalized
    for action, label in HSE2_GUI_ACTION_LABELS.items():
        if normalized == label:
            return action
    raise ValueError("请选择有效的 HSE2 实验操作。")


def hse2_gui_action_display_label(action: str) -> str:
    """Return the localized combobox label for an HSE2 action key or label."""

    return HSE2_GUI_ACTION_LABELS[hse2_gui_action_key_from_display(action)]


def visible_hse2_gui_field_keys(action: str) -> frozenset[str]:
    """Return the GUI field keys that should be visible for one HSE2 action."""

    normalized_action = hse2_gui_action_key_from_display(action)
    return HSE2_GUI_FIELD_VISIBILITY[normalized_action]


def build_hse2_command_from_tab_state(state: HSE2GuiTabState) -> list[str]:
    """Convert HSE2 tab state into a CLI argument list."""

    plan = build_hse2_gui_command(
        action=hse2_gui_action_key_from_display(state.action),
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
        self.action_label = tk.StringVar(value=hse2_gui_action_display_label(self.action.get()))
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

        self._field_widgets: dict[str, FieldWidgets] = {}
        self._option_widgets: dict[str, ttk.Checkbutton] = {}
        self._options_frame: ttk.Frame | None = None

        self._build_widgets()
        self.action_label.trace_add("write", self._on_action_label_changed)
        self.action.trace_add("write", self._on_action_changed)
        self._apply_action_visibility()

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

        _add_choice_row(self, 1, "操作", self.action_label, hse2_gui_action_display_values())
        self._field_widgets["config_path"] = _add_path_row(self, 2, "配置文件", self.config_path, self._browse_config)
        self._field_widgets["input_path"] = _add_path_row(
            self,
            3,
            "输入文件 / .hse2 容器",
            self.input_path,
            self._browse_input,
        )
        self._field_widgets["output_path"] = _add_path_row(
            self,
            4,
            "输出文件",
            self.output_path,
            self._browse_output,
            save=True,
        )
        self._field_widgets["validation_report_output"] = _add_path_row(
            self,
            5,
            "校验报告保存到",
            self.validation_report_output,
            self._browse_validation_report,
            save=True,
        )
        self._field_widgets["size"] = _add_spin_row(self, 6, "keyfile 大小", self.size)
        self._field_widgets["scope"] = _add_choice_row(self, 7, "DPAPI scope", self.scope, ("current_user", "local_machine"))
        self._field_widgets["wrapper_id"] = _add_text_row(self, 8, "wrapper id", self.wrapper_id)
        self._field_widgets["password_file"] = _add_path_row(self, 9, "密码文件", self.password_file, self._browse_password_file)
        self._field_widgets["keyfile_path"] = _add_path_row(self, 10, "keyfile", self.keyfile_path, self._browse_keyfile)
        self._field_widgets["access_confirmation_phrase"] = _add_text_row(
            self,
            11,
            "永久禁用访问确认短语",
            self.access_confirmation_phrase,
        )

        danger_label = ttk.Label(
            self,
            text=f"危险操作确认短语：{DESTROY_ACCESS_CONFIRMATION_PHRASE}",
            wraplength=780,
            justify=tk.LEFT,
        )
        danger_label.grid(row=12, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self._field_widgets["danger_text"] = (danger_label,)

        self._options_frame = ttk.Frame(self)
        self._options_frame.grid(row=13, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self._option_widgets = {
            "force": ttk.Checkbutton(self._options_frame, text="允许覆盖输出文件", variable=self.force),
            "validation_summary_only": ttk.Checkbutton(
                self._options_frame,
                text="HSE2 校验只输出摘要",
                variable=self.validation_summary_only,
            ),
            "validation_exit_code_on_failure": ttk.Checkbutton(
                self._options_frame,
                text="HSE2 校验失败时返回失败状态",
                variable=self.validation_exit_code_on_failure,
            ),
            "allow_dpapi": ttk.Checkbutton(
                self._options_frame,
                text="允许 DPAPI 解锁 wrapper",
                variable=self.allow_dpapi,
            ),
        }

        ttk.Button(self, text="运行 HSE2 实验操作", command=self.run_selected_action).grid(
            row=14,
            column=0,
            sticky="w",
            pady=(14, 0),
        )

    def _on_action_label_changed(self, *_args: object) -> None:
        normalized_action = hse2_gui_action_key_from_display(self.action_label.get())
        if self.action.get() != normalized_action:
            self.action.set(normalized_action)

    def _on_action_changed(self, *_args: object) -> None:
        display_label = hse2_gui_action_display_label(self.action.get())
        if self.action_label.get() != display_label:
            self.action_label.set(display_label)
        self._apply_action_visibility()

    def _apply_action_visibility(self) -> None:
        visible_fields = visible_hse2_gui_field_keys(self.action.get())
        for field_key, widgets in self._field_widgets.items():
            for widget in widgets:
                if field_key in visible_fields:
                    widget.grid()
                else:
                    widget.grid_remove()

        if self._options_frame is None:
            return
        any_visible_option = False
        for field_key in _OPTION_FIELD_ORDER:
            widget = self._option_widgets[field_key]
            widget.pack_forget()
            if field_key in visible_fields:
                any_visible_option = True
                widget.pack(side=tk.LEFT, padx=(0, 12))
        if any_visible_option:
            self._options_frame.grid()
        else:
            self._options_frame.grid_remove()

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


def _add_choice_row(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, values: tuple[str, ...]) -> FieldWidgets:
    label_widget = ttk.Label(parent, text=label)
    label_widget.grid(row=row, column=0, sticky="w", pady=4)
    choice_widget = ttk.Combobox(parent, textvariable=variable, values=values, state="readonly")
    choice_widget.grid(
        row=row,
        column=1,
        sticky="ew",
        padx=(8, 8),
        pady=4,
    )
    return (label_widget, choice_widget)


def _add_spin_row(parent: ttk.Frame, row: int, label: str, variable: tk.IntVar) -> FieldWidgets:
    label_widget = ttk.Label(parent, text=label)
    label_widget.grid(row=row, column=0, sticky="w", pady=4)
    spin_widget = ttk.Spinbox(parent, from_=16, to=1048576, textvariable=variable, width=12)
    spin_widget.grid(
        row=row,
        column=1,
        sticky="w",
        padx=(8, 8),
        pady=4,
    )
    return (label_widget, spin_widget)


def _add_text_row(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> FieldWidgets:
    label_widget = ttk.Label(parent, text=label)
    label_widget.grid(row=row, column=0, sticky="w", pady=4)
    entry_widget = ttk.Entry(parent, textvariable=variable)
    entry_widget.grid(row=row, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=4)
    return (label_widget, entry_widget)


def _add_path_row(
    parent: ttk.Frame,
    row: int,
    label: str,
    variable: tk.StringVar,
    browse_command: Callable[[], None],
    *,
    save: bool = False,
) -> FieldWidgets:
    label_widget = ttk.Label(parent, text=label)
    label_widget.grid(row=row, column=0, sticky="w", pady=4)
    entry_widget = ttk.Entry(parent, textvariable=variable)
    entry_widget.grid(row=row, column=1, sticky="ew", padx=(8, 8), pady=4)
    button_widget = ttk.Button(parent, text="保存到" if save else "选择", command=browse_command)
    button_widget.grid(row=row, column=2, pady=4)
    return (label_widget, entry_widget, button_widget)


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
