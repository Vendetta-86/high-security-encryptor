"""Reusable Tkinter tab component for explicit HSE2 workflows.

The component is intentionally isolated from the main GUI module so that the HSE2
experimental UI can be reviewed and tested before being wired into the existing
large Tkinter application.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .dpapi_guidance import DPAPI_LOCAL_MACHINE_SCOPE_WARNING, DPAPI_WRAPPER_PORTABILITY_WARNING
from .hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE
from .hse2_gui_actions import HSE2_GUI_ACTION_LABELS, build_hse2_gui_command


RunCommand = Callable[[list[str]], None]
FieldWidgets = tuple[tk.Widget, ...]


HSE2_GUI_FIELD_VISIBILITY: dict[str, frozenset[str]] = {
    "encrypt-config": frozenset({"config_path"}),
    "decrypt-config": frozenset({"config_path"}),
    "archive-create": frozenset({
        "root_path", "output_path", "password_file", "keyfile_path", "archive_profile", "archive_format_version",
        "archive_chunk_size", "new_wrapper_dpapi", "force", "archive_pad_last_chunk", "paranoid_warning", "dpapi_warning",
        "archive_validate_after_create",
    }),
    "archive-open": frozenset({
        "input_path", "output_path", "password_file", "keyfile_path", "allow_dpapi", "force", "dpapi_warning",
    }),
    "validate": frozenset(
        {
            "config_path",
            "validation_report_output",
            "validation_summary_only",
            "validation_exit_code_on_failure",
        }
    ),
    "inspect": frozenset({"input_path"}),
    "header-backup-export": frozenset({"input_path", "output_path", "force"}),
    "rotate-keyfile": frozenset({"config_path"}),
    "generate-keyfile": frozenset({"output_path", "size", "force", "paranoid_warning"}),
    "dpapi-protect": frozenset({"input_path", "output_path", "scope", "force", "dpapi_warning"}),
    "wrapper-list": frozenset({"input_path"}),
    "wrapper-add": frozenset({
        "input_path", "output_path", "wrapper_id", "password_file", "keyfile_path", "new_password_file",
        "new_keyfile_path", "new_kdf_profile", "new_label", "allow_dpapi", "new_wrapper_dpapi", "force",
        "paranoid_warning", "dpapi_warning",
    }),
    "wrapper-remove": frozenset(
        {"input_path", "output_path", "wrapper_id", "password_file", "keyfile_path", "allow_dpapi", "force", "paranoid_warning"}
    ),
    "wrapper-rewrap": frozenset({
        "input_path", "output_path", "wrapper_id", "new_wrapper_id", "password_file", "keyfile_path",
        "new_password_file", "new_keyfile_path", "new_kdf_profile", "new_label", "allow_dpapi",
        "new_wrapper_dpapi", "force", "paranoid_warning",
        "dpapi_warning",
    }),
    "access-destroy": frozenset(
        {"input_path", "output_path", "password_file", "keyfile_path", "allow_dpapi", "access_confirmation_phrase", "danger_text", "force", "paranoid_warning"}
    ),
}

_OPTION_FIELD_ORDER = (
    "force",
    "validation_summary_only",
    "validation_exit_code_on_failure",
    "allow_dpapi",
    "new_wrapper_dpapi",
    "archive_pad_last_chunk",
    "archive_validate_after_create",
)

_HSE2_KDF_PROFILE_LABELS = {
    "compatible": "兼容旧设备",
    "hardened": "推荐高安全",
    "paranoid": "极高安全",
}

HEADER_BACKUP_RECOVERY_WARNING = (
    "重要：header backup 只用于恢复容器头部，不能恢复或替代解锁所需的密码、keyfile 或 DPAPI 访问条件。"
    "建议在创建归档后立即导出，并将备份与 .hse2 容器分开保存；同时继续保管原有解锁因子。"
)


def hse2_kdf_profile_display_values() -> tuple[str, ...]:
    return tuple(_HSE2_KDF_PROFILE_LABELS.values())


def hse2_kdf_profile_key_from_display(value: str) -> str:
    normalized = value.strip()
    if normalized in _HSE2_KDF_PROFILE_LABELS:
        return normalized
    for key, label in _HSE2_KDF_PROFILE_LABELS.items():
        if normalized == label:
            return key
    raise ValueError("请选择有效的 HSE2 密码 wrapper 安全等级。")


def should_show_paranoid_profile_warning(action: str, new_profile: str, new_password_file: str) -> bool:
    return (
        hse2_gui_action_key_from_display(action) in {"archive-create", "wrapper-add", "wrapper-rewrap"}
        and hse2_kdf_profile_key_from_display(new_profile) == "paranoid"
        and bool(new_password_file.strip())
    )


def dpapi_warning_for_state(action: str, scope: str, new_wrapper_dpapi: bool) -> str | None:
    normalized_action = hse2_gui_action_key_from_display(action)
    if normalized_action == "dpapi-protect" and scope == "local_machine":
        return DPAPI_LOCAL_MACHINE_SCOPE_WARNING
    if normalized_action in {"archive-create", "archive-open", "wrapper-add", "wrapper-rewrap"} and new_wrapper_dpapi:
        return DPAPI_WRAPPER_PORTABILITY_WARNING
    return None


@dataclass(frozen=True)
class HSE2GuiTabState:
    """Serializable field values collected by the HSE2 experimental tab."""

    action: str
    config_path: str = ""
    root_path: str = ""
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
    new_wrapper_id: str = ""
    new_password_file: str = ""
    new_keyfile_path: str = ""
    new_kdf_profile: str = "hardened"
    new_label: str = ""
    new_wrapper_dpapi: bool = False
    archive_profile: str = "hardened"
    archive_format_version: str = "2"
    archive_chunk_size: int = 1024 * 1024
    archive_pad_last_chunk: bool = False
    archive_validate_after_create: bool = False
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
        root_path=state.root_path,
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
        new_wrapper_id=state.new_wrapper_id,
        new_password_file=state.new_password_file,
        new_keyfile_path=state.new_keyfile_path,
        new_profile_name=hse2_kdf_profile_key_from_display(state.new_kdf_profile),
        new_label=state.new_label,
        new_wrapper_dpapi=state.new_wrapper_dpapi,
        archive_profile=hse2_kdf_profile_key_from_display(state.archive_profile),
        archive_format_version=int(state.archive_format_version),
        archive_chunk_size=state.archive_chunk_size,
        archive_pad_last_chunk=state.archive_pad_last_chunk,
        archive_validate_after_create=state.archive_validate_after_create,
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
        self.root_path = tk.StringVar()
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
        self.new_wrapper_id = tk.StringVar()
        self.new_password_file = tk.StringVar()
        self.new_keyfile_path = tk.StringVar()
        self.new_kdf_profile = tk.StringVar(value=_HSE2_KDF_PROFILE_LABELS["hardened"])
        self.new_label = tk.StringVar()
        self.new_wrapper_dpapi = tk.BooleanVar(value=False)
        self.archive_profile = tk.StringVar(value=_HSE2_KDF_PROFILE_LABELS["hardened"])
        self.archive_format_version = tk.StringVar(value="2")
        self.archive_chunk_size = tk.IntVar(value=1024 * 1024)
        self.archive_pad_last_chunk = tk.BooleanVar(value=False)
        self.archive_validate_after_create = tk.BooleanVar(value=True)
        self.access_confirmation_phrase = tk.StringVar()

        self._field_widgets: dict[str, FieldWidgets] = {}
        self._option_widgets: dict[str, ttk.Checkbutton] = {}
        self._options_frame: ttk.Frame | None = None

        self._build_widgets()
        self.action_label.trace_add("write", self._on_action_label_changed)
        self.action.trace_add("write", self._on_action_changed)
        self.new_kdf_profile.trace_add("write", lambda *_args: self._apply_action_visibility())
        self.new_password_file.trace_add("write", lambda *_args: self._apply_action_visibility())
        self.password_file.trace_add("write", lambda *_args: self._apply_action_visibility())
        self.allow_dpapi.trace_add("write", lambda *_args: self._apply_action_visibility())
        self.scope.trace_add("write", lambda *_args: self._apply_action_visibility())
        self.new_wrapper_dpapi.trace_add("write", lambda *_args: self._apply_action_visibility())
        self.archive_profile.trace_add("write", lambda *_args: self._apply_action_visibility())
        self._apply_action_visibility()

    def state(self) -> HSE2GuiTabState:
        """Return current widget state as a serializable object."""

        return HSE2GuiTabState(
            action=self.action.get(),
            config_path=self.config_path.get(),
            root_path=self.root_path.get(),
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
            new_wrapper_id=self.new_wrapper_id.get(),
            new_password_file=self.new_password_file.get(),
            new_keyfile_path=self.new_keyfile_path.get(),
            new_kdf_profile=hse2_kdf_profile_key_from_display(self.new_kdf_profile.get()),
            new_label=self.new_label.get(),
            new_wrapper_dpapi=bool(self.new_wrapper_dpapi.get()),
            archive_profile=hse2_kdf_profile_key_from_display(self.archive_profile.get()),
            archive_format_version=self.archive_format_version.get(),
            archive_chunk_size=int(self.archive_chunk_size.get()),
            archive_pad_last_chunk=bool(self.archive_pad_last_chunk.get()),
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

        ttk.Label(
            self,
            text=HEADER_BACKUP_RECOVERY_WARNING,
            wraplength=780,
            justify=tk.LEFT,
            foreground="#9b1c1c",
            font=("TkDefaultFont", 9, "bold"),
        ).grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        dpapi_warning = ttk.Label(
            self,
            text="",
            wraplength=780,
            justify=tk.LEFT,
            foreground="#9b1c1c",
            font=("TkDefaultFont", 9, "bold"),
        )
        self._field_widgets["dpapi_warning"] = (dpapi_warning,)
        dpapi_warning.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        _add_choice_row(self, 3, "操作", self.action_label, hse2_gui_action_display_values())
        self._field_widgets["config_path"] = _add_path_row(self, 4, "配置文件", self.config_path, self._browse_config)
        self._field_widgets["input_path"] = _add_path_row(
            self,
            5,
            "输入文件 / .hse2 容器",
            self.input_path,
            self._browse_input,
        )
        self._field_widgets["output_path"] = _add_path_row(
            self,
            6,
            "输出文件",
            self.output_path,
            self._browse_output,
            save=True,
        )
        self._field_widgets["validation_report_output"] = _add_path_row(
            self,
            7,
            "校验报告保存到",
            self.validation_report_output,
            self._browse_validation_report,
            save=True,
        )
        self._field_widgets["size"] = _add_spin_row(self, 8, "keyfile 大小", self.size)
        self._field_widgets["scope"] = _add_choice_row(self, 9, "DPAPI scope", self.scope, ("current_user", "local_machine"))
        self._field_widgets["wrapper_id"] = _add_text_row(self, 10, "wrapper id", self.wrapper_id)
        self._field_widgets["password_file"] = _add_path_row(self, 11, "密码文件", self.password_file, self._browse_password_file)
        self._field_widgets["keyfile_path"] = _add_path_row(self, 12, "keyfile", self.keyfile_path, self._browse_keyfile)
        self._field_widgets["new_wrapper_id"] = _add_text_row(self, 13, "新 wrapper id（留空则沿用原 ID）", self.new_wrapper_id)
        self._field_widgets["new_password_file"] = _add_path_row(self, 14, "新密码文件", self.new_password_file, self._browse_new_password_file)
        self._field_widgets["new_keyfile_path"] = _add_path_row(self, 15, "新 keyfile", self.new_keyfile_path, self._browse_new_keyfile)
        self._field_widgets["new_kdf_profile"] = _add_choice_row(self, 16, "新密码安全等级", self.new_kdf_profile, hse2_kdf_profile_display_values())
        self._field_widgets["new_label"] = _add_text_row(self, 17, "新 wrapper 标签", self.new_label)
        warning = ttk.Label(
            self,
            text="keyfile 丢失后无法解锁依赖它的容器。请保留独立离线备份，并确认能读取备份；不要把 keyfile 与 .hse2 容器放在同一目录。极高安全会明显增加密码 wrapper 创建、重新包装和解锁所需时间及内存；资源有限时请选择推荐档。",
            wraplength=780,
            justify=tk.LEFT,
        )
        self._field_widgets["paranoid_warning"] = (warning,)
        warning.grid(row=18, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        self._field_widgets["access_confirmation_phrase"] = _add_text_row(
            self,
            19,
            "永久禁用访问确认短语",
            self.access_confirmation_phrase,
        )

        danger_label = ttk.Label(
            self,
            text=f"危险操作确认短语：{DESTROY_ACCESS_CONFIRMATION_PHRASE}",
            wraplength=780,
            justify=tk.LEFT,
        )
        danger_label.grid(row=20, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self._field_widgets["danger_text"] = (danger_label,)

        self._field_widgets["root_path"] = _add_path_row(self, 22, "要加密的文件夹", self.root_path, self._browse_root)
        self._field_widgets["archive_profile"] = _add_choice_row(
            self, 23, "归档密码安全等级", self.archive_profile, hse2_kdf_profile_display_values()
        )
        self._field_widgets["archive_format_version"] = _add_choice_row(
            self, 24, "容器格式版本", self.archive_format_version, ("2", "3")
        )
        self._field_widgets["archive_chunk_size"] = _add_spin_row(
            self, 25, "Payload chunk 大小（字节）", self.archive_chunk_size
        )

        self._options_frame = ttk.Frame(self)
        self._options_frame.grid(row=26, column=0, columnspan=3, sticky="w", pady=(8, 0))
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
            "new_wrapper_dpapi": ttk.Checkbutton(self._options_frame, text="新 wrapper 使用 Windows DPAPI", variable=self.new_wrapper_dpapi),
            "archive_pad_last_chunk": ttk.Checkbutton(self._options_frame, text="隐藏文件精确大小（末块 padding）", variable=self.archive_pad_last_chunk),
            "archive_validate_after_create": ttk.Checkbutton(
                self._options_frame, text="创建后校验归档（不写出明文）", variable=self.archive_validate_after_create
            ),
        }

        ttk.Button(self, text="运行 HSE2 实验操作", command=self.run_selected_action).grid(
            row=27,
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
        action = hse2_gui_action_key_from_display(self.action.get())
        visible_fields = visible_hse2_gui_field_keys(action)
        wrapper_id_labels = {
            "wrapper-add": "新 wrapper id",
            "wrapper-remove": "要移除的 wrapper id",
            "wrapper-rewrap": "要替换的现有 wrapper id",
        }
        if action in wrapper_id_labels:
            self._field_widgets["wrapper_id"][0].configure(text=wrapper_id_labels[action])
        self._option_widgets["new_wrapper_dpapi"].configure(
            text="新建归档使用 Windows DPAPI" if action == "archive-create" else "新 wrapper 使用 Windows DPAPI"
        )
        for field_key, widgets in self._field_widgets.items():
            for widget in widgets:
                if field_key in visible_fields:
                    widget.grid()
                else:
                    widget.grid_remove()

        if "paranoid_warning" in visible_fields:
            always_show_keyfile_risk = action in {
                "generate-keyfile", "wrapper-add", "wrapper-remove", "wrapper-rewrap", "access-destroy"
            }
            if always_show_keyfile_risk or should_show_paranoid_profile_warning(
                action,
                self.archive_profile.get() if action == "archive-create" else self.new_kdf_profile.get(),
                self.password_file.get() if action == "archive-create" else self.new_password_file.get(),
            ):
                for widget in self._field_widgets["paranoid_warning"]:
                    widget.grid()
            else:
                for widget in self._field_widgets["paranoid_warning"]:
                    widget.grid_remove()

        dpapi_enabled = bool(self.new_wrapper_dpapi.get()) or (action == "archive-open" and bool(self.allow_dpapi.get()))
        dpapi_warning = dpapi_warning_for_state(action, self.scope.get(), dpapi_enabled)
        for widget in self._field_widgets["dpapi_warning"]:
            if "dpapi_warning" in visible_fields and dpapi_warning:
                widget.configure(text=dpapi_warning)
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
                "该操作会写出一个移除指定 wrapper 的新 HSE2 容器。请确认仍保留可用访问方式；若保留的方式依赖 keyfile，请确认已有独立离线备份且可读取。是否继续？",
            )
        if action == "wrapper-rewrap":
            portability_warning = (
                f"\n\n{DPAPI_WRAPPER_PORTABILITY_WARNING}"
                if self.new_wrapper_dpapi.get()
                else ""
            )
            return messagebox.askyesno(
                "确认更换 wrapper",
                "该操作会用新访问因子替换指定 wrapper，并写出新的 HSE2 容器。请确认新密码/keyfile/DPAPI 可用、已保留旧容器；keyfile 请另存可读取的离线备份，丢失可能导致容器无法恢复。"
                f"{portability_warning}\n\n是否继续？",
            )
        if action == "wrapper-add":
            portability_warning = (
                f"\n\n{DPAPI_WRAPPER_PORTABILITY_WARNING}"
                if self.new_wrapper_dpapi.get()
                else ""
            )
            return messagebox.askyesno(
                "确认添加 wrapper",
                "该操作会使用现有解锁因子验证容器，并写出包含新 wrapper 的 HSE2 副本。请确认新访问因子已安全保存；若使用 keyfile，请保留独立、可读取的离线备份。"
                f"{portability_warning}\n\n是否继续？",
            )
        if action == "access-destroy":
            return messagebox.askyesno(
                "确认永久禁用访问",
                "该操作会写出一个移除全部 wrapper 且标记 access_destroyed 的新 HSE2 容器。数据将无法再解锁。是否继续？",
            )
        if action == "archive-create" and self.force.get() and self.output_path.get().strip():
            if Path(self.output_path.get().strip()).exists():
                return messagebox.askyesno(
                    "确认覆盖 HSE2 归档",
                    "输出路径已存在。覆盖会替换现有容器；请确认已有安全备份和可用解锁因子。是否继续？",
                )
        return True

    def _browse_config(self) -> None:
        _browse_open(self.config_path, [("JSON 文件", "*.json"), ("所有文件", "*.*")])

    def _browse_input(self) -> None:
        _browse_open(self.input_path, [("HSE2 容器", "*.hse2"), ("所有文件", "*.*")])

    def _browse_root(self) -> None:
        path = filedialog.askdirectory(title="选择要加密的文件夹")
        if path:
            self.root_path.set(path)

    def _browse_output(self) -> None:
        _browse_save(self.output_path, "")

    def _browse_validation_report(self) -> None:
        _browse_save(self.validation_report_output, ".json")

    def _browse_password_file(self) -> None:
        _browse_open(self.password_file, [("文本文件", "*.txt"), ("所有文件", "*.*")])

    def _browse_keyfile(self) -> None:
        _browse_open(self.keyfile_path, [("所有文件", "*.*")])

    def _browse_new_password_file(self) -> None:
        _browse_open(self.new_password_file, [("文本文件", "*.txt"), ("所有文件", "*.*")])

    def _browse_new_keyfile(self) -> None:
        _browse_open(self.new_keyfile_path, [("所有文件", "*.*")])


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
