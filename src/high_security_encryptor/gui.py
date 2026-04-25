"""Tkinter GUI wrapper for High Security Encryptor."""

from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
import argparse
import io
import json
import os
from pathlib import Path
import shlex
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:  # pragma: no cover - exercised only when optional GUI dependency is missing.
    DND_FILES = None
    TkinterDnD = None

from .api import decrypt_file_streaming, encrypt_file_streaming
from .batch_workflow_inputs import get_encrypted_target_path
from .cli import main as cli_main
from .folder_decryption import decrypt_folder_archive
from .folder_workflow import get_folder_package_target_path, package_folder_to_encrypted_archive
from .removable_bitlocker import (
    BitLockerActionResult,
    RemovableStorageDevice,
    RemovableStorageInventory,
    RemovableStorageError,
    enable_removable_bitlocker,
    list_removable_storage_devices,
    lock_removable_bitlocker,
    open_mount_point,
    unlock_removable_bitlocker,
)


SECURITY_MODES = ("compatible", "hardened", "no-password-tables")
CONFIG_KINDS = ("encrypt", "decrypt")
REPORT_FORMATS = ("json", "text")
QUICK_ACTIONS = ("encrypt", "decrypt")
PASSWORD_OUTPUT_ENV = "env"
PASSWORD_OUTPUT_LITERAL = "literal"
REMOVABLE_ENCRYPTION_METHODS = ("XtsAes256", "XtsAes128", "Aes256", "Aes128")

SECURITY_MODE_LABELS = {
    "compatible": "简单兼容：保存完整密码表",
    "hardened": "推荐安全：少保存一份密码表",
    "no-password-tables": "最高隐私：不保存密码表",
}
CONFIG_KIND_LABELS = {
    "encrypt": "加密配置",
    "decrypt": "解密配置",
}
REPORT_FORMAT_LABELS = {
    "json": "JSON 格式：方便程序读取",
    "text": "文本格式：方便人工查看",
}
QUICK_ACTION_LABELS = {
    "encrypt": "加密",
    "decrypt": "解密",
}
REMOVABLE_ENCRYPTION_METHOD_LABELS = {
    "XtsAes256": "XTS-AES 256 位（推荐）",
    "XtsAes128": "XTS-AES 128 位",
    "Aes256": "AES-CBC 256 位",
    "Aes128": "AES-CBC 128 位",
}

PASSWORD_PROVIDER_HINT = (
    "图形界面不会弹出控制台输入框。配置里的密码请使用直接填写、环境变量、本地文件或命令输出。"
)

HELP_TEXT = """使用说明

快速使用
适合临时、紧急、单次处理。选择文件或文件夹，或者把文件/文件夹直接拖进路径框，输入密码，点击“一键开始”。不需要写 JSON 配置。

加密：文件会生成 .hse；文件夹会生成一个加密后的文件夹文件。输出默认放在原文件旁边，遇到重名会自动改名，不会覆盖已有文件。
解密：选择 .hse 或 .zip.hse 文件，输入主加密密码。普通文件会恢复到同目录；文件夹会解到一个新的目录。
多个文件：点击“多个文件加密”或拖入多个项目，系统会转到“文件加密”的多文件配置；多个 .hse 文件会转到“文件解密”的多文件配置。
主加密密码：加密时需要输入两次确认。请务必记住主加密密码，密码丢失后无法恢复。

检查配置
用于在真正加密或解密前检查 JSON 配置文件。它不会处理文件，只验证配置能否被程序识别，并在需要时列出异常、警告和解决建议。

配置用途：选择这份 JSON 是加密配置还是解密配置。选错用途时，字段校验会按错误的规则执行。
配置文件：选择要检查的 JSON 文件。
结果格式：JSON 适合复制给程序或 issue；文本格式适合直接阅读。
结果保存到：可选。填写后会把检查报告写入文件。
高级检查：在基础格式检查之外，额外检查安全模式和密码表策略是否一致。
显示检查结果：输出完整检查报告。
只看摘要：只输出错误和警告数量等摘要信息。
发现异常后退出检查：只要发现 error 级异常，就用失败状态结束，适合发布前检查。
出现警告后退出检查：warning 级问题也会用失败状态结束，适合更严格的发布流程。

文件加密
用于处理多个文件、多个文件夹，或运行已有加密配置。

运行已有配置：选择加密 JSON 配置文件后开始加密。图形界面不支持 prompt 密码来源，请使用直接填写、环境变量、本地文件或命令输出。
多文件配置：一行一个文件或文件夹。系统会先整理为一个加密包，再用主加密密码保护整个包。需要给某个文件夹内的子文件单独加密时，填写“文件夹路径|子文件相对路径|密码”。
加密密码表：默认会输出加密的 batch_password_table.hsm。也可以手动指定密码表、manifest、template 的保存路径，不必和加密包放在同一目录。

文件解密
用于恢复多个已加密文件、文件夹包，或运行已有解密配置。

运行已有配置：选择解密 JSON 配置文件后开始解密。密码、manifest、模板和密码表需要属于同一批次，否则完整性校验会失败。
多文件配置：可以手动指定 encrypted files、manifest、密码表、template 和输出目录，适合这些文件不在同一目录的情况。

生成配置
用于生成可编辑的示例 JSON。先生成示例，再按实际文件路径和密码来源修改，最后用“检查配置”验证。

密码表保存方式：选择安全模式。简单兼容会保存完整密码表；推荐安全会减少顶层密码表；最高隐私不保存密码表，需要模板和运行时密码来源。
配置用途：选择生成加密配置或解密配置。
保存为：选择示例 JSON 的保存位置。
生成配置文件：写出示例配置文件。"""


HELP_TEXT += """

移动存储加密
用于 Windows 的 BitLocker To Go。这个页面会读取系统上的 USB 或 SD 移动存储设备信息，并在设备级别启用整盘加密。
设备加密后，未解锁前不能正常读写；解锁只恢复本次访问权限，不会删除密码；设备拔出后仍保持加密状态，再次插入时仍需重新解锁。
该功能需要管理员权限运行程序，建议同时保存恢复信息文件，避免忘记密码后无法恢复数据。
"""


@dataclass(frozen=True)
class GuiCommandResult:
    """Captured result from an existing CLI command."""

    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class QuickActionResult:
    """Result from the simplified one-click workflow."""

    action: str
    output_path: Path
    detail: str


@dataclass(frozen=True)
class GeneratedConfigPlan:
    """Config payload plus runtime-only secrets needed for immediate GUI execution."""

    payload: dict[str, Any]
    runtime_env: dict[str, str]


def invoke_cli_command(args: list[str]) -> GuiCommandResult:
    """Run the existing CLI implementation and capture its text output."""

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        exit_code = cli_main(args)
    return GuiCommandResult(
        exit_code=exit_code,
        stdout=stdout_buffer.getvalue(),
        stderr=stderr_buffer.getvalue(),
    )


def build_validate_config_args(
    *,
    kind: str,
    config_path: str,
    strict: bool,
    report: bool,
    report_format: str,
    output_path: str,
    summary_only: bool,
    exit_code_on_issues: bool,
    warnings_as_errors: bool,
) -> list[str]:
    """Build CLI arguments for config validation."""

    normalized_config_path = _require_path(config_path, "请选择配置文件。")
    effective_exit_code_on_issues = exit_code_on_issues or warnings_as_errors
    effective_report = report or effective_exit_code_on_issues
    args = [
        "validate-config",
        "--kind",
        _require_choice(kind, CONFIG_KINDS, "请选择加密配置或解密配置。", CONFIG_KIND_LABELS),
        "--config",
        normalized_config_path,
    ]
    if strict:
        args.append("--strict")
    if effective_report:
        args.append("--report")
        args.extend(
            [
                "--format",
                _require_choice(report_format, REPORT_FORMATS, "请选择报告格式。", REPORT_FORMAT_LABELS),
            ]
        )
        if summary_only and not effective_exit_code_on_issues:
            args.append("--summary-only")
        if output_path.strip():
            args.extend(["--output", output_path.strip()])
        if effective_exit_code_on_issues:
            args.append("--exit-code-on-issues")
        if warnings_as_errors:
            args.append("--warnings-as-errors")
    return args


def build_batch_args(*, command: str, config_path: str) -> list[str]:
    """Build CLI arguments for batch encryption or decryption."""

    if command not in {"encrypt-batch", "decrypt-batch"}:
        raise ValueError("请选择 encrypt-batch 或 decrypt-batch。")
    return [command, "--config", _require_path(config_path, "请选择配置文件。")]


def build_init_example_args(*, mode: str, kind: str, output_path: str) -> list[str]:
    """Build CLI arguments for example config generation."""

    return [
        "init-example",
        "--mode",
        _require_choice(mode, SECURITY_MODES, "请选择保存密码表的方式。", SECURITY_MODE_LABELS),
        "--kind",
        _require_choice(kind, CONFIG_KINDS, "请选择加密配置或解密配置。", CONFIG_KIND_LABELS),
        "--output",
        _require_path(output_path, "请选择输出路径。"),
    ]


def parse_nonempty_lines(value: str) -> list[str]:
    """Parse newline-separated text fields."""

    return [line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith("#")]


def parse_password_override_lines(value: str) -> dict[str, str]:
    """Parse `path=password` lines used by the file-config tab."""

    overrides: dict[str, str] = {}
    for line in parse_nonempty_lines(value):
        if "=" not in line:
            raise ValueError(f"密码行需要使用 路径=密码 格式：{line}")
        path, password = line.split("=", 1)
        path = path.strip()
        password = password.strip()
        if not path or not password:
            raise ValueError(f"密码行的路径和密码都不能为空：{line}")
        overrides[path] = password
    return overrides


def parse_folder_inner_password_lines(value: str) -> tuple[dict[str, list[str]], dict[str, dict[str, str]]]:
    """Parse `folder|relative/path|password` lines for folder-internal encryption."""

    selections: dict[str, list[str]] = {}
    passwords: dict[str, dict[str, str]] = {}
    for line in parse_nonempty_lines(value):
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 3:
            raise ValueError(f"文件夹内单独加密行需要使用 文件夹路径|相对路径|密码 格式：{line}")
        folder, relative_path, password = parts
        if not folder or not relative_path or not password:
            raise ValueError(f"文件夹路径、相对路径和密码都不能为空：{line}")
        selections.setdefault(folder, [])
        if relative_path not in selections[folder]:
            selections[folder].append(relative_path)
        passwords.setdefault(folder, {})[relative_path] = password
    return selections, passwords


def build_file_encryption_config_plan(
    *,
    sources_text: str,
    default_password: str,
    metadata_password: str,
    output_dir: str,
    security_mode: str,
    source_passwords_text: str = "",
    folder_inner_passwords_text: str = "",
    bundle_output_path: str = "",
    manifest_output_path: str = "",
    password_table_output_path: str = "",
    template_output_path: str = "",
    package_as_bundle: bool | None = None,
    write_password_table: bool | None = None,
    write_internal_password_tables: bool | None = None,
    password_output: str = PASSWORD_OUTPUT_ENV,
) -> GeneratedConfigPlan:
    """Build an encryption config without persisting GUI-entered secrets by default."""

    sources = parse_nonempty_lines(sources_text)
    if not sources:
        raise ValueError("请至少添加一个要加密的文件或文件夹。")
    if not default_password:
        raise ValueError("请输入主加密密码。")
    if not metadata_password:
        metadata_password = default_password
    output_dir = _require_path(output_dir, "请选择输出目录。")
    security_mode_value = _require_choice(security_mode, SECURITY_MODES, "请选择密码表保存方式。", SECURITY_MODE_LABELS)
    if write_password_table is None:
        write_password_table = security_mode_value == "compatible"
    if write_internal_password_tables is None:
        write_internal_password_tables = security_mode_value in {"compatible", "hardened"}
    source_overrides = parse_password_override_lines(source_passwords_text)
    folder_selections, folder_passwords = parse_folder_inner_password_lines(folder_inner_passwords_text)
    runtime_env: dict[str, str] = {}
    source_passwords = {
        source: _secret_spec_for_gui_password(
            source_overrides.get(source, default_password),
            f"HSE_GUI_SOURCE_PASSWORD_{index}",
            runtime_env,
            password_output,
        )
        for index, source in enumerate(sources, start=1)
    }
    metadata_secret = _secret_spec_for_gui_password(
        metadata_password,
        "HSE_GUI_METADATA_PASSWORD",
        runtime_env,
        password_output,
    )
    folder_secret_specs: dict[str, dict[str, Any]] = {}
    for folder_index, (folder, relative_passwords) in enumerate(folder_passwords.items(), start=1):
        folder_secret_specs[folder] = {}
        for relative_index, (relative_path, password) in enumerate(relative_passwords.items(), start=1):
            folder_secret_specs[folder][relative_path] = _secret_spec_for_gui_password(
                password,
                f"HSE_GUI_FOLDER_INNER_PASSWORD_{folder_index}_{relative_index}",
                runtime_env,
                password_output,
            )
    effective_package_as_bundle = len(sources) > 1 if package_as_bundle is None else bool(package_as_bundle)
    payload: dict[str, Any] = {
        "sources": sources,
        "source_passwords": source_passwords,
        "metadata_password": metadata_secret,
        "output_dir": output_dir,
        "security_mode": security_mode_value,
        "package_as_bundle": effective_package_as_bundle,
        "individually_encrypted_files_by_folder": folder_selections,
        "folder_inner_passwords": folder_secret_specs,
        "write_password_table": bool(write_password_table),
        "write_internal_password_tables": bool(write_internal_password_tables),
    }
    if bundle_output_path.strip() and effective_package_as_bundle:
        payload["bundle_output_path"] = bundle_output_path.strip()
    if manifest_output_path.strip():
        payload["manifest_output_path"] = manifest_output_path.strip()
    if password_table_output_path.strip():
        payload["password_table_output_path"] = password_table_output_path.strip()
    if template_output_path.strip():
        payload["template_output_path"] = template_output_path.strip()
    return GeneratedConfigPlan(payload=payload, runtime_env=runtime_env)


def build_file_encryption_config_payload(**kwargs: Any) -> dict[str, Any]:
    """Build an encryption JSON payload from beginner-friendly text fields."""

    return build_file_encryption_config_plan(**kwargs).payload


def build_file_decryption_config_plan(
    *,
    encrypted_files_text: str,
    manifest_path: str,
    password_table_path: str,
    template_path: str,
    metadata_password: str,
    output_dir: str,
    security_mode: str,
    password_output: str = PASSWORD_OUTPUT_ENV,
) -> GeneratedConfigPlan:
    """Build a decryption config without persisting GUI-entered secrets by default."""

    encrypted_files = parse_nonempty_lines(encrypted_files_text)
    if not encrypted_files:
        raise ValueError("请至少添加一个要解密的 .hse 文件。")
    runtime_env: dict[str, str] = {}
    payload: dict[str, Any] = {
        "encrypted_files": encrypted_files,
        "manifest_path": _require_path(manifest_path, "请选择 manifest 文件。"),
        "password_table_path": _require_path(password_table_path, "请选择加密密码表。"),
        "template_path": _require_path(template_path, "请选择 template 文件。"),
        "metadata_password": _secret_spec_for_gui_password(
            _require_path(metadata_password, "请输入密码表/清单密码。"),
            "HSE_GUI_METADATA_PASSWORD",
            runtime_env,
            password_output,
        ),
        "output_dir": _require_path(output_dir, "请选择输出目录。"),
        "security_mode": _require_choice(security_mode, SECURITY_MODES, "请选择密码表保存方式。", SECURITY_MODE_LABELS),
    }
    if payload["security_mode"] != "compatible":
        raise ValueError("手动指定密码表时，请选择“简单兼容：保存完整密码表”。")
    return GeneratedConfigPlan(payload=payload, runtime_env=runtime_env)


def build_file_decryption_config_payload(**kwargs: Any) -> dict[str, Any]:
    """Build a decryption JSON payload with manually chosen sidecar paths."""

    return build_file_decryption_config_plan(**kwargs).payload


def write_json_config_file(payload: dict[str, Any], output_path: str | Path) -> Path:
    """Persist a generated config payload."""

    target = Path(_require_path(str(output_path), "请选择配置保存路径。"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return target


def run_quick_action(action: str, source_path: str | Path, password: str) -> QuickActionResult:
    """Run the no-config quick encrypt/decrypt workflow."""

    normalized_action = _require_choice(action, QUICK_ACTIONS, "请选择加密或解密。", QUICK_ACTION_LABELS)
    source = Path(source_path)
    if not password:
        raise ValueError("请输入密码。")
    if not source.exists():
        raise FileNotFoundError(source)

    if normalized_action == "encrypt":
        if source.is_dir():
            target = make_available_path(get_folder_package_target_path(source))
            package_folder_to_encrypted_archive(
                source,
                target,
                folder_password=password,
                metadata_password=password,
            )
            return QuickActionResult(
                action=normalized_action,
                output_path=target,
                detail="文件夹已加密。请保存输出文件和主加密密码。",
            )
        if not source.is_file():
            raise ValueError("请选择文件或文件夹。")
        target = make_available_path(get_encrypted_target_path(source))
        encrypt_file_streaming(source, target, password)
        return QuickActionResult(
            action=normalized_action,
            output_path=target,
            detail="文件已加密为 .hse。请保存该文件和主加密密码。",
        )

    if source.name.endswith(".zip.hse"):
        output_dir = make_available_path(source.with_name(f"{source.name[:-8]}_decrypted"))
        result = decrypt_folder_archive(
            source,
            output_dir,
            folder_password=password,
            metadata_password=password,
        )
        return QuickActionResult(
            action=normalized_action,
            output_path=result.extracted_root,
            detail="文件夹包已解密到新目录。",
        )
    if source.name.endswith(".hse"):
        target = make_available_path(source.with_name(source.name[:-4]))
        decrypt_file_streaming(source, target, password)
        return QuickActionResult(
            action=normalized_action,
            output_path=target,
            detail="文件已解密。",
        )
    raise ValueError("快速解密请选择 .hse 或 .zip.hse 文件。")


def make_available_path(path: str | Path) -> Path:
    """Return a non-existing sibling path without overwriting user files."""

    target = Path(path)
    if not target.exists():
        return target
    for index in range(1, 1000):
        candidate = target.with_name(f"{target.stem} ({index}){target.suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"无法为输出自动选择可用文件名：{target}")


def split_drop_paths(data: str, splitlist: Any | None = None) -> list[str]:
    """Parse TkinterDnD file-list payloads into filesystem paths."""

    if not data.strip():
        return []
    if splitlist is not None:
        try:
            return [str(item) for item in splitlist(data) if str(item).strip()]
        except tk.TclError:
            pass
    try:
        interpreter = tk.Tcl()
        return [str(item) for item in interpreter.splitlist(data) if str(item).strip()]
    except tk.TclError:
        return [data.strip()]


def choose_multi_file_workflow(paths: list[str], quick_action: str) -> str:
    """Choose the advanced workflow reached from quick-use multi-file entry points."""

    if not paths:
        raise ValueError("请选择多个文件。")
    action = _require_choice(quick_action, QUICK_ACTIONS, "请选择加密或解密。", QUICK_ACTION_LABELS)
    if action == "decrypt" or all(path.lower().endswith(".hse") for path in paths):
        return "decrypt"
    return "encrypt"


def config_uses_prompt_provider(config_path: str) -> bool:
    """Return whether a config contains prompt password providers."""

    path = Path(config_path)
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return _contains_prompt_provider(payload)


def build_validation_result_guidance(args: list[str], result: GuiCommandResult) -> str:
    """Build a user-facing issue summary for failed GUI validation runs."""

    if result.exit_code == 0 or not args or args[0] != "validate-config":
        return ""

    summary = _extract_json_summary(result.stdout)
    issues = summary.get("issues", []) if isinstance(summary, dict) else []
    if not issues:
        detail = (result.stderr or result.stdout).strip()
        lines = [
            "检查未完成，未取得结构化问题列表。",
            "异常信息：",
            detail or "没有返回详细错误信息。",
            "解决建议：确认配置文件路径存在、JSON 格式正确，并检查配置用途是否选择正确。",
        ]
        return "\n".join(lines)

    lines = ["检查发现的问题和处理建议："]
    for index, issue in enumerate(issues, start=1):
        severity = issue.get("severity", "issue")
        severity_label = {"error": "异常", "warning": "警告"}.get(severity, severity)
        lines.append(f"{index}. {severity_label} {issue.get('code', 'unknown')}")
        lines.append(f"   异常信息：{issue.get('message', '没有返回问题说明。')}")
        lines.append(f"   解决建议：{issue.get('suggestion', '请检查配置文件后重试。')}")
    return "\n".join(lines)


def format_size_bytes(value: int | None) -> str:
    """Format a byte count into a short human-readable string."""

    if value is None:
        return "-"
    size = float(value)
    units = ("B", "KB", "MB", "GB", "TB")
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.1f} {unit}"


def describe_removable_device_status(device: RemovableStorageDevice) -> str:
    """Return a short BitLocker status label for the removable-device table."""

    if device.bitlocker_protection_status == "On":
        return "已加密"
    if device.bitlocker_volume_status == "FullyDecrypted":
        return "未加密"
    if device.bitlocker_volume_status:
        return device.bitlocker_volume_status
    return "未知"


def describe_removable_inventory_status(inventory: RemovableStorageInventory) -> str:
    """Return the status line shown above the removable-device list."""

    if inventory.status_warning:
        return inventory.status_warning
    if not inventory.devices:
        return "未检测到可操作的 USB 或 SD 移动存储设备。"
    return f"已检测到 {len(inventory.devices)} 个可移动存储卷，可在下方选择后执行加密、解锁或上锁。"


def build_removable_action_summary(action: str, result: BitLockerActionResult) -> str:
    """Summarize a removable-device action for the shared GUI log."""

    lines = [
        f"{action}完成：{result.mount_point}",
        f"卷状态：{result.volume_status or '未知'}",
        f"保护状态：{result.protection_status or '未知'}",
        f"锁定状态：{result.lock_status or '未知'}",
    ]
    if result.encryption_percentage is not None:
        lines.append(f"加密进度：{result.encryption_percentage}%")
    if result.encryption_method:
        lines.append(f"加密算法：{result.encryption_method}")
    if result.auto_unlock_enabled is not None:
        lines.append(f"自动解锁：{'开启' if result.auto_unlock_enabled else '关闭'}")
    if result.recovery_file is not None:
        lines.append(f"恢复信息：{result.recovery_file}")
    return "\n".join(lines)


def smoke_test() -> None:
    """Validate GUI imports without opening a window."""

    root = tk.Tcl()
    if not root.call("info", "patchlevel"):
        raise RuntimeError("tkinter 不可用")


def create_gui_root() -> tk.Tk:
    """Create a Tk root with drag-and-drop support when available."""

    if TkinterDnD is not None:
        return TkinterDnD.Tk()
    return tk.Tk()


class HighSecurityEncryptorApp(ttk.Frame):
    """Main Tkinter application."""

    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=12)
        self.master = master
        self.master.title("文件加解密工具")
        self.master.minsize(860, 620)
        self._is_busy = False
        self._last_generated_runtime_env: dict[str, str] = {}

        self.pack(fill=tk.BOTH, expand=True)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_controls()
        self._build_log()
        self.after(150, lambda: self._refresh_removable_devices(show_message=False, write_log=False))

    def _build_controls(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=0, sticky="nsew")
        self.main_notebook = notebook

        self._build_quick_tab(notebook)
        self._build_encrypt_tab(notebook)
        self._build_decrypt_tab(notebook)
        self._build_removable_storage_tab(notebook)
        self._build_validate_tab(notebook)
        self._build_examples_tab(notebook)
        self._build_help_tab(notebook)

    def _build_quick_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="快速使用")
        frame.columnconfigure(1, weight=1)

        self.quick_action = tk.StringVar(value=QUICK_ACTION_LABELS["encrypt"])
        self.quick_source = tk.StringVar()
        self.quick_password = tk.StringVar()
        self.quick_password_confirm = tk.StringVar()

        ttk.Label(
            frame,
            text="不写配置，直接加密或解密一个文件/文件夹。可拖入文件或文件夹，输出不会覆盖已有文件。",
        ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))
        self._add_choice_row(frame, 1, "我要", self.quick_action, _choice_label_values(QUICK_ACTION_LABELS))

        ttk.Label(frame, text="文件或文件夹").grid(row=2, column=0, sticky="w", pady=4)
        source_entry = ttk.Entry(frame, textvariable=self.quick_source)
        source_entry.grid(row=2, column=1, sticky="ew", padx=(8, 8), pady=4)
        ttk.Button(frame, text="选择文件", command=self._browse_quick_file).grid(row=2, column=2, pady=4)
        ttk.Button(frame, text="选择文件夹", command=self._browse_quick_folder).grid(row=2, column=3, pady=4)

        ttk.Label(frame, text="主加密密码").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.quick_password, show="*").grid(
            row=3,
            column=1,
            sticky="ew",
            padx=(8, 8),
            pady=4,
        )
        ttk.Label(frame, text="确认主加密密码").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.quick_password_confirm, show="*").grid(
            row=4,
            column=1,
            sticky="ew",
            padx=(8, 8),
            pady=4,
        )

        ttk.Label(
            frame,
            text="加密时请填写两次主加密密码；解密时只需要填写“主加密密码”。多个文件请用下面的多文件入口。",
        ).grid(row=5, column=0, columnspan=4, sticky="w", pady=(8, 0))
        action_row = ttk.Frame(frame)
        action_row.grid(row=6, column=0, columnspan=4, sticky="w", pady=(14, 0))
        ttk.Button(action_row, text="一键开始", command=self._run_quick).pack(side=tk.LEFT)
        ttk.Button(action_row, text="多个文件加密", command=self._open_encrypt_multi_file_setup).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )
        ttk.Button(action_row, text="多个文件解密", command=self._open_decrypt_multi_file_setup).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )
        self._enable_drop_target(frame, self._handle_quick_drop)
        self._enable_drop_target(source_entry, self._handle_quick_drop)

    def _build_file_encrypt_config_tab(self, notebook: ttk.Notebook, *, tab_text: str = "多文件配置") -> ttk.Frame:
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=tab_text)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(6, weight=1)
        frame.rowconfigure(7, weight=1)

        self.config_encrypt_sources = scrolledtext.ScrolledText(frame, height=5, wrap=tk.WORD)
        self.config_encrypt_source_passwords = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self.config_encrypt_folder_inner = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self.config_encrypt_default_password = tk.StringVar()
        self.config_encrypt_metadata_password = tk.StringVar()
        self.config_encrypt_output_dir = tk.StringVar()
        self.config_encrypt_security_mode = tk.StringVar(value=SECURITY_MODE_LABELS["no-password-tables"])
        self.config_encrypt_bundle_path = tk.StringVar()
        self.config_encrypt_manifest_path = tk.StringVar()
        self.config_encrypt_password_table_path = tk.StringVar()
        self.config_encrypt_template_path = tk.StringVar()
        self.config_encrypt_save_path = tk.StringVar()
        self.config_encrypt_write_password_table = tk.BooleanVar(value=False)
        self.config_encrypt_write_internal_password_tables = tk.BooleanVar(value=False)

        ttk.Label(frame, text="加密文件/文件夹，每行一个").grid(row=0, column=0, sticky="nw", pady=4)
        self.config_encrypt_sources.grid(row=0, column=1, sticky="nsew", padx=(8, 8), pady=4)
        buttons = ttk.Frame(frame)
        buttons.grid(row=0, column=2, sticky="n", pady=4)
        ttk.Button(buttons, text="添加文件", command=self._add_config_encrypt_files).pack(fill=tk.X, pady=(0, 4))
        ttk.Button(buttons, text="添加文件夹", command=self._add_config_encrypt_folder).pack(fill=tk.X)

        self._add_secret_row(frame, 1, "主加密密码", self.config_encrypt_default_password)
        self._add_secret_row(frame, 2, "密码表/清单密码（留空则同主加密密码）", self.config_encrypt_metadata_password)
        self._add_path_row(frame, 3, "输出目录", self.config_encrypt_output_dir, self._browse_config_encrypt_output_dir)
        self._add_choice_row(
            frame,
            4,
            "密码表保存方式",
            self.config_encrypt_security_mode,
            _choice_label_values(SECURITY_MODE_LABELS),
        )
        options = ttk.Frame(frame)
        options.grid(row=5, column=1, sticky="w", pady=4)
        ttk.Checkbutton(options, text="输出加密密码表", variable=self.config_encrypt_write_password_table).pack(
            side=tk.LEFT,
            padx=(0, 12),
        )
        ttk.Checkbutton(
            options,
            text="文件夹内单独加密时输出内部密码表",
            variable=self.config_encrypt_write_internal_password_tables,
        ).pack(side=tk.LEFT)

        ttk.Label(frame, text="单独文件密码\n格式：完整路径=密码").grid(row=6, column=0, sticky="nw", pady=4)
        self.config_encrypt_source_passwords.grid(row=6, column=1, columnspan=2, sticky="nsew", padx=(8, 0), pady=4)
        ttk.Label(frame, text="文件夹内单独加密\n格式：文件夹路径|相对路径|密码").grid(row=7, column=0, sticky="nw", pady=4)
        self.config_encrypt_folder_inner.grid(row=7, column=1, columnspan=2, sticky="nsew", padx=(8, 0), pady=4)

        self._add_path_row(
            frame,
            8,
            "多文件加密包保存到",
            self.config_encrypt_bundle_path,
            self._browse_config_encrypt_bundle,
            save=True,
        )
        self._add_path_row(frame, 9, "manifest 保存到", self.config_encrypt_manifest_path, self._browse_config_encrypt_manifest, save=True)
        self._add_path_row(
            frame,
            10,
            "加密密码表保存到",
            self.config_encrypt_password_table_path,
            self._browse_config_encrypt_password_table,
            save=True,
        )
        self._add_path_row(frame, 11, "template 保存到", self.config_encrypt_template_path, self._browse_config_encrypt_template, save=True)
        self._add_path_row(frame, 12, "配置保存到", self.config_encrypt_save_path, self._browse_config_encrypt_save, save=True)

        action_row = ttk.Frame(frame)
        action_row.grid(row=13, column=1, sticky="w", pady=(10, 0))
        ttk.Button(action_row, text="生成加密配置", command=self._generate_file_encrypt_config).pack(side=tk.LEFT)
        ttk.Button(action_row, text="生成并开始加密", command=self._generate_and_run_file_encrypt_config).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )
        return frame

    def _build_file_decrypt_config_tab(self, notebook: ttk.Notebook, *, tab_text: str = "多文件解密配置") -> ttk.Frame:
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=tab_text)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(0, weight=1)

        self.config_decrypt_files = scrolledtext.ScrolledText(frame, height=5, wrap=tk.WORD)
        self.config_decrypt_manifest_path = tk.StringVar()
        self.config_decrypt_password_table_path = tk.StringVar()
        self.config_decrypt_template_path = tk.StringVar()
        self.config_decrypt_metadata_password = tk.StringVar()
        self.config_decrypt_output_dir = tk.StringVar()
        self.config_decrypt_security_mode = tk.StringVar(value=SECURITY_MODE_LABELS["compatible"])
        self.config_decrypt_save_path = tk.StringVar()

        ttk.Label(frame, text="要解密的 .hse 文件，每行一个").grid(row=0, column=0, sticky="nw", pady=4)
        self.config_decrypt_files.grid(row=0, column=1, sticky="nsew", padx=(8, 8), pady=4)
        ttk.Button(frame, text="添加文件", command=self._add_config_decrypt_files).grid(row=0, column=2, sticky="n", pady=4)
        self._add_path_row(frame, 1, "manifest 文件", self.config_decrypt_manifest_path, self._browse_config_decrypt_manifest)
        self._add_path_row(frame, 2, "加密密码表", self.config_decrypt_password_table_path, self._browse_config_decrypt_password_table)
        self._add_path_row(frame, 3, "template 文件", self.config_decrypt_template_path, self._browse_config_decrypt_template)
        self._add_secret_row(frame, 4, "密码表/清单密码", self.config_decrypt_metadata_password)
        self._add_path_row(frame, 5, "输出目录", self.config_decrypt_output_dir, self._browse_config_decrypt_output_dir)
        self._add_choice_row(
            frame,
            6,
            "密码表保存方式",
            self.config_decrypt_security_mode,
            _choice_label_values(SECURITY_MODE_LABELS),
        )
        self._add_path_row(frame, 7, "配置保存到", self.config_decrypt_save_path, self._browse_config_decrypt_save, save=True)

        action_row = ttk.Frame(frame)
        action_row.grid(row=8, column=1, sticky="w", pady=(10, 0))
        ttk.Button(action_row, text="生成解密配置", command=self._generate_file_decrypt_config).pack(side=tk.LEFT)
        ttk.Button(action_row, text="生成并开始解密", command=self._generate_and_run_file_decrypt_config).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )
        return frame

    def _build_removable_storage_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="移动存储加密")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)

        ttk.Label(
            frame,
            text=(
                "Windows 专用：调用 BitLocker To Go 管理 USB 或 SD 移动存储设备。"
                "设备加密后，未解锁前不能读写；解锁只恢复当前访问权限，不会移除密码；"
                "设备拔出后仍保持加密状态，再次插入时仍需重新解锁。"
            ),
            wraplength=780,
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky="ew")

        self.removable_status_text = tk.StringVar(value="正在读取移动存储设备信息...")
        ttk.Label(
            frame,
            textvariable=self.removable_status_text,
            wraplength=780,
            justify=tk.LEFT,
        ).grid(row=1, column=0, sticky="ew", pady=(8, 8))

        device_frame = ttk.LabelFrame(frame, text="设备列表", padding=8)
        device_frame.grid(row=2, column=0, sticky="nsew")
        device_frame.columnconfigure(0, weight=1)
        device_frame.rowconfigure(0, weight=1)

        columns = ("mount", "label", "filesystem", "size", "free", "bus", "status", "lock", "progress")
        self.removable_tree = ttk.Treeview(device_frame, columns=columns, show="headings", height=8, selectmode="browse")
        headings = {
            "mount": "盘符",
            "label": "卷标",
            "filesystem": "文件系统",
            "size": "容量",
            "free": "剩余",
            "bus": "总线",
            "status": "加密状态",
            "lock": "锁定状态",
            "progress": "进度",
        }
        widths = {
            "mount": 70,
            "label": 150,
            "filesystem": 100,
            "size": 110,
            "free": 110,
            "bus": 90,
            "status": 110,
            "lock": 100,
            "progress": 80,
        }
        for column in columns:
            self.removable_tree.heading(column, text=headings[column])
            anchor = tk.CENTER if column in {"mount", "filesystem", "bus", "status", "lock", "progress"} else tk.W
            self.removable_tree.column(column, width=widths[column], anchor=anchor, stretch=column in {"label"})
        self.removable_tree.grid(row=0, column=0, sticky="nsew")
        self.removable_tree.bind("<<TreeviewSelect>>", self._handle_removable_tree_selection)

        tree_scrollbar = ttk.Scrollbar(device_frame, orient=tk.VERTICAL, command=self.removable_tree.yview)
        tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.removable_tree.configure(yscrollcommand=tree_scrollbar.set)

        controls = ttk.LabelFrame(frame, text="设备操作", padding=8)
        controls.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        controls.columnconfigure(1, weight=1)

        self._removable_devices_by_mount: dict[str, RemovableStorageDevice] = {}
        self.removable_selected_mount = tk.StringVar()
        self.removable_password = tk.StringVar()
        self.removable_password_confirm = tk.StringVar()
        self.removable_recovery_dir = tk.StringVar()
        self.removable_encryption_method = tk.StringVar(value=REMOVABLE_ENCRYPTION_METHOD_LABELS["XtsAes256"])
        self.removable_used_space_only = tk.BooleanVar(value=False)
        self.removable_disable_auto_unlock = tk.BooleanVar(value=True)

        ttk.Label(controls, text="目标盘符").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(controls, textvariable=self.removable_selected_mount, state="readonly").grid(
            row=0,
            column=1,
            sticky="ew",
            padx=(8, 8),
            pady=4,
        )
        ttk.Button(controls, text="刷新设备", command=self._refresh_removable_devices).grid(row=0, column=2, pady=4)
        self._add_path_row(controls, 1, "恢复信息保存目录", self.removable_recovery_dir, self._browse_removable_recovery_dir)
        self._add_choice_row(
            controls,
            2,
            "加密方式",
            self.removable_encryption_method,
            _choice_label_values(REMOVABLE_ENCRYPTION_METHOD_LABELS),
        )
        self._add_secret_row(controls, 3, "设备密码", self.removable_password)
        self._add_secret_row(controls, 4, "确认设备密码（仅加密时需要）", self.removable_password_confirm)

        options = ttk.Frame(controls)
        options.grid(row=5, column=0, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Checkbutton(options, text="仅加密已用空间（新盘更快）", variable=self.removable_used_space_only).pack(
            side=tk.LEFT,
            padx=(0, 12),
        )
        ttk.Checkbutton(
            options,
            text="禁用自动解锁，拔出后重新插入仍需手动解锁",
            variable=self.removable_disable_auto_unlock,
        ).pack(side=tk.LEFT)

        button_row = ttk.Frame(controls)
        button_row.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))
        ttk.Button(button_row, text="开始加密", command=self._run_removable_encrypt).pack(side=tk.LEFT)
        ttk.Button(button_row, text="解锁设备", command=self._run_removable_unlock).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(button_row, text="立即上锁", command=self._run_removable_lock).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(button_row, text="打开盘符", command=self._open_selected_removable_mount).pack(side=tk.LEFT, padx=(8, 0))

    def _build_validate_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="检查配置")
        frame.columnconfigure(1, weight=1)

        self.validate_kind = tk.StringVar(value=CONFIG_KIND_LABELS["encrypt"])
        self.validate_config = tk.StringVar()
        self.validate_strict = tk.BooleanVar(value=False)
        self.validate_report = tk.BooleanVar(value=True)
        self.validate_format = tk.StringVar(value=REPORT_FORMAT_LABELS["json"])
        self.validate_output = tk.StringVar()
        self.validate_summary_only = tk.BooleanVar(value=False)
        self.validate_exit_code_on_issues = tk.BooleanVar(value=False)
        self.validate_warnings_as_errors = tk.BooleanVar(value=False)

        self._add_choice_row(frame, 0, "配置用途", self.validate_kind, _choice_label_values(CONFIG_KIND_LABELS))
        self._add_path_row(frame, 1, "配置文件", self.validate_config, self._browse_validate_config)
        self._add_choice_row(frame, 2, "结果格式", self.validate_format, _choice_label_values(REPORT_FORMAT_LABELS))
        self._add_path_row(frame, 3, "结果保存到", self.validate_output, self._browse_validate_output, save=True)

        options = ttk.Frame(frame)
        options.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(options, text="高级检查", variable=self.validate_strict).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(options, text="显示检查结果", variable=self.validate_report).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(options, text="只看摘要", variable=self.validate_summary_only).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            options,
            text="发现异常后退出检查",
            variable=self.validate_exit_code_on_issues,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            options,
            text="出现警告后退出检查",
            variable=self.validate_warnings_as_errors,
        ).pack(side=tk.LEFT)

        ttk.Button(frame, text="检查配置", command=self._run_validate).grid(row=5, column=0, sticky="w", pady=(14, 0))

    def _build_encrypt_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        self.encrypt_tab = frame
        notebook.add(frame, text="文件加密")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        inner = ttk.Notebook(frame)
        self.encrypt_notebook = inner
        inner.grid(row=0, column=0, sticky="nsew")

        run_frame = ttk.Frame(inner, padding=10)
        inner.add(run_frame, text="运行已有配置")
        run_frame.columnconfigure(1, weight=1)
        self.encrypt_config = tk.StringVar()
        self._add_path_row(run_frame, 0, "加密配置", self.encrypt_config, self._browse_encrypt_config)
        ttk.Label(
            run_frame,
            text=f"{PASSWORD_PROVIDER_HINT}\n多个文件或需要单独密码时，请切换到“多文件配置”。",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(run_frame, text="开始加密", command=self._run_encrypt).grid(
            row=2,
            column=0,
            sticky="w",
            pady=(14, 0),
        )
        self.encrypt_multi_tab = self._build_file_encrypt_config_tab(inner, tab_text="多文件配置")

    def _build_decrypt_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        self.decrypt_tab = frame
        notebook.add(frame, text="文件解密")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        inner = ttk.Notebook(frame)
        self.decrypt_notebook = inner
        inner.grid(row=0, column=0, sticky="nsew")

        run_frame = ttk.Frame(inner, padding=10)
        inner.add(run_frame, text="运行已有配置")
        run_frame.columnconfigure(1, weight=1)
        self.decrypt_config = tk.StringVar()
        self._add_path_row(run_frame, 0, "解密配置", self.decrypt_config, self._browse_decrypt_config)
        ttk.Label(
            run_frame,
            text=f"{PASSWORD_PROVIDER_HINT}\n多个文件或副产物不在同一目录时，请切换到“多文件解密配置”。",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(run_frame, text="开始解密", command=self._run_decrypt).grid(
            row=2,
            column=0,
            sticky="w",
            pady=(14, 0),
        )
        self.decrypt_multi_tab = self._build_file_decrypt_config_tab(inner, tab_text="多文件解密配置")

    def _build_examples_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="生成配置")
        frame.columnconfigure(1, weight=1)

        self.example_mode = tk.StringVar(value=SECURITY_MODE_LABELS["hardened"])
        self.example_kind = tk.StringVar(value=CONFIG_KIND_LABELS["encrypt"])
        self.example_output = tk.StringVar()

        self._add_choice_row(frame, 0, "密码表保存方式", self.example_mode, _choice_label_values(SECURITY_MODE_LABELS))
        self._add_choice_row(frame, 1, "配置用途", self.example_kind, _choice_label_values(CONFIG_KIND_LABELS))
        self._add_path_row(frame, 2, "保存为", self.example_output, self._browse_example_output, save=True)
        ttk.Button(frame, text="生成配置文件", command=self._run_init_example).grid(
            row=3,
            column=0,
            sticky="w",
            pady=(14, 0),
        )

    def _build_help_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="说明")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        help_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        help_text.grid(row=0, column=0, sticky="nsew")
        help_text.insert("1.0", HELP_TEXT)
        help_text.configure(state="disabled")

    def _build_log(self) -> None:
        log_frame = ttk.Frame(self, padding=(0, 10, 0, 0))
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        button_row = ttk.Frame(log_frame)
        button_row.grid(row=0, column=0, sticky="ew")
        ttk.Label(button_row, text="运行结果").pack(side=tk.LEFT)
        ttk.Button(button_row, text="清空结果", command=self._clear_log).pack(side=tk.RIGHT)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=16, wrap=tk.WORD)
        self.log_text.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

    def _add_choice_row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        values: tuple[str, ...],
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        combo = ttk.Combobox(parent, textvariable=variable, values=values, state="readonly")
        combo.grid(row=row, column=1, sticky="ew", pady=4)

    def _add_path_row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        browse_command: Any,
        *,
        save: bool = False,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=(8, 8), pady=4)
        button_text = "保存到" if save else "选择"
        ttk.Button(parent, text=button_text, command=browse_command).grid(row=row, column=2, pady=4)

    def _add_secret_row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=variable, show="*").grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(8, 8),
            pady=4,
        )

    def _browse_validate_config(self) -> None:
        self._browse_json_file(self.validate_config)

    def _browse_quick_file(self) -> None:
        path = filedialog.askopenfilename(
            title="选择要处理的文件",
            filetypes=[("加密文件", "*.hse"), ("所有文件", "*.*")],
        )
        if path:
            self.quick_source.set(path)

    def _browse_quick_folder(self) -> None:
        path = filedialog.askdirectory(title="选择要加密的文件夹")
        if path:
            self.quick_source.set(path)

    def _enable_drop_target(self, widget: tk.Widget, callback: Any) -> None:
        if DND_FILES is None:
            return
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", callback)
        except (AttributeError, tk.TclError):
            return

    def _handle_quick_drop(self, event: Any) -> str:
        paths = split_drop_paths(str(getattr(event, "data", "")), self.master.tk.splitlist)
        if not paths:
            return "break"
        if len(paths) > 1:
            workflow = choose_multi_file_workflow(paths, self.quick_action.get())
            if workflow == "decrypt":
                self._open_decrypt_multi_file_setup(paths)
                self._append_log("已拖入多个项目，已转到“文件解密”的多文件配置。\n")
            else:
                self._open_encrypt_multi_file_setup(paths)
                self._append_log("已拖入多个项目，已转到“文件加密”的多文件配置。\n")
            return "break"
        selected_path = paths[0]
        self.quick_source.set(selected_path)
        if selected_path.lower().endswith(".hse"):
            self.quick_action.set(QUICK_ACTION_LABELS["decrypt"])
        else:
            self.quick_action.set(QUICK_ACTION_LABELS["encrypt"])
        self._append_log(f"已拖入：{selected_path}\n")
        return "break"

    def _browse_validate_output(self) -> None:
        self._browse_save_file(self.validate_output, default_extension=".json")

    def _browse_encrypt_config(self) -> None:
        self._browse_json_file(self.encrypt_config)

    def _browse_decrypt_config(self) -> None:
        self._browse_json_file(self.decrypt_config)

    def _browse_example_output(self) -> None:
        self._browse_save_file(self.example_output, default_extension=".json")

    def _add_config_encrypt_files(self) -> None:
        paths = filedialog.askopenfilenames(title="选择要加密的文件")
        self._append_lines(self.config_encrypt_sources, paths)

    def _add_config_encrypt_folder(self) -> None:
        path = filedialog.askdirectory(title="选择要加密的文件夹")
        if path:
            self._append_lines(self.config_encrypt_sources, [path])

    def _add_config_decrypt_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="选择要解密的 .hse 文件",
            filetypes=[("HSE 文件", "*.hse"), ("所有文件", "*.*")],
        )
        self._append_lines(self.config_decrypt_files, paths)

    def _browse_config_encrypt_output_dir(self) -> None:
        self._browse_directory(self.config_encrypt_output_dir, "选择加密输出目录")

    def _browse_config_decrypt_output_dir(self) -> None:
        self._browse_directory(self.config_decrypt_output_dir, "选择解密输出目录")

    def _browse_config_encrypt_bundle(self) -> None:
        self._browse_save_file(self.config_encrypt_bundle_path, default_extension=".zip.hse")

    def _browse_config_encrypt_manifest(self) -> None:
        self._browse_save_file(self.config_encrypt_manifest_path, default_extension=".hsm")

    def _browse_config_encrypt_password_table(self) -> None:
        self._browse_save_file(self.config_encrypt_password_table_path, default_extension=".hsm")

    def _browse_config_encrypt_template(self) -> None:
        self._browse_save_file(self.config_encrypt_template_path, default_extension=".hsm")

    def _browse_config_encrypt_save(self) -> None:
        self._browse_save_file(self.config_encrypt_save_path, default_extension=".json")

    def _browse_config_decrypt_manifest(self) -> None:
        self._browse_hsm_file(self.config_decrypt_manifest_path)

    def _browse_config_decrypt_password_table(self) -> None:
        self._browse_hsm_file(self.config_decrypt_password_table_path)

    def _browse_config_decrypt_template(self) -> None:
        self._browse_hsm_file(self.config_decrypt_template_path)

    def _browse_config_decrypt_save(self) -> None:
        self._browse_save_file(self.config_decrypt_save_path, default_extension=".json")

    def _browse_hsm_file(self, variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            title="选择加密副产物文件",
            filetypes=[("HSM 文件", "*.hsm"), ("所有文件", "*.*")],
        )
        if path:
            variable.set(path)

    def _browse_json_file(self, variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            title="选择配置文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if path:
            variable.set(path)

    def _browse_directory(self, variable: tk.StringVar, title: str) -> None:
        path = filedialog.askdirectory(title=title)
        if path:
            variable.set(path)

    def _browse_removable_recovery_dir(self) -> None:
        self._browse_directory(self.removable_recovery_dir, "选择恢复信息保存目录")

    def _browse_save_file(self, variable: tk.StringVar, *, default_extension: str) -> None:
        filetypes = [("所有文件", "*.*")]
        if default_extension == ".json":
            filetypes = [("JSON 文件", "*.json"), ("所有文件", "*.*")]
        elif default_extension == ".hsm":
            filetypes = [("HSM 文件", "*.hsm"), ("所有文件", "*.*")]
        elif default_extension == ".zip.hse":
            filetypes = [("加密文件夹/多文件包", "*.zip.hse"), ("所有文件", "*.*")]
        path = filedialog.asksaveasfilename(
            title="选择保存位置",
            defaultextension=default_extension,
            filetypes=filetypes,
        )
        if path:
            variable.set(path)

    def _handle_removable_tree_selection(self, _event: tk.Event[Any] | None = None) -> None:
        selection = self.removable_tree.selection()
        if not selection:
            self.removable_selected_mount.set("")
            return
        self.removable_selected_mount.set(selection[0])

    def _selected_removable_mount(self) -> str:
        mount_point = self.removable_selected_mount.get().strip()
        if not mount_point:
            raise ValueError("请先在设备列表中选择一个移动存储设备。")
        return mount_point

    def _selected_removable_device(self) -> RemovableStorageDevice:
        mount_point = self._selected_removable_mount()
        device = self._removable_devices_by_mount.get(mount_point)
        if device is None:
            raise ValueError("当前选择的移动存储设备已失效，请先刷新设备列表。")
        return device

    def _populate_removable_device_list(self, inventory: RemovableStorageInventory) -> None:
        self._removable_devices_by_mount = {device.mount_point: device for device in inventory.devices}
        existing_selection = self.removable_selected_mount.get().strip()
        for item_id in self.removable_tree.get_children():
            self.removable_tree.delete(item_id)

        for device in inventory.devices:
            progress = (
                f"{device.bitlocker_encryption_percentage}%"
                if device.bitlocker_encryption_percentage is not None
                else "-"
            )
            self.removable_tree.insert(
                "",
                tk.END,
                iid=device.mount_point,
                values=(
                    device.mount_point,
                    device.volume_label or device.friendly_name or "-",
                    device.file_system or "-",
                    format_size_bytes(device.size_bytes),
                    format_size_bytes(device.free_bytes),
                    device.bus_type or "-",
                    describe_removable_device_status(device),
                    device.bitlocker_lock_status or "-",
                    progress,
                ),
            )

        next_selection = existing_selection if existing_selection in self._removable_devices_by_mount else ""
        if not next_selection and inventory.devices:
            next_selection = inventory.devices[0].mount_point
        if next_selection:
            self.removable_tree.selection_set(next_selection)
            self.removable_tree.focus(next_selection)
            self.removable_selected_mount.set(next_selection)
        else:
            self.removable_selected_mount.set("")

    def _append_lines(self, text_widget: tk.Text, values: Any) -> None:
        for value in values:
            text_widget.insert(tk.END, f"{value}\n")

    def _open_encrypt_multi_file_setup(self, paths: list[str] | None = None, main_password: str = "") -> None:
        if paths:
            self._append_lines(self.config_encrypt_sources, paths)
        if main_password:
            self.config_encrypt_default_password.set(main_password)
            self.config_encrypt_metadata_password.set(main_password)
            if len(paths or []) == 1:
                self.config_encrypt_output_dir.set(str(Path(paths[0]).parent))
        self.main_notebook.select(self.encrypt_tab)
        self.encrypt_notebook.select(self.encrypt_multi_tab)
        if paths:
            self._append_log("已带入多文件加密列表，可继续填写密码和输出位置。\n")

    def _open_decrypt_multi_file_setup(self, paths: list[str] | None = None) -> None:
        if paths:
            self._append_lines(self.config_decrypt_files, paths)
        self.main_notebook.select(self.decrypt_tab)
        self.decrypt_notebook.select(self.decrypt_multi_tab)
        if paths:
            self._append_log("已带入多文件解密列表，可继续选择 manifest、密码表和 template。\n")

    def _build_file_encrypt_config_plan_from_ui(self) -> GeneratedConfigPlan:
        return build_file_encryption_config_plan(
            sources_text=self.config_encrypt_sources.get("1.0", tk.END),
            default_password=self.config_encrypt_default_password.get(),
            metadata_password=self.config_encrypt_metadata_password.get(),
            output_dir=self.config_encrypt_output_dir.get(),
            security_mode=self.config_encrypt_security_mode.get(),
            source_passwords_text=self.config_encrypt_source_passwords.get("1.0", tk.END),
            folder_inner_passwords_text=self.config_encrypt_folder_inner.get("1.0", tk.END),
            bundle_output_path=self.config_encrypt_bundle_path.get(),
            manifest_output_path=self.config_encrypt_manifest_path.get(),
            password_table_output_path=self.config_encrypt_password_table_path.get(),
            template_output_path=self.config_encrypt_template_path.get(),
            write_password_table=self.config_encrypt_write_password_table.get(),
            write_internal_password_tables=self.config_encrypt_write_internal_password_tables.get(),
        )

    def _build_file_encrypt_config_payload_from_ui(self) -> dict[str, Any]:
        return self._build_file_encrypt_config_plan_from_ui().payload

    def _build_file_decrypt_config_plan_from_ui(self) -> GeneratedConfigPlan:
        return build_file_decryption_config_plan(
            encrypted_files_text=self.config_decrypt_files.get("1.0", tk.END),
            manifest_path=self.config_decrypt_manifest_path.get(),
            password_table_path=self.config_decrypt_password_table_path.get(),
            template_path=self.config_decrypt_template_path.get(),
            metadata_password=self.config_decrypt_metadata_password.get(),
            output_dir=self.config_decrypt_output_dir.get(),
            security_mode=self.config_decrypt_security_mode.get(),
        )

    def _build_file_decrypt_config_payload_from_ui(self) -> dict[str, Any]:
        return self._build_file_decrypt_config_plan_from_ui().payload

    def _generate_file_encrypt_config(self) -> Path | None:
        try:
            plan = self._build_file_encrypt_config_plan_from_ui()
            payload = plan.payload
            path = write_json_config_file(payload, self.config_encrypt_save_path.get())
            self._last_generated_runtime_env = plan.runtime_env
        except ValueError as exc:
            self._show_input_error(exc)
            return None
        self._append_log(f"已生成加密配置：{path}\n")
        if payload.get("bundle_output_path"):
            self._append_log(f"多文件加密包将输出到：{payload['bundle_output_path']}\n")
        elif payload.get("package_as_bundle"):
            self._append_log("多文件会打包后用主加密密码加密，输出到所选目录。\n")
        if payload.get("password_table_output_path"):
            self._append_log(f"加密密码表将输出到：{payload['password_table_output_path']}\n")
        elif payload.get("package_as_bundle") and payload.get("write_password_table", True):
            self._append_log("加密密码表将输出到加密包所在目录。\n")
        self._append_log("\n")
        return path

    def _generate_file_decrypt_config(self) -> Path | None:
        try:
            plan = self._build_file_decrypt_config_plan_from_ui()
            payload = plan.payload
            path = write_json_config_file(payload, self.config_decrypt_save_path.get())
            self._last_generated_runtime_env = plan.runtime_env
        except ValueError as exc:
            self._show_input_error(exc)
            return None
        self._append_log(f"已生成解密配置：{path}\n")
        self._append_log(f"使用加密密码表：{payload['password_table_path']}\n\n")
        return path

    def _generate_and_run_file_encrypt_config(self) -> None:
        path = self._generate_file_encrypt_config()
        if path is None:
            return
        self._run_cli(
            ["encrypt-batch", "--config", str(path)],
            block_prompt_providers=True,
            runtime_env=self._last_generated_runtime_env,
        )

    def _generate_and_run_file_decrypt_config(self) -> None:
        path = self._generate_file_decrypt_config()
        if path is None:
            return
        self._run_cli(
            ["decrypt-batch", "--config", str(path)],
            block_prompt_providers=True,
            runtime_env=self._last_generated_runtime_env,
        )

    def _refresh_removable_devices(self, *_args: Any, show_message: bool = True, write_log: bool = True) -> None:
        if self._is_busy:
            if show_message:
                messagebox.showinfo("正在处理", "上一个任务还没结束，请稍后再试。")
            return

        self._is_busy = True
        self.removable_status_text.set("正在读取移动存储设备信息...")
        if write_log:
            self._append_log("刷新移动存储设备列表\n")
        worker = threading.Thread(
            target=self._execute_removable_inventory_worker,
            args=(show_message, write_log),
            daemon=True,
        )
        worker.start()

    def _execute_removable_inventory_worker(self, show_message: bool, write_log: bool) -> None:
        try:
            inventory = list_removable_storage_devices()
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            self.after(0, self._handle_removable_inventory_error, str(exc), show_message, write_log)
            return
        self.after(0, self._handle_removable_inventory_success, inventory, show_message, write_log)

    def _handle_removable_inventory_success(
        self,
        inventory: RemovableStorageInventory,
        show_message: bool,
        write_log: bool,
    ) -> None:
        self._is_busy = False
        self._populate_removable_device_list(inventory)
        status_text = describe_removable_inventory_status(inventory)
        self.removable_status_text.set(status_text)
        if write_log:
            self._append_log(f"{status_text}\n\n")
        if show_message and inventory.status_warning:
            messagebox.showinfo("移动存储加密", status_text)

    def _handle_removable_inventory_error(self, message: str, show_message: bool, write_log: bool) -> None:
        self._is_busy = False
        status_text = f"移动存储设备读取失败：{message}"
        self.removable_status_text.set(status_text)
        if write_log:
            self._append_log(f"{status_text}\n\n")
        if show_message:
            messagebox.showerror("移动存储加密", message)

    def _run_removable_encrypt(self) -> None:
        try:
            device = self._selected_removable_device()
            if device.bitlocker_protection_status == "On":
                raise ValueError("该设备已经启用 BitLocker，请直接使用“解锁设备”或系统工具管理。")
            password = self.removable_password.get()
            confirm_password = self.removable_password_confirm.get()
            recovery_dir = _require_path(self.removable_recovery_dir.get(), "请选择恢复信息保存目录。")
            encryption_method = _require_choice(
                self.removable_encryption_method.get(),
                REMOVABLE_ENCRYPTION_METHODS,
                "请选择加密方式。",
                REMOVABLE_ENCRYPTION_METHOD_LABELS,
            )
            if not password:
                raise ValueError("请输入设备密码。")
            if not confirm_password:
                raise ValueError("加密前请再次输入设备密码。")
            if password != confirm_password:
                raise ValueError("两次输入的设备密码不一致。")
        except ValueError as exc:
            self._show_input_error(exc)
            return

        if self._is_busy:
            messagebox.showinfo("正在处理", "上一个任务还没结束，请稍后再试。")
            return

        self._is_busy = True
        self._append_log(f"开始对移动存储 {device.mount_point} 启用 BitLocker\n")
        worker = threading.Thread(
            target=self._execute_removable_encrypt_worker,
            args=(
                device.mount_point,
                password,
                recovery_dir,
                encryption_method,
                self.removable_used_space_only.get(),
                self.removable_disable_auto_unlock.get(),
            ),
            daemon=True,
        )
        worker.start()

    def _execute_removable_encrypt_worker(
        self,
        mount_point: str,
        password: str,
        recovery_dir: str,
        encryption_method: str,
        used_space_only: bool,
        disable_auto_unlock: bool,
    ) -> None:
        try:
            result = enable_removable_bitlocker(
                mount_point,
                password,
                recovery_directory=recovery_dir,
                encryption_method=encryption_method,
                used_space_only=used_space_only,
                disable_auto_unlock=disable_auto_unlock,
            )
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            self.after(0, self._handle_removable_action_error, "移动存储加密", str(exc))
            return
        self.after(0, self._handle_removable_action_success, "移动存储加密", result)

    def _run_removable_unlock(self) -> None:
        try:
            device = self._selected_removable_device()
            password = self.removable_password.get()
            if not password:
                raise ValueError("请输入设备密码。")
            if device.bitlocker_protection_status != "On":
                raise ValueError("该设备还没有启用 BitLocker，无法执行解锁。")
        except ValueError as exc:
            self._show_input_error(exc)
            return

        if self._is_busy:
            messagebox.showinfo("正在处理", "上一个任务还没结束，请稍后再试。")
            return

        self._is_busy = True
        self._append_log(f"尝试解锁移动存储 {device.mount_point}\n")
        worker = threading.Thread(
            target=self._execute_removable_unlock_worker,
            args=(device.mount_point, password, self.removable_disable_auto_unlock.get()),
            daemon=True,
        )
        worker.start()

    def _execute_removable_unlock_worker(
        self,
        mount_point: str,
        password: str,
        disable_auto_unlock: bool,
    ) -> None:
        try:
            result = unlock_removable_bitlocker(
                mount_point,
                password,
                disable_auto_unlock=disable_auto_unlock,
            )
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            self.after(0, self._handle_removable_action_error, "移动存储解锁", str(exc))
            return
        self.after(0, self._handle_removable_action_success, "移动存储解锁", result)

    def _run_removable_lock(self) -> None:
        try:
            device = self._selected_removable_device()
            if device.bitlocker_protection_status != "On":
                raise ValueError("该设备还没有启用 BitLocker，无法执行上锁。")
        except ValueError as exc:
            self._show_input_error(exc)
            return

        if self._is_busy:
            messagebox.showinfo("正在处理", "上一个任务还没结束，请稍后再试。")
            return

        self._is_busy = True
        self._append_log(f"尝试上锁移动存储 {device.mount_point}\n")
        worker = threading.Thread(
            target=self._execute_removable_lock_worker,
            args=(device.mount_point,),
            daemon=True,
        )
        worker.start()

    def _execute_removable_lock_worker(self, mount_point: str) -> None:
        try:
            result = lock_removable_bitlocker(mount_point)
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            self.after(0, self._handle_removable_action_error, "移动存储上锁", str(exc))
            return
        self.after(0, self._handle_removable_action_success, "移动存储上锁", result)

    def _handle_removable_action_success(self, action: str, result: BitLockerActionResult) -> None:
        self._is_busy = False
        self.removable_status_text.set(f"{action}完成：{result.mount_point}")
        self.removable_password.set("")
        self.removable_password_confirm.set("")
        self._append_log(f"{build_removable_action_summary(action, result)}\n\n")
        self.after(100, lambda: self._refresh_removable_devices(show_message=False, write_log=False))

    def _handle_removable_action_error(self, action: str, message: str) -> None:
        self._is_busy = False
        self.removable_status_text.set(f"{action}失败：{message}")
        self._append_log(f"{action}失败：{message}\n\n")
        messagebox.showerror("移动存储加密", message)

    def _open_selected_removable_mount(self) -> None:
        try:
            mount_point = self._selected_removable_mount()
            open_mount_point(mount_point)
        except (ValueError, RemovableStorageError, OSError) as exc:
            messagebox.showerror("移动存储加密", str(exc))

    def _run_quick(self) -> None:
        if self._is_busy:
            messagebox.showinfo("正在处理", "上一个任务还没结束，请稍后再试。")
            return

        try:
            action = _require_choice(self.quick_action.get(), QUICK_ACTIONS, "请选择加密或解密。", QUICK_ACTION_LABELS)
            source_path = _require_path(self.quick_source.get(), "请选择要处理的文件或文件夹。")
            password = self.quick_password.get()
            if not password:
                raise ValueError("请输入主加密密码。")
            if action == "encrypt":
                confirm_password = self.quick_password_confirm.get()
                if not confirm_password:
                    raise ValueError("加密前请再次输入主加密密码。")
                if password != confirm_password:
                    raise ValueError("两次输入的密码不一致。")
        except ValueError as exc:
            self._show_input_error(exc)
            return

        if action == "encrypt" and Path(source_path).is_dir():
            if messagebox.askyesno(
                "单独加密文件夹内文件",
                "是否需要给文件夹内的某些文件单独设置密码？\n\n"
                "选择“是”会转到文件加密的多文件配置页面，你可以指定要单独加密的文件并输入密码。\n"
                "选择“否”会直接用主加密密码加密整个文件夹。",
            ):
                self._open_encrypt_multi_file_setup([source_path], main_password=password)
                return

        self._is_busy = True
        self._append_log(f"快速{QUICK_ACTION_LABELS[action]}：{source_path}\n")
        worker = threading.Thread(
            target=self._execute_quick_worker,
            args=(action, source_path, password),
            daemon=True,
        )
        worker.start()

    def _execute_quick_worker(self, action: str, source_path: str, password: str) -> None:
        try:
            result = run_quick_action(action, source_path, password)
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            self.after(0, self._handle_quick_error, str(exc))
            return
        self.after(0, self._handle_quick_success, result)

    def _handle_quick_success(self, result: QuickActionResult) -> None:
        self._is_busy = False
        self._append_log("处理完成\n")
        self._append_log(f"输出位置：{result.output_path}\n")
        self._append_log(f"{result.detail}\n\n")

    def _handle_quick_error(self, message: str) -> None:
        self._is_busy = False
        self._append_log("快速处理失败\n")
        self._append_log(f"异常信息：{message}\n")
        self._append_log(
            "解决建议：确认密码正确、文件存在且未被占用；解密时请选择 .hse 或 .zip.hse 文件。\n\n"
        )
        messagebox.showerror("快速处理失败", message)

    def _run_validate(self) -> None:
        try:
            args = build_validate_config_args(
                kind=self.validate_kind.get(),
                config_path=self.validate_config.get(),
                strict=self.validate_strict.get(),
                report=self.validate_report.get(),
                report_format=self.validate_format.get(),
                output_path=self.validate_output.get(),
                summary_only=self.validate_summary_only.get(),
                exit_code_on_issues=self.validate_exit_code_on_issues.get(),
                warnings_as_errors=self.validate_warnings_as_errors.get(),
            )
        except ValueError as exc:
            self._show_input_error(exc)
            return
        self._run_cli(args)

    def _run_encrypt(self) -> None:
        try:
            args = build_batch_args(command="encrypt-batch", config_path=self.encrypt_config.get())
        except ValueError as exc:
            self._show_input_error(exc)
            return
        self._run_cli(args, block_prompt_providers=True)

    def _run_decrypt(self) -> None:
        try:
            args = build_batch_args(command="decrypt-batch", config_path=self.decrypt_config.get())
        except ValueError as exc:
            self._show_input_error(exc)
            return
        self._run_cli(args, block_prompt_providers=True)

    def _run_init_example(self) -> None:
        try:
            args = build_init_example_args(
                mode=self.example_mode.get(),
                kind=self.example_kind.get(),
                output_path=self.example_output.get(),
            )
        except ValueError as exc:
            self._show_input_error(exc)
            return
        self._run_cli(args)

    def _run_cli(
        self,
        args: list[str],
        *,
        block_prompt_providers: bool = False,
        runtime_env: dict[str, str] | None = None,
    ) -> None:
        if self._is_busy:
            messagebox.showinfo("正在处理", "上一个任务还没结束，请稍后再试。")
            return
        if block_prompt_providers and config_uses_prompt_provider(_config_path_from_args(args)):
            messagebox.showerror(
                "这种密码输入方式暂不支持",
                "配置里使用了运行时手动输入密码（prompt），图形界面无法接收这类控制台输入。\n\n"
                "请改用直接填写、环境变量、本地文件或命令输出。",
            )
            return

        self._is_busy = True
        self._append_log(f"$ high-security-encryptor {shlex.join(args)}\n")
        worker = threading.Thread(
            target=self._execute_cli_worker,
            args=(args, dict(runtime_env or {})),
            daemon=True,
        )
        worker.start()

    def _execute_cli_worker(self, args: list[str], runtime_env: dict[str, str]) -> None:
        try:
            with _temporary_environment(runtime_env):
                result = invoke_cli_command(args)
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            result = GuiCommandResult(exit_code=1, stdout="", stderr=f"错误：{exc}")
        self.after(0, self._handle_cli_result, args, result)

    def _handle_cli_result(self, args: list[str], result: GuiCommandResult) -> None:
        self._is_busy = False
        if result.stdout:
            self._append_log(result.stdout)
            if not result.stdout.endswith("\n"):
                self._append_log("\n")
        if result.stderr:
            self._append_log(result.stderr)
            if not result.stderr.endswith("\n"):
                self._append_log("\n")
        guidance = build_validation_result_guidance(args, result)
        if guidance:
            self._append_log(f"{guidance}\n")
        self._append_log(f"退出码：{result.exit_code}\n\n")
        if result.exit_code == 0:
            return
        messagebox.showerror("操作失败", f"这次操作没有完成，状态码：{result.exit_code}。")

    def _append_log(self, text: str) -> None:
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _show_input_error(self, exc: ValueError) -> None:
        messagebox.showerror("缺少必要信息", str(exc))


def main(argv: list[str] | None = None) -> int:
    """Run the GUI application."""

    parser = argparse.ArgumentParser(prog="high-security-encryptor-gui")
    parser.add_argument("--smoke-test", action="store_true", help="验证 GUI 依赖并退出。")
    args = parser.parse_args(argv)
    if args.smoke_test:
        smoke_test()
        return 0

    root = create_gui_root()
    HighSecurityEncryptorApp(root)
    root.mainloop()
    return 0


def _secret_spec_for_gui_password(
    password: str,
    env_name: str,
    runtime_env: dict[str, str],
    password_output: str,
) -> str | dict[str, str]:
    if password_output == PASSWORD_OUTPUT_LITERAL:
        return password
    if password_output != PASSWORD_OUTPUT_ENV:
        raise ValueError(f"unsupported password output mode: {password_output}")
    runtime_env[env_name] = password
    return {"type": "env", "name": env_name}


@contextmanager
def _temporary_environment(updates: dict[str, str]):
    original = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _require_path(value: str, message: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(message)
    return normalized


def _require_choice(
    value: str,
    allowed: tuple[str, ...],
    message: str,
    labels: dict[str, str] | None = None,
) -> str:
    normalized = value.strip()
    if normalized not in allowed:
        if labels:
            for raw_value, display_label in labels.items():
                if normalized == display_label:
                    return raw_value
        raise ValueError(message)
    return normalized


def _choice_label_values(labels: dict[str, str]) -> tuple[str, ...]:
    return tuple(labels[raw_value] for raw_value in labels)


def _config_path_from_args(args: list[str]) -> str:
    try:
        index = args.index("--config")
    except ValueError:
        return ""
    try:
        return args[index + 1]
    except IndexError:
        return ""


def _extract_json_summary(stdout: str) -> dict[str, Any] | None:
    payload = stdout.strip()
    if "###SUMMARY###" in payload:
        payload = payload.rsplit("###SUMMARY###", 1)[1].strip()
    if not payload:
        return None
    try:
        summary = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return summary if isinstance(summary, dict) else None


def _contains_prompt_provider(value: Any) -> bool:
    if isinstance(value, dict):
        if str(value.get("type", "")).strip().lower() == "prompt":
            return True
        return any(_contains_prompt_provider(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_prompt_provider(child) for child in value)
    return False


if __name__ == "__main__":
    raise SystemExit(main())
