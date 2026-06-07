"""GUI-facing command builders for explicit HSE2 workflows.

These helpers deliberately build CLI argument lists instead of reimplementing
HSE2 workflow logic in the GUI layer. The Tkinter UI can call these builders and
then pass the returned argv to the existing GUI CLI runner.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE


HSE2_GUI_ACTIONS = (
    "encrypt-config",
    "decrypt-config",
    "validate",
    "rotate-keyfile",
    "generate-keyfile",
    "dpapi-protect",
    "wrapper-list",
    "wrapper-remove",
    "access-destroy",
)

HSE2_GUI_ACTION_LABELS = {
    "encrypt-config": "HSE2 加密配置",
    "decrypt-config": "HSE2 解密配置",
    "validate": "HSE2 只读校验",
    "rotate-keyfile": "HSE2 keyfile 轮换",
    "generate-keyfile": "生成 keyfile",
    "dpapi-protect": "Windows DPAPI 保护 keyfile",
    "wrapper-list": "列出 HSE2 wrapper",
    "wrapper-remove": "移除指定 HSE2 wrapper",
    "access-destroy": "永久禁用 HSE2 访问",
}


@dataclass(frozen=True)
class HSE2GuiCommandPlan:
    """A GUI-safe HSE2 command plan."""

    action: str
    argv: tuple[str, ...]
    description: str
    experimental: bool = True


def build_hse2_gui_command(
    *,
    action: str,
    config_path: str = "",
    input_path: str = "",
    output_path: str = "",
    size: int = 32,
    force: bool = False,
    scope: str = "current_user",
    validation_report_output: str = "",
    validation_summary_only: bool = False,
    validation_exit_code_on_failure: bool = False,
    wrapper_id: str = "",
    password_file: str = "",
    keyfile_path: str = "",
    allow_dpapi: bool = False,
    access_confirmation_phrase: str = "",
) -> HSE2GuiCommandPlan:
    """Build a CLI argv plan for one explicit HSE2 GUI action."""

    normalized_action = _require_action(action)
    if normalized_action == "encrypt-config":
        argv = ("hse2-encrypt-config", "--config", _require_text(config_path, "请选择 HSE2 加密配置文件。"))
    elif normalized_action == "decrypt-config":
        argv = ("hse2-decrypt-config", "--config", _require_text(config_path, "请选择 HSE2 解密配置文件。"))
    elif normalized_action == "validate":
        args: list[str] = ["hse2-validate", "--config", _require_text(config_path, "请选择 HSE2 校验配置文件。")]
        if validation_report_output.strip():
            args.extend(["--output", validation_report_output.strip()])
        if validation_summary_only:
            args.append("--summary-only")
        if validation_exit_code_on_failure:
            args.append("--exit-code-on-failure")
        argv = tuple(args)
    elif normalized_action == "rotate-keyfile":
        argv = ("hse2-rotate-keyfile", "--config", _require_text(config_path, "请选择 HSE2 keyfile 轮换配置文件。"))
    elif normalized_action == "generate-keyfile":
        if size < 16:
            raise ValueError("keyfile size must be at least 16 bytes")
        args = ["generate-keyfile", "--output", _require_text(output_path, "请选择 keyfile 输出路径。"), "--size", str(size)]
        if force:
            args.append("--force")
        argv = tuple(args)
    elif normalized_action == "dpapi-protect":
        normalized_scope = _require_scope(scope)
        args = [
            "dpapi-protect",
            "--input",
            _require_text(input_path, "请选择要保护的 keyfile。"),
            "--output",
            _require_text(output_path, "请选择 DPAPI blob 输出路径。"),
            "--scope",
            normalized_scope,
        ]
        if force:
            args.append("--force")
        argv = tuple(args)
    elif normalized_action == "wrapper-list":
        argv = (
            "hse2-wrapper",
            "list",
            "--input",
            _require_text(input_path, "请选择要读取 wrapper 的 .hse2 容器。"),
        )
    elif normalized_action == "wrapper-remove":
        args = [
            "hse2-wrapper",
            "remove",
            "--input",
            _require_text(input_path, "请选择要修改 wrapper 的 .hse2 容器。"),
            "--output",
            _require_text(output_path, "请选择移除 wrapper 后的新 .hse2 输出路径。"),
            "--wrapper-id",
            _require_text(wrapper_id, "请输入要移除的 wrapper id。"),
        ]
        if password_file.strip():
            args.extend(["--password-file", password_file.strip()])
        if keyfile_path.strip():
            args.extend(["--keyfile", keyfile_path.strip()])
        if allow_dpapi:
            args.append("--dpapi")
        if force:
            args.append("--overwrite")
        argv = tuple(args)
    elif normalized_action == "access-destroy":
        confirmation_phrase = _require_text(access_confirmation_phrase, "请输入永久禁用访问确认短语。")
        if confirmation_phrase != DESTROY_ACCESS_CONFIRMATION_PHRASE:
            raise ValueError("永久禁用访问确认短语不匹配。")
        args = [
            "hse2-access",
            "destroy",
            "--input",
            _require_text(input_path, "请选择要永久禁用访问的 .hse2 容器。"),
            "--output",
            _require_text(output_path, "请选择永久禁用访问后的新 .hse2 输出路径。"),
            "--confirm",
            confirmation_phrase,
        ]
        if force:
            args.append("--overwrite")
        argv = tuple(args)
    else:  # pragma: no cover - guarded by _require_action.
        raise ValueError(f"unsupported HSE2 GUI action: {action}")
    return HSE2GuiCommandPlan(
        action=normalized_action,
        argv=argv,
        description=HSE2_GUI_ACTION_LABELS[normalized_action],
    )


def _require_action(value: str) -> str:
    normalized = value.strip()
    if normalized not in HSE2_GUI_ACTIONS:
        raise ValueError("请选择有效的 HSE2 实验操作。")
    return normalized


def _require_scope(value: str) -> str:
    normalized = value.strip() or "current_user"
    if normalized not in {"current_user", "local_machine"}:
        raise ValueError("DPAPI scope must be current_user or local_machine")
    return normalized


def _require_text(value: str, message: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(message)
    return normalized
