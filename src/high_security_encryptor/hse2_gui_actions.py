"""GUI-facing command builders for explicit HSE2 workflows.

These helpers deliberately build CLI argument lists instead of reimplementing
HSE2 workflow logic in the GUI layer. The Tkinter UI can call these builders and
then pass the returned argv to the existing GUI CLI runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE


HSE2_GUI_ACTIONS = (
    "encrypt-config",
    "decrypt-config",
    "archive-create",
    "archive-open",
    "archive-validate",
    "validate",
    "inspect",
    "header-backup-export",
    "rotate-keyfile",
    "generate-keyfile",
    "dpapi-protect",
    "wrapper-list",
    "wrapper-add",
    "wrapper-remove",
    "wrapper-rewrap",
    "access-destroy",
)

HSE2_GUI_ACTION_LABELS = {
    "encrypt-config": "HSE2 加密配置",
    "decrypt-config": "HSE2 解密配置",
    "archive-create": "创建 HSE2 归档",
    "archive-open": "解密并打开 HSE2 归档",
    "archive-validate": "完整校验 HSE2 归档",
    "validate": "HSE2 只读校验",
    "inspect": "检查 HSE2 元数据",
    "header-backup-export": "导出 HSE2 header backup",
    "rotate-keyfile": "HSE2 keyfile 轮换",
    "generate-keyfile": "生成 keyfile",
    "dpapi-protect": "Windows DPAPI 保护 keyfile",
    "wrapper-list": "列出 HSE2 wrapper",
    "wrapper-add": "添加 HSE2 wrapper",
    "wrapper-remove": "移除指定 HSE2 wrapper",
    "wrapper-rewrap": "更换 HSE2 wrapper",
    "access-destroy": "永久禁用 HSE2 访问",
}


@dataclass(frozen=True)
class HSE2GuiCommandPlan:
    """A GUI-safe HSE2 command plan."""

    action: str
    argv: tuple[str, ...]
    description: str
    experimental: bool = True
    secret_input: str | None = field(default=None, repr=False, compare=False)


def build_hse2_gui_command(
    *,
    action: str,
    config_path: str = "",
    root_path: str = "",
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
    new_wrapper_id: str = "",
    new_password_file: str = "",
    new_keyfile_path: str = "",
    new_profile_name: str = "hardened",
    new_label: str = "",
    new_wrapper_dpapi: bool = False,
    archive_profile: str = "hardened",
    archive_format_version: int = 2,
    archive_chunk_size: int = 1024 * 1024,
    archive_pad_last_chunk: bool = False,
    archive_validate_after_create: bool = False,
    archive_validate_before_open: bool = False,
    archive_password: str = "",
    archive_password_confirmation: str = "",
    access_confirmation_phrase: str = "",
) -> HSE2GuiCommandPlan:
    """Build a CLI argv plan for one explicit HSE2 GUI action."""

    normalized_action = _require_action(action)
    plan_secret: str | None = None
    if normalized_action == "encrypt-config":
        argv = ("hse2-encrypt-config", "--config", _require_text(config_path, "请选择 HSE2 加密配置文件。"))
    elif normalized_action == "decrypt-config":
        argv = ("hse2-decrypt-config", "--config", _require_text(config_path, "请选择 HSE2 解密配置文件。"))
    elif normalized_action == "archive-create":
        if archive_profile not in {"compatible", "hardened", "paranoid"}:
            raise ValueError("请选择有效的 HSE2 密码安全等级。")
        if archive_format_version not in {2, 3}:
            raise ValueError("HSE2 格式版本必须为 2 或 3。")
        if archive_chunk_size < 1 or archive_chunk_size > 16 * 1024 * 1024:
            raise ValueError("HSE2 chunk size must be between 1 byte and 16 MiB.")
        password_path = password_file.strip()
        keyfile = keyfile_path.strip()
        typed_password = archive_password
        if bool(typed_password) != bool(archive_password_confirmation):
            raise ValueError("请填写归档密码和确认密码。")
        if typed_password and typed_password != archive_password_confirmation:
            raise ValueError("两次输入的归档密码不一致。")
        if typed_password and password_path:
            raise ValueError("请使用密码输入框或密码文件其中一种方式。")
        if new_wrapper_dpapi and (typed_password or password_path or keyfile):
            raise ValueError("新归档 DPAPI wrapper 不能同时使用密码或 keyfile。")
        if not new_wrapper_dpapi and not typed_password and not password_path and not keyfile:
            raise ValueError("请选择密码文件、keyfile 或 Windows DPAPI 作为归档解锁方式。")
        if archive_profile == "paranoid" and (password_path or typed_password) and not keyfile:
            raise ValueError("极高安全密码 wrapper 需要同时提供 keyfile。")
        args = [
            "hse2-create",
            "--root", _require_text(root_path, "请选择要加密的文件夹。"),
            "--output", _require_text(output_path, "请选择 HSE2 归档输出路径。"),
            "--format-version", str(archive_format_version),
            "--chunk-size", str(archive_chunk_size),
        ]
        if password_path:
            args.extend(["--password-file", password_path, "--profile", archive_profile])
        elif typed_password:
            args.extend(["--profile", archive_profile])
            plan_secret = typed_password
        if keyfile:
            args.extend(["--keyfile", keyfile])
        if new_wrapper_dpapi:
            args.append("--dpapi")
        if archive_pad_last_chunk:
            args.append("--pad-last-chunk")
        if archive_validate_after_create:
            args.append("--validate-after-create")
        if force:
            args.append("--overwrite")
        argv = tuple(args)
    elif normalized_action == "archive-open":
        password_path = password_file.strip()
        keyfile = keyfile_path.strip()
        typed_password = archive_password
        if typed_password and password_path:
            raise ValueError("请使用密码输入框或密码文件其中一种方式。")
        if not password_path and not typed_password and not keyfile and not allow_dpapi:
            raise ValueError("请选择密码文件、keyfile 或允许 Windows DPAPI 解锁。")
        args = [
            "hse2-open",
            "--input", _require_text(input_path, "请选择要解密的 .hse2 容器。"),
            "--output-dir", _require_text(output_path, "请选择解密文件的输出文件夹。"),
        ]
        if password_path:
            args.extend(["--password-file", password_path])
        if typed_password:
            plan_secret = typed_password
        if keyfile:
            args.extend(["--keyfile", keyfile])
        if allow_dpapi:
            args.append("--dpapi")
        if force:
            args.append("--overwrite")
        if archive_validate_before_open:
            args.append("--validate-before-open")
        argv = tuple(args)
    elif normalized_action == "archive-validate":
        password_path = password_file.strip()
        keyfile = keyfile_path.strip()
        typed_password = archive_password
        if typed_password and password_path:
            raise ValueError("请使用密码输入框或密码文件其中一种方式。")
        if not password_path and not typed_password and not keyfile and not allow_dpapi:
            raise ValueError("请选择密码文件、keyfile 或允许 Windows DPAPI 解锁。")
        args = ["hse2-archive-validate", "--input", _require_text(input_path, "请选择要校验的 .hse2 容器。")]
        if password_path:
            args.extend(["--password-file", password_path])
        if typed_password:
            plan_secret = typed_password
        if keyfile:
            args.extend(["--keyfile", keyfile])
        if allow_dpapi:
            args.append("--dpapi")
        argv = tuple(args)
    elif normalized_action == "validate":
        args: list[str] = ["hse2-validate", "--config", _require_text(config_path, "请选择 HSE2 校验配置文件。")]
        if validation_report_output.strip():
            args.extend(["--output", validation_report_output.strip()])
        if validation_summary_only:
            args.append("--summary-only")
        if validation_exit_code_on_failure:
            args.append("--exit-code-on-failure")
        argv = tuple(args)
    elif normalized_action == "inspect":
        argv = (
            "hse2-inspect",
            "--input",
            _require_text(input_path, "请选择要检查元数据的 .hse2 容器。"),
        )
    elif normalized_action == "header-backup-export":
        args = [
            "hse2-header-backup", "export",
            "--input", _require_text(input_path, "请选择要备份 header 的 .hse2 容器。"),
            "--output", _require_text(output_path, "请选择 .hse2.header 备份输出路径。"),
        ]
        if force:
            args.append("--overwrite")
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
    elif normalized_action == "wrapper-add":
        new_id = _require_text(wrapper_id, "请输入要新增的 wrapper id。")
        if not password_file.strip() and not keyfile_path.strip() and not allow_dpapi:
            raise ValueError("请选择现有容器的密码文件、keyfile 或 DPAPI 解锁方式。")
        if new_wrapper_dpapi and (new_password_file.strip() or new_keyfile_path.strip()):
            raise ValueError("新 DPAPI wrapper 不能同时使用密码或 keyfile。")
        if not new_wrapper_dpapi and not new_password_file.strip() and not new_keyfile_path.strip():
            raise ValueError("请提供新密码文件、新 keyfile 或选择新 DPAPI wrapper。")
        args = [
            "hse2-wrapper", "add", "--input",
            _require_text(input_path, "请选择要添加 wrapper 的 .hse2 容器。"),
            "--output", _require_text(output_path, "请选择添加 wrapper 后的新 .hse2 输出路径。"),
            "--wrapper-id", new_id,
        ]
        if new_password_file.strip():
            args.extend(["--new-password-file", new_password_file.strip()])
        if new_keyfile_path.strip():
            args.extend(["--new-keyfile", new_keyfile_path.strip()])
        if new_wrapper_dpapi:
            args.append("--new-dpapi")
        elif new_password_file.strip():
            if new_profile_name not in {"compatible", "hardened", "paranoid"}:
                raise ValueError("请选择有效的 HSE2 密码 wrapper 安全等级。")
            args.extend(["--new-profile", new_profile_name])
        if new_label.strip():
            args.extend(["--new-label", new_label.strip()])
        if password_file.strip():
            args.extend(["--password-file", password_file.strip()])
        if keyfile_path.strip():
            args.extend(["--keyfile", keyfile_path.strip()])
        if allow_dpapi:
            args.append("--dpapi")
        if force:
            args.append("--overwrite")
        argv = tuple(args)
    elif normalized_action == "wrapper-rewrap":
        old_wrapper_id = _require_text(wrapper_id, "请选择要替换的现有 wrapper id。")
        if not password_file.strip() and not keyfile_path.strip() and not allow_dpapi:
            raise ValueError("请选择现有容器的密码文件、keyfile 或 DPAPI 解锁方式。")
        if new_wrapper_dpapi and (new_password_file.strip() or new_keyfile_path.strip()):
            raise ValueError("新 DPAPI wrapper 不能同时使用密码或 keyfile。")
        if not new_wrapper_dpapi and not new_password_file.strip() and not new_keyfile_path.strip():
            raise ValueError("请提供新密码文件、新 keyfile 或选择新 DPAPI wrapper。")
        args = [
            "hse2-wrapper", "rewrap", "--input",
            _require_text(input_path, "请选择要更新 wrapper 的 .hse2 容器。"),
            "--output", _require_text(output_path, "请选择重新包装后的新 .hse2 输出路径。"),
            "--wrapper-id", old_wrapper_id,
        ]
        if new_wrapper_id.strip():
            args.extend(["--new-wrapper-id", new_wrapper_id.strip()])
        if new_password_file.strip():
            args.extend(["--new-password-file", new_password_file.strip()])
        if new_keyfile_path.strip():
            args.extend(["--new-keyfile", new_keyfile_path.strip()])
        if new_wrapper_dpapi:
            args.append("--new-dpapi")
        elif new_password_file.strip():
            if new_profile_name not in {"compatible", "hardened", "paranoid"}:
                raise ValueError("请选择有效的 HSE2 密码 wrapper 安全等级。")
            args.extend(["--new-profile", new_profile_name])
        if new_label.strip():
            args.extend(["--new-label", new_label.strip()])
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
        if password_file.strip():
            args.extend(["--password-file", password_file.strip()])
        if keyfile_path.strip():
            args.extend(["--keyfile", keyfile_path.strip()])
        if allow_dpapi:
            args.append("--dpapi")
        if force:
            args.append("--overwrite")
        argv = tuple(args)
    else:  # pragma: no cover - guarded by _require_action.
        raise ValueError(f"unsupported HSE2 GUI action: {action}")
    return HSE2GuiCommandPlan(
        action=normalized_action,
        argv=argv,
        description=HSE2_GUI_ACTION_LABELS[normalized_action],
        secret_input=plan_secret,
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
