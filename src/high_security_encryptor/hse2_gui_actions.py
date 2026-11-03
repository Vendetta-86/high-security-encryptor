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
    "v4-create",
    "v4-open",
    "v4-replace",
    "v5-create",
    "v5-open",
    "v5-verify",
    "v5-preview",
    "v5-password-update",
    "v5-replace",
    "v5-compact",
    "v4-to-v5",
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
    "v4-create": "实验性 HSE2 v4 双视图创建",
    "v4-open": "实验性 HSE2 v4 单视图恢复",
    "v4-replace": "实验性 HSE2 v4 单视图替换",
    "v5-create": "实验性 HSE2 v5 双视图创建",
    "v5-open": "实验性 HSE2 v5 单视图恢复",
    "v5-verify": "实验性 HSE2 v5 完整校验（不写明文）",
    "v5-preview": "实验性 HSE2 v5 恢复预览",
    "v5-password-update": "实验性 HSE2 v5 单视图更换口令",
    "v5-replace": "实验性 HSE2 v5 单视图替换",
    "v5-compact": "实验性 HSE2 v5 双密码压缩",
    "v4-to-v5": "实验性 HSE2 v4 导出到 v5",
}

HSE2_GUI_ACTION_HELP = {
    "encrypt-config": "按 JSON 加密配置运行批量任务；先检查配置和密码来源，确认输出目录及元数据去向。",
    "decrypt-config": "按 JSON 解密配置恢复批量文件；准备同一批次的清单、模板及所需口令。",
    "archive-create": "把选定文件夹写入新的 HSE2 归档；保留原文件，并单独保存口令、keyfile 等解锁材料。",
    "archive-open": "把 HSE2 归档恢复到目标目录；先确认目标、空间和冲突，再使用匹配的解锁因子。",
    "archive-validate": "认证归档中的加密内容而不写出明文；检查结果不会替代备份或恢复演练。",
    "validate": "检查 HSE2 配置文件和规则，不会执行加密或解密。",
    "inspect": "查看归档结构和元数据；结果可能显示文件名、数量等信息，注意旁观者和日志。",
    "header-backup-export": "导出归档头部备份以支持特定头部恢复；它不保存口令、keyfile 或明文。",
    "rotate-keyfile": "按配置轮换归档使用的 keyfile；准备新旧 keyfile，验证新副本能解锁后再归档旧材料。",
    "generate-keyfile": "生成随机 keyfile；立即另存独立备份，丢失后可能无法解锁依赖它的归档。",
    "dpapi-protect": "用 Windows DPAPI 保护 keyfile 副本；解锁范围受当前 Windows 用户或设备范围限制。",
    "wrapper-list": "查看归档有哪些解锁 wrapper；输出是元数据，分享前检查是否泄露信息。",
    "wrapper-add": "使用现有解锁因子，为新归档副本增加一种解锁方式；先验证新凭据并保留输入归档。",
    "wrapper-remove": "从新归档副本移除指定解锁方式；移除前确认其他有效解锁方式和备份仍可用。",
    "wrapper-rewrap": "将指定 wrapper 改用新口令或 keyfile 写入新副本；保留旧归档并核对新凭据。",
    "access-destroy": "永久禁用输出副本的归档访问；可能令内容无法恢复，只有确认不再需要时才使用。",
    "v4-create": "创建实验性固定容量双视图归档；容量会影响文件上限和体积，保留输入及恢复材料。",
    "v4-open": "从实验性 v4 归档恢复一个视图；核对输出位置，完整验证前保留原归档。",
    "v4-replace": "替换实验性 v4 的一个视图并写出新副本；先检查固定容量是否足够。",
    "v5-create": "创建公开双视图的实验性 v5 归档；准备两组不同口令。格式不承诺可否认性。",
    "v5-open": "恢复实验性 v5 中由所输口令解锁的视图；预览输出并保留源归档。",
    "v5-verify": "认证所选 v5 视图的活动内容，不写出明文；可能显示归档元数据。",
    "v5-preview": "预览 v5 恢复文件数、空间需求和目标冲突；预览通过不代表恢复必定成功。",
    "v5-password-update": "更新所选 v5 视图口令并写出新副本；需要旧口令，新口令须与另一视图不同。",
    "v5-replace": "替换所选 v5 视图内容并生成新归档；另一视图与输入归档应保持可用。",
    "v5-compact": "用两组视图口令重写活动 v5 内容到新副本；不会保证旧密文从介质安全删除。",
    "v4-to-v5": "显式把 v4 内容导出到新的 v5 归档；准备两组不同口令，验证新档后再处理旧档。",
}


@dataclass(frozen=True)
class HSE2GuiCommandPlan:
    """A GUI-safe HSE2 command plan."""

    action: str
    argv: tuple[str, ...]
    description: str
    experimental: bool = True
    secret_input: str | None = field(default=None, repr=False, compare=False)
    secret_inputs: tuple[str, ...] = field(default=(), repr=False, compare=False)


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
    primary_file_spec: str = "",
    secondary_file_spec: str = "",
    capacity_records: int = 2,
    primary_password: str = "",
    primary_password_confirmation: str = "",
    secondary_password: str = "",
    secondary_password_confirmation: str = "",
    current_view_password: str = "",
    new_view_password: str = "",
    new_view_password_confirmation: str = "",
    replace_file_spec: str = "",
) -> HSE2GuiCommandPlan:
    """Build a CLI argv plan for one explicit HSE2 GUI action."""

    normalized_action = _require_action(action)
    plan_secret: str | None = None
    plan_secrets: tuple[str, ...] = ()
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
    elif normalized_action == "v4-create":
        if (not primary_password or primary_password != primary_password_confirmation
                or not secondary_password or secondary_password != secondary_password_confirmation):
            raise ValueError("请分别填写并确认两个 v4 视图密码。")
        if primary_password == secondary_password:
            raise ValueError("两个 v4 视图密码必须不同。")
        if type(capacity_records) is not int or capacity_records < 2 or capacity_records > 65536 or capacity_records % 2:
            raise ValueError("v4 固定记录容量必须为 2 到 65536 之间的偶数。")
        primary_spec = _require_text(primary_file_spec, "请提供 primary 文件映射，格式为归档路径=源文件路径。")
        secondary_spec = _require_text(secondary_file_spec, "请提供 secondary 文件映射，格式为归档路径=源文件路径。")
        args = ["hse2", "v4-create", "--output", _require_text(output_path, "请选择 v4 输出路径。"),
                "--capacity-records", str(capacity_records), "--primary-file", primary_spec,
                "--secondary-file", secondary_spec]
        if force:
            args.append("--force")
        plan_secrets = (primary_password, primary_password_confirmation, secondary_password, secondary_password_confirmation)
        argv = tuple(args)
    elif normalized_action == "v4-open":
        args = ["hse2", "v4-open", "--input", _require_text(input_path, "请选择 v4 容器。"),
                "--output-dir", _require_text(output_path, "请选择新的恢复目录。")]
        plan_secrets = (_require_text(archive_password, "请输入视图密码。"),)
        argv = tuple(args)
    elif normalized_action == "v4-replace":
        args = ["hse2", "v4-replace", "--input", _require_text(input_path, "请选择 v4 容器。"),
                "--output", _require_text(output_path, "请选择新的 v4 输出路径。"),
                "--file", _require_text(replace_file_spec, "请提供文件映射，格式为归档路径=源文件路径。")]
        if force:
            args.append("--force")
        plan_secrets = (_require_text(archive_password, "请输入需要替换的视图密码。"),)
        argv = tuple(args)
    elif normalized_action == "v5-create":
        if (not primary_password or primary_password != primary_password_confirmation
                or not secondary_password or secondary_password != secondary_password_confirmation):
            raise ValueError("请分别填写并确认两个 v5 视图密码。")
        if primary_password == secondary_password:
            raise ValueError("两个 v5 视图密码必须不同。")
        primary_spec = _require_text(primary_file_spec, "请提供 primary 文件映射，格式为归档路径=源文件路径。")
        secondary_spec = _require_text(secondary_file_spec, "请提供 secondary 文件映射，格式为归档路径=源文件路径。")
        args = ["hse2", "v5-create", "--output", _require_text(output_path, "请选择 v5 输出路径。"),
                "--primary-file", primary_spec, "--secondary-file", secondary_spec]
        if force:
            args.append("--force")
        plan_secrets = (primary_password, primary_password_confirmation, secondary_password, secondary_password_confirmation)
        argv = tuple(args)
    elif normalized_action == "v5-open":
        args = ["hse2", "v5-open", "--input", _require_text(input_path, "请选择 v5 容器。"),
                "--output-dir", _require_text(output_path, "请选择新的恢复目录。")]
        plan_secrets = (_require_text(archive_password, "请输入视图密码。"),)
        argv = tuple(args)
    elif normalized_action == "v5-verify":
        args = ["hse2", "v5-verify", "--input", _require_text(input_path, "请选择 v5 容器。")]
        plan_secrets = (_require_text(archive_password, "请输入要校验视图的密码。"),)
        argv = tuple(args)
    elif normalized_action == "v5-preview":
        args = ["hse2", "v5-preview", "--input", _require_text(input_path, "请选择 v5 容器。"),
                "--output-dir", _require_text(output_path, "请选择新的恢复目录。")]
        plan_secrets = (_require_text(archive_password, "请输入要预览视图的密码。"),)
        argv = tuple(args)
    elif normalized_action == "v5-password-update":
        if not new_view_password or new_view_password != new_view_password_confirmation:
            raise ValueError("请填写并确认新视图口令。")
        if not current_view_password:
            raise ValueError("请输入当前视图口令。")
        if new_view_password == current_view_password:
            raise ValueError("新口令必须与当前口令不同。")
        args = ["hse2", "v5-password-update", "--input", _require_text(input_path, "请选择 v5 容器。"),
                "--output", _require_text(output_path, "请选择新的 v5 输出路径。")]
        if force:
            args.append("--force")
        plan_secrets = (current_view_password, new_view_password, new_view_password_confirmation)
        argv = tuple(args)
    elif normalized_action == "v5-replace":
        args = ["hse2", "v5-replace", "--input", _require_text(input_path, "请选择 v5 容器。"),
                "--output", _require_text(output_path, "请选择新的 v5 输出路径。")]
        if replace_file_spec.strip():
            args.extend(["--file", replace_file_spec.strip()])
        if force:
            args.append("--force")
        plan_secrets = (_require_text(archive_password, "请输入需要替换的视图密码。"),)
        argv = tuple(args)
    elif normalized_action in {"v5-compact", "v4-to-v5"}:
        command = normalized_action
        input_label = "v5" if command == "v5-compact" else "v4"
        args = [
            "hse2", command, "--input", _require_text(input_path, f"请选择 {input_label} 容器。"),
            "--output", _require_text(output_path, "请选择新的 v5 输出路径。"),
        ]
        if force:
            args.append("--force")
        plan_secrets = (
            _require_text(primary_password, "请输入 primary 视图密码。"),
            _require_text(secondary_password, "请输入 secondary 视图密码。"),
        )
        if plan_secrets[0] == plan_secrets[1]:
            raise ValueError("两个视图密码必须不同。")
        argv = tuple(args)
    else:  # pragma: no cover - guarded by _require_action.
        raise ValueError(f"unsupported HSE2 GUI action: {action}")
    return HSE2GuiCommandPlan(
        action=normalized_action,
        argv=argv,
        description=HSE2_GUI_ACTION_LABELS[normalized_action],
        secret_input=plan_secret,
        secret_inputs=plan_secrets,
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
