"""Example config template export helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_example_config(
    *,
    mode: str,
    kind: str,
    output: str | None,
    print_to_stdout: bool,
    override_specs: list[str],
    file_override_specs: list[str],
) -> dict[str, Any]:
    """导出指定安全模式和用途的示例配置文件。"""

    example_path = get_example_template_path(mode, kind)
    example_payload = json.loads(example_path.read_text(encoding="utf-8"))
    applied_overrides = apply_example_overrides(example_payload, override_specs, file_override_specs)
    example_text = json.dumps(example_payload, ensure_ascii=False, indent=2)
    summary = {
        "command": "init-example",
        "security_mode": mode,
        "kind": kind,
        "source_example": str(example_path),
        "output_path": None,
        "applied_overrides": applied_overrides,
    }
    if print_to_stdout:
        summary["__raw_stdout__"] = example_text
        return summary
    if not output:
        raise ValueError("--output is required unless --print is used")
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(example_text, encoding="utf-8")
    summary["output_path"] = str(output_path)
    return summary


def get_example_template_path(mode: str, kind: str) -> Path:
    """定位指定模式和用途对应的示例配置文件。"""

    project_root = Path(__file__).resolve().parents[2]
    file_name = f"{mode.replace('-', '_')}_{kind}.json"
    return project_root / "examples" / file_name


def apply_example_overrides(
    payload: dict[str, Any],
    override_specs: list[str],
    file_override_specs: list[str],
) -> list[str]:
    """按 `--set` 与 `--set-file` 的形式原地替换示例配置中的现有字段。"""

    applied_overrides: list[str] = []
    for override_spec in override_specs:
        key_path, raw_value = _split_override_spec(override_spec)
        parsed_value = _parse_override_value(raw_value)
        _set_existing_path_value(payload, key_path.split("."), parsed_value)
        applied_overrides.append(key_path)
    for file_override_spec in file_override_specs:
        key_path, file_path = _split_override_spec(file_override_spec)
        parsed_value = _load_override_value_from_file(file_path)
        _set_existing_path_value(payload, key_path.split("."), parsed_value)
        applied_overrides.append(f"{key_path}@file")
    return applied_overrides


def _split_override_spec(override_spec: str) -> tuple[str, str]:
    """拆分单条 `KEY=VALUE` 覆盖表达式。"""

    if "=" not in override_spec:
        raise ValueError(f"invalid override {override_spec!r}: expected KEY=VALUE")
    key_path, raw_value = override_spec.split("=", 1)
    normalized_key_path = key_path.strip()
    if not normalized_key_path:
        raise ValueError(f"invalid override {override_spec!r}: key path is empty")
    return normalized_key_path, raw_value


def _parse_override_value(raw_value: str) -> Any:
    """把覆盖值优先解析为 JSON 字面量，失败时保留原始字符串。"""

    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value


def _load_override_value_from_file(file_path: str) -> Any:
    """从 JSON 文件加载覆盖值。"""

    normalized_file_path = file_path[1:] if file_path.startswith("@") else file_path
    override_path = Path(normalized_file_path)
    return json.loads(override_path.read_text(encoding="utf-8"))


def _set_existing_path_value(container: Any, path_parts: list[str], value: Any) -> None:
    """按点路径覆盖字典或列表里的已有字段。"""

    current = container
    for index, part in enumerate(path_parts):
        is_last = index == len(path_parts) - 1
        if isinstance(current, dict):
            if part not in current:
                raise ValueError(f"unknown override path: {'.'.join(path_parts)}")
            if is_last:
                current[part] = value
                return
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                numeric_index = int(part)
            except ValueError as exc:
                raise ValueError(f"list override path requires a numeric index: {'.'.join(path_parts)}") from exc
            if numeric_index < 0 or numeric_index >= len(current):
                raise ValueError(f"list override index out of range: {'.'.join(path_parts)}")
            if is_last:
                current[numeric_index] = value
                return
            current = current[numeric_index]
            continue
        raise ValueError(f"cannot traverse scalar value at path: {'.'.join(path_parts)}")
    raise ValueError(f"invalid override path: {'.'.join(path_parts)}")
