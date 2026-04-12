"""Rendering, persistence, and exit-code helpers for validation reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def render_validation_report_text(summary: dict[str, Any]) -> str:
    """把结构化校验报告渲染成适合终端阅读的文本。"""

    lines = [
        "配置校验报告",
        f"kind: {summary['kind']}",
        f"config: {summary['config_path']}",
        f"security_mode: {summary['security_mode']}",
        f"strict: {summary['strict']}",
        f"valid: {summary['valid']}",
    ]
    issues = summary.get("issues", [])
    if not issues:
        lines.append("issues: none")
        return "\n".join(lines)

    lines.append(f"issues: {len(issues)}")
    for index, issue in enumerate(issues, start=1):
        lines.append(f"{index}. [{issue['severity']}] {issue['code']}")
        lines.append(f"   message: {issue['message']}")
        lines.append(f"   suggestion: {issue['suggestion']}")
    return "\n".join(lines)


def render_validation_report_summary_text(summary: dict[str, Any]) -> str:
    """把校验报告渲染成更紧凑的摘要文本。"""

    issues = summary.get("issues", [])
    warning_count = sum(1 for issue in issues if issue.get("severity") == "warning")
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    lines = [
        "配置校验摘要",
        f"kind: {summary['kind']}",
        f"security_mode: {summary['security_mode']}",
        f"valid: {summary['valid']}",
        f"errors: {error_count}",
        f"warnings: {warning_count}",
    ]
    if issues:
        lines.append(f"top_issue: {issues[0]['code']}")
    if summary.get("output_path"):
        lines.append(f"full_report: {summary['output_path']}")
    return "\n".join(lines)


def build_validation_report_summary_payload(summary: dict[str, Any]) -> dict[str, Any]:
    """构建适合 summary-only 输出的紧凑 JSON 摘要。"""

    issues = summary.get("issues", [])
    warning_count = sum(1 for issue in issues if issue.get("severity") == "warning")
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    return {
        "command": summary["command"],
        "kind": summary["kind"],
        "config_path": summary["config_path"],
        "security_mode": summary["security_mode"],
        "strict": summary["strict"],
        "report": summary["report"],
        "format": summary["format"],
        "summary_only": True,
        "valid": summary["valid"],
        "issue_counts": {
            "error": error_count,
            "warning": warning_count,
            "total": len(issues),
        },
        "top_issue_code": issues[0]["code"] if issues else None,
        "output_path": summary.get("output_path"),
        "exit_code_on_issues": summary.get("exit_code_on_issues", False),
        "warnings_as_errors": summary.get("warnings_as_errors", False),
    }


def maybe_write_validation_report(args: argparse.Namespace, summary: dict[str, Any]) -> None:
    """在用户提供输出路径时，把报告内容写入文件。"""

    output_path_value = getattr(args, "output", None)
    if not output_path_value:
        return
    output_path = Path(output_path_value)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if summary.get("format") == "text":
        report_text = render_validation_report_text(summary)
        output_path.write_text(report_text, encoding="utf-8")
        return
    serializable_summary = dict(summary)
    serializable_summary.pop("__raw_stdout__", None)
    output_path.write_text(
        json.dumps(serializable_summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def should_return_issue_exit_code(args: argparse.Namespace, summary: Any) -> bool:
    """判断当前命令是否应在报告存在问题时返回非零退出码。"""

    if not (
        getattr(args, "command", None) == "validate-config"
        and getattr(args, "report", False)
        and getattr(args, "exit_code_on_issues", False)
        and isinstance(summary, dict)
    ):
        return False
    issues = summary.get("issues", [])
    if getattr(args, "warnings_as_errors", False):
        return bool(issues)
    return bool(
        not summary.get("valid", True) or _contains_error_issues(issues)
    )


def _contains_error_issues(issues: list[dict[str, str]]) -> bool:
    """判断问题列表中是否包含 error 级别的问题。"""

    return any(issue.get("severity") == "error" for issue in issues)
