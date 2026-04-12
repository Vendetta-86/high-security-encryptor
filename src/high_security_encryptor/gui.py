"""Tkinter GUI wrapper for High Security Encryptor."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
import argparse
import io
import json
from pathlib import Path
import shlex
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from .cli import main as cli_main


SECURITY_MODES = ("compatible", "hardened", "no-password-tables")
CONFIG_KINDS = ("encrypt", "decrypt")
REPORT_FORMATS = ("json", "text")


@dataclass(frozen=True)
class GuiCommandResult:
    """Captured result from an existing CLI command."""

    exit_code: int
    stdout: str
    stderr: str


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
    args = [
        "validate-config",
        "--kind",
        _require_choice(kind, CONFIG_KINDS, "请选择 encrypt 或 decrypt。"),
        "--config",
        normalized_config_path,
    ]
    if strict:
        args.append("--strict")
    if report:
        args.append("--report")
        args.extend(["--format", _require_choice(report_format, REPORT_FORMATS, "请选择报告格式。")])
        if summary_only:
            args.append("--summary-only")
        if output_path.strip():
            args.extend(["--output", output_path.strip()])
        if exit_code_on_issues:
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
        _require_choice(mode, SECURITY_MODES, "请选择安全模式。"),
        "--kind",
        _require_choice(kind, CONFIG_KINDS, "请选择 encrypt 或 decrypt。"),
        "--output",
        _require_path(output_path, "请选择输出路径。"),
    ]


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


def smoke_test() -> None:
    """Validate GUI imports without opening a window."""

    root = tk.Tcl()
    if not root.call("info", "patchlevel"):
        raise RuntimeError("tkinter 不可用")


class HighSecurityEncryptorApp(ttk.Frame):
    """Main Tkinter application."""

    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=12)
        self.master = master
        self.master.title("高安全加密器")
        self.master.minsize(860, 620)
        self._is_busy = False

        self.pack(fill=tk.BOTH, expand=True)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_controls()
        self._build_log()

    def _build_controls(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=0, sticky="nsew")

        self._build_validate_tab(notebook)
        self._build_encrypt_tab(notebook)
        self._build_decrypt_tab(notebook)
        self._build_examples_tab(notebook)

    def _build_validate_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="配置校验")
        frame.columnconfigure(1, weight=1)

        self.validate_kind = tk.StringVar(value="encrypt")
        self.validate_config = tk.StringVar()
        self.validate_strict = tk.BooleanVar(value=False)
        self.validate_report = tk.BooleanVar(value=True)
        self.validate_format = tk.StringVar(value="json")
        self.validate_output = tk.StringVar()
        self.validate_summary_only = tk.BooleanVar(value=False)
        self.validate_exit_code_on_issues = tk.BooleanVar(value=False)
        self.validate_warnings_as_errors = tk.BooleanVar(value=False)

        self._add_choice_row(frame, 0, "类型", self.validate_kind, CONFIG_KINDS)
        self._add_path_row(frame, 1, "配置文件", self.validate_config, self._browse_validate_config)
        self._add_choice_row(frame, 2, "报告格式", self.validate_format, REPORT_FORMATS)
        self._add_path_row(frame, 3, "报告输出", self.validate_output, self._browse_validate_output, save=True)

        options = ttk.Frame(frame)
        options.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(options, text="严格模式", variable=self.validate_strict).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(options, text="生成报告", variable=self.validate_report).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(options, text="仅摘要", variable=self.validate_summary_only).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            options,
            text="发现问题返回非零",
            variable=self.validate_exit_code_on_issues,
        ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(
            options,
            text="警告视为错误",
            variable=self.validate_warnings_as_errors,
        ).pack(side=tk.LEFT)

        ttk.Button(frame, text="开始校验", command=self._run_validate).grid(row=5, column=0, sticky="w", pady=(14, 0))

    def _build_encrypt_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="批量加密")
        frame.columnconfigure(1, weight=1)

        self.encrypt_config = tk.StringVar()
        self._add_path_row(frame, 0, "配置文件", self.encrypt_config, self._browse_encrypt_config)
        ttk.Label(
            frame,
            text="GUI 会阻止 prompt 密码来源，避免等待控制台输入。请使用 literal、env、file 或 command。",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(frame, text="开始加密", command=self._run_encrypt).grid(
            row=2,
            column=0,
            sticky="w",
            pady=(14, 0),
        )

    def _build_decrypt_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="批量解密")
        frame.columnconfigure(1, weight=1)

        self.decrypt_config = tk.StringVar()
        self._add_path_row(frame, 0, "配置文件", self.decrypt_config, self._browse_decrypt_config)
        ttk.Label(
            frame,
            text="GUI 会阻止 prompt 密码来源，避免等待控制台输入。请使用 literal、env、file 或 command。",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(frame, text="开始解密", command=self._run_decrypt).grid(
            row=2,
            column=0,
            sticky="w",
            pady=(14, 0),
        )

    def _build_examples_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="示例配置")
        frame.columnconfigure(1, weight=1)

        self.example_mode = tk.StringVar(value="hardened")
        self.example_kind = tk.StringVar(value="encrypt")
        self.example_output = tk.StringVar()

        self._add_choice_row(frame, 0, "安全模式", self.example_mode, SECURITY_MODES)
        self._add_choice_row(frame, 1, "类型", self.example_kind, CONFIG_KINDS)
        self._add_path_row(frame, 2, "输出文件", self.example_output, self._browse_example_output, save=True)
        ttk.Button(frame, text="生成示例", command=self._run_init_example).grid(
            row=3,
            column=0,
            sticky="w",
            pady=(14, 0),
        )

    def _build_log(self) -> None:
        log_frame = ttk.Frame(self, padding=(0, 10, 0, 0))
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        button_row = ttk.Frame(log_frame)
        button_row.grid(row=0, column=0, sticky="ew")
        ttk.Label(button_row, text="输出").pack(side=tk.LEFT)
        ttk.Button(button_row, text="清空", command=self._clear_log).pack(side=tk.RIGHT)

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
        button_text = "另存为" if save else "浏览"
        ttk.Button(parent, text=button_text, command=browse_command).grid(row=row, column=2, pady=4)

    def _browse_validate_config(self) -> None:
        self._browse_json_file(self.validate_config)

    def _browse_validate_output(self) -> None:
        self._browse_save_file(self.validate_output, default_extension=".json")

    def _browse_encrypt_config(self) -> None:
        self._browse_json_file(self.encrypt_config)

    def _browse_decrypt_config(self) -> None:
        self._browse_json_file(self.decrypt_config)

    def _browse_example_output(self) -> None:
        self._browse_save_file(self.example_output, default_extension=".json")

    def _browse_json_file(self, variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            title="选择 JSON 配置文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if path:
            variable.set(path)

    def _browse_save_file(self, variable: tk.StringVar, *, default_extension: str) -> None:
        path = filedialog.asksaveasfilename(
            title="选择输出路径",
            defaultextension=default_extension,
            filetypes=[("JSON 文件", "*.json"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if path:
            variable.set(path)

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

    def _run_cli(self, args: list[str], *, block_prompt_providers: bool = False) -> None:
        if self._is_busy:
            messagebox.showinfo("正在运行", "已有命令正在执行。")
            return
        if block_prompt_providers and config_uses_prompt_provider(_config_path_from_args(args)):
            messagebox.showerror(
                "不支持的密码来源",
                "prompt 密码来源可能阻塞 GUI。请使用 literal、env、file 或 command。",
            )
            return

        self._is_busy = True
        self._append_log(f"$ high-security-encryptor {shlex.join(args)}\n")
        worker = threading.Thread(target=self._execute_cli_worker, args=(args,), daemon=True)
        worker.start()

    def _execute_cli_worker(self, args: list[str]) -> None:
        try:
            result = invoke_cli_command(args)
        except Exception as exc:  # noqa: BLE001 - GUI boundary reports unexpected failures.
            result = GuiCommandResult(exit_code=1, stdout="", stderr=f"错误：{exc}")
        self.after(0, self._handle_cli_result, result)

    def _handle_cli_result(self, result: GuiCommandResult) -> None:
        self._is_busy = False
        if result.stdout:
            self._append_log(result.stdout)
            if not result.stdout.endswith("\n"):
                self._append_log("\n")
        if result.stderr:
            self._append_log(result.stderr)
            if not result.stderr.endswith("\n"):
                self._append_log("\n")
        self._append_log(f"退出码：{result.exit_code}\n\n")
        if result.exit_code == 0:
            return
        messagebox.showerror("命令失败", f"命令退出码：{result.exit_code}。")

    def _append_log(self, text: str) -> None:
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _show_input_error(self, exc: ValueError) -> None:
        messagebox.showerror("需要输入", str(exc))


def main(argv: list[str] | None = None) -> int:
    """Run the GUI application."""

    parser = argparse.ArgumentParser(prog="high-security-encryptor-gui")
    parser.add_argument("--smoke-test", action="store_true", help="验证 GUI 依赖并退出。")
    args = parser.parse_args(argv)
    if args.smoke_test:
        smoke_test()
        return 0

    root = tk.Tk()
    HighSecurityEncryptorApp(root)
    root.mainloop()
    return 0


def _require_path(value: str, message: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(message)
    return normalized


def _require_choice(value: str, allowed: tuple[str, ...], message: str) -> str:
    normalized = value.strip()
    if normalized not in allowed:
        raise ValueError(message)
    return normalized


def _config_path_from_args(args: list[str]) -> str:
    try:
        index = args.index("--config")
    except ValueError:
        return ""
    try:
        return args[index + 1]
    except IndexError:
        return ""


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
