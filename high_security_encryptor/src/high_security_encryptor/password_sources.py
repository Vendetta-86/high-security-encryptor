"""运行时密码来源解析器。"""

from __future__ import annotations

from dataclasses import dataclass, field
import getpass
import os
from pathlib import Path
import subprocess
import sys
from typing import Callable


SecretSpec = str | dict[str, object]
ProviderHandler = Callable[[dict[str, object], str], str]


class PasswordSourceError(Exception):
    """当密码来源配置无法解析时抛出。"""


@dataclass(frozen=True)
class PasswordResolver:
    """把运行时密码来源引用解析为明文密码。"""

    environment: dict[str, str]
    prompt_callback: Callable[[str], str]
    file_reader: Callable[[Path], str]
    command_runner: Callable[[list[str]], str]
    providers: dict[str, ProviderHandler] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """安装内置 provider，除非调用方已显式提供同名实现。"""

        provider_map = dict(self.providers)
        provider_map.setdefault("literal", self._resolve_literal)
        provider_map.setdefault("env", self._resolve_env)
        provider_map.setdefault("prompt", self._resolve_prompt)
        provider_map.setdefault("file", self._resolve_file)
        provider_map.setdefault("command", self._resolve_command)
        object.__setattr__(self, "providers", provider_map)

    def resolve(self, spec: SecretSpec, context: str) -> str:
        """解析一个密码来源配置，得到明文密码。"""

        if isinstance(spec, str):
            if not spec:
                raise PasswordSourceError(f"{context}: empty password value")
            return spec
        if not isinstance(spec, dict):
            raise PasswordSourceError(f"{context}: invalid password source type")

        source_type = str(spec.get("type", "")).strip().lower()
        if not source_type:
            raise PasswordSourceError(f"{context}: missing password source type")
        try:
            provider = self.providers[source_type]
        except KeyError as exc:
            raise PasswordSourceError(f"{context}: unsupported password source type: {source_type!r}") from exc
        value = provider(spec, context)
        if not value:
            raise PasswordSourceError(f"{context}: resolved password is empty")
        return value

    def _resolve_literal(self, spec: dict[str, object], context: str) -> str:
        """解析配置里显式写出的字面量密码。"""

        value = str(spec.get("value", ""))
        if not value:
            raise PasswordSourceError(f"{context}: empty literal password value")
        return value

    def _resolve_env(self, spec: dict[str, object], context: str) -> str:
        """从环境变量读取密码。"""

        variable_name = str(spec.get("name", "")).strip()
        if not variable_name:
            raise PasswordSourceError(f"{context}: env source missing variable name")
        try:
            value = self.environment[variable_name]
        except KeyError as exc:
            raise PasswordSourceError(f"{context}: environment variable not set: {variable_name}") from exc
        if not value:
            raise PasswordSourceError(f"{context}: environment variable is empty: {variable_name}")
        return value

    def _resolve_prompt(self, spec: dict[str, object], context: str) -> str:
        """在运行时向用户提示输入密码。"""

        prompt = str(spec.get("prompt", "")).strip() or f"Enter password for {context}: "
        value = self.prompt_callback(prompt)
        if not value:
            raise PasswordSourceError(f"{context}: prompted password is empty")
        return value

    def _resolve_file(self, spec: dict[str, object], context: str) -> str:
        """通过读取本地文件解析密码。"""

        file_path = str(spec.get("path", "")).strip()
        if not file_path:
            raise PasswordSourceError(f"{context}: file source missing path")
        raw_value = self.file_reader(Path(file_path))
        return raw_value.rstrip("\r\n")

    def _resolve_command(self, spec: dict[str, object], context: str) -> str:
        """通过执行命令并读取标准输出解析密码。"""

        argv_value = spec.get("argv")
        if not isinstance(argv_value, list) or not argv_value:
            raise PasswordSourceError(f"{context}: command source requires non-empty argv list")
        argv = [str(item) for item in argv_value]
        output = self.command_runner(argv)
        return output.rstrip("\r\n")


def create_default_password_resolver() -> PasswordResolver:
    """创建 CLI 默认使用的密码解析器。"""

    def prompt_callback(prompt: str) -> str:
        try:
            return getpass.getpass(prompt)
        except (EOFError, OSError):
            sys.stderr.write(prompt)
            sys.stderr.flush()
            line = sys.stdin.readline()
            if line.endswith("\n"):
                line = line[:-1]
            return line

    def file_reader(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PasswordSourceError(f"file source could not read {path}") from exc

    def command_runner(argv: list[str]) -> str:
        try:
            result = subprocess.run(
                argv,
                text=True,
                capture_output=True,
                check=True,
            )
        except OSError as exc:
            raise PasswordSourceError(f"command source failed to launch: {argv[0]!r}") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else ""
            detail = f" ({stderr})" if stderr else ""
            raise PasswordSourceError(f"command source failed with exit code {exc.returncode}{detail}") from exc
        return result.stdout

    return PasswordResolver(
        environment=dict(os.environ),
        prompt_callback=prompt_callback,
        file_reader=file_reader,
        command_runner=command_runner,
    )
