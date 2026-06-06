"""Quickstart workspace helpers for the HSE2 experimental GUI."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import secrets

DEFAULT_KEYFILE_BYTES = 32
DEFAULT_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class HSE2QuickstartWorkspace:
    """Files produced by the quickstart workspace generator."""

    base_dir: Path
    sample_input: Path
    keyfile: Path
    encrypted_output: Path
    restored_output: Path
    encrypt_config: Path
    validate_config: Path
    decrypt_config: Path
    validation_report: Path
    command_notes: Path

    def paths(self) -> tuple[Path, ...]:
        return (
            self.sample_input,
            self.keyfile,
            self.encrypt_config,
            self.validate_config,
            self.decrypt_config,
            self.command_notes,
        )


def build_hse2_quickstart_paths(base_dir: str | Path) -> HSE2QuickstartWorkspace:
    """Return the conventional file layout for a quickstart workspace."""

    root = Path(base_dir).expanduser()
    return HSE2QuickstartWorkspace(
        base_dir=root,
        sample_input=root / "plain.txt",
        keyfile=root / "wrapper.key",
        encrypted_output=root / "plain.txt.hse2",
        restored_output=root / "plain.restored.txt",
        encrypt_config=root / "hse2-encrypt.json",
        validate_config=root / "hse2-validate.json",
        decrypt_config=root / "hse2-decrypt.json",
        validation_report=root / "hse2-validation-report.json",
        command_notes=root / "hse2-quickstart-commands.txt",
    )


def create_hse2_quickstart_workspace(
    base_dir: str | Path,
    *,
    keyfile_size: int = DEFAULT_KEYFILE_BYTES,
    overwrite: bool = False,
) -> HSE2QuickstartWorkspace:
    """Create a minimal local HSE2 keyfile workflow workspace.

    The generated workspace writes only sample plaintext, a random local keyfile,
    JSON config files, and a command note file. It does not run encryption,
    decryption, validation, or DPAPI operations.
    """

    if keyfile_size < 16:
        raise ValueError("keyfile_size must be at least 16 bytes")
    workspace = build_hse2_quickstart_paths(base_dir)
    workspace.base_dir.mkdir(parents=True, exist_ok=True)
    _refuse_existing_outputs(workspace.paths(), overwrite=overwrite)

    workspace.sample_input.write_text(
        "HSE2 quickstart sample.\n"
        "You can replace this file with your own test file after the first run.\n",
        encoding="utf-8",
    )
    workspace.keyfile.write_bytes(secrets.token_bytes(keyfile_size))
    wrapper = {"type": "keyfile", "path": str(workspace.keyfile)}
    _write_json(
        workspace.encrypt_config,
        {
            "input": str(workspace.sample_input),
            "output": str(workspace.encrypted_output),
            "wrapper": wrapper,
            "kdf_profile": "compatible",
            "chunk_size": DEFAULT_CHUNK_SIZE,
        },
    )
    _write_json(
        workspace.validate_config,
        {
            "items": [{"input": str(workspace.encrypted_output)}],
            "wrapper": wrapper,
            "continue_on_error": True,
        },
    )
    _write_json(
        workspace.decrypt_config,
        {
            "input": str(workspace.encrypted_output),
            "output": str(workspace.restored_output),
            "wrapper": wrapper,
        },
    )
    workspace.command_notes.write_text(build_hse2_quickstart_commands(workspace), encoding="utf-8")
    return workspace


def build_hse2_quickstart_commands(workspace: HSE2QuickstartWorkspace) -> str:
    """Return copyable commands for the generated quickstart workspace."""

    lines = [
        "HSE2 quickstart commands",
        "========================",
        "",
        "1. Encrypt the sample file:",
        f"high-security-encryptor hse2-encrypt-config --config {_quote_path(workspace.encrypt_config)}",
        "",
        "2. Validate the container:",
        f"high-security-encryptor hse2-validate --config {_quote_path(workspace.validate_config)} --output {_quote_path(workspace.validation_report)}",
        "",
        "3. Decrypt the container:",
        f"high-security-encryptor hse2-decrypt-config --config {_quote_path(workspace.decrypt_config)}",
        "",
        "Optional Windows-only DPAPI local protection command:",
        f"high-security-encryptor dpapi-protect --input {_quote_path(workspace.keyfile)} --output {_quote_path(workspace.keyfile.with_suffix(workspace.keyfile.suffix + '.dpapi'))} --scope current_user",
        "",
        "Notes:",
        "- Keep wrapper.key with the .hse2 file; losing it means the sample cannot be opened.",
        "- The DPAPI command is optional and binds the produced blob to the selected Windows scope.",
        "- Do not paste keyfile bytes into chat, issue trackers, or logs.",
    ]
    return "\n".join(lines) + "\n"


def _refuse_existing_outputs(paths: tuple[Path, ...], *, overwrite: bool) -> None:
    if overwrite:
        return
    existing = [path for path in paths if path.exists()]
    if existing:
        rendered = ", ".join(str(path) for path in existing)
        raise FileExistsError(f"quickstart output already exists: {rendered}")


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _quote_path(path: Path) -> str:
    text = str(path)
    if not text:
        return '""'
    if any(ch.isspace() for ch in text):
        return '"' + text.replace('"', '\\"') + '"'
    return text
