"""Decryption helpers for encrypted members inside folder packages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .api import decrypt_file_streaming
from .batch_artifacts import load_password_table_artifact
from .batch_binding import BatchBinding
from .folder_workflow import INTERNAL_SIDECAR_DIRNAME
from .password_sources import PasswordResolver
from .runtime_password_plan import RuntimePasswordPlan, resolve_password_plan_from_template


@dataclass(frozen=True)
class InnerFileDecryptionResult:
    """Describes one inner package member decrypted after extraction."""

    encrypted_relative_path: str
    decrypted_relative_path: str
    decrypted_path: Path


def discover_internal_sidecars(extracted_root: str | Path) -> tuple[Path | None, Path | None, Path | None]:
    """Find internal sidecar files in an extracted folder package."""

    root_path = Path(extracted_root)
    sidecar_root = root_path / INTERNAL_SIDECAR_DIRNAME
    if not sidecar_root.is_dir():
        return None, None, None
    manifest_path = sidecar_root / "batch_manifest.hsm"
    password_table_path = sidecar_root / "batch_password_table.hsm"
    template_path = sidecar_root / "batch_template.hsm"
    return (
        manifest_path if manifest_path.is_file() else None,
        password_table_path if password_table_path.is_file() else None,
        template_path if template_path.is_file() else None,
    )


def decrypt_inner_hse_members(
    extracted_root: str | Path,
    password_table_payload: dict,
    inner_password_overrides: dict[str, str] | None = None,
) -> list[InnerFileDecryptionResult]:
    """Decrypt `.hse` members listed in an internal password-table payload."""

    root_path = Path(extracted_root)
    overrides = {PurePosixPath(path).as_posix(): password for path, password in (inner_password_overrides or {}).items()}
    results: list[InnerFileDecryptionResult] = []

    for record in password_table_payload.get("records", []):
        encrypted_relative_path = PurePosixPath(str(record["encrypted_name"])).as_posix()
        encrypted_path = root_path / Path(*PurePosixPath(encrypted_relative_path).parts)
        decrypted_relative_path = _remove_trailing_hse_suffix(encrypted_relative_path)
        decrypted_path = root_path / Path(*PurePosixPath(decrypted_relative_path).parts)
        password = overrides.get(encrypted_relative_path, str(record["password"]))
        if decrypted_path.exists():
            raise FileExistsError(f"decrypted inner target already exists: {decrypted_relative_path}")
        decrypt_file_streaming(encrypted_path, decrypted_path, password)
        results.append(
            InnerFileDecryptionResult(
                encrypted_relative_path=encrypted_relative_path,
                decrypted_relative_path=decrypted_relative_path,
                decrypted_path=decrypted_path,
            )
        )

    return results


def load_internal_password_payload(
    password_table_path: Path | None,
    template_payload: dict | None,
    metadata_password: str,
    discovered_binding: BatchBinding,
    internal_runtime_password_plan: RuntimePasswordPlan | None,
    password_resolver: PasswordResolver | None,
) -> dict:
    """Load or build the password payload used to decrypt inner package members."""

    if password_table_path is not None:
        return load_password_table_artifact(
            password_table_path,
            metadata_password,
            discovered_binding,
        )
    if template_payload is None:
        raise FileNotFoundError("internal template is missing")
    if internal_runtime_password_plan is None:
        raise FileNotFoundError("internal password table is missing")
    if password_resolver is None:
        raise ValueError("password_resolver is required when internal_runtime_password_plan is used")
    resolved_passwords = resolve_password_plan_from_template(
        template_payload=template_payload,
        resolver=password_resolver,
        plan=internal_runtime_password_plan,
    )
    expected_encrypted_names = [str(row["encrypted_name"]) for row in template_payload.get("rows", [])]
    missing_passwords = [name for name in expected_encrypted_names if name not in resolved_passwords]
    if missing_passwords:
        raise KeyError(
            "missing runtime passwords for internal encrypted members: "
            + ", ".join(sorted(missing_passwords))
        )
    return {
        "kind": "password_table",
        "records": [
            {
                "source_name": str(row["source_name"]),
                "encrypted_name": str(row["encrypted_name"]),
                "password": resolved_passwords[str(row["encrypted_name"])],
            }
            for row in template_payload.get("rows", [])
            if str(row["encrypted_name"]) in resolved_passwords
        ],
        "binding": discovered_binding.as_dict(),
    }


def _remove_trailing_hse_suffix(relative_path: str) -> str:
    """Remove the final `.hse` suffix from a relative member path."""

    pure_path = PurePosixPath(relative_path)
    if pure_path.suffix != ".hse":
        raise ValueError(f"expected .hse member path, got: {relative_path}")
    return str(pure_path.with_suffix(""))
