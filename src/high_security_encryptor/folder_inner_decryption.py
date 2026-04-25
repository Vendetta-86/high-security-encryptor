"""Decryption helpers for encrypted members inside folder packages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .api import decrypt_file_streaming
from .batch_artifacts import load_password_table_artifact
from .batch_binding import BatchBinding
from .folder_package_utils import normalize_safe_relative_member_path
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
    root_resolved = root_path.resolve()
    overrides = {
        normalize_safe_relative_member_path(path, "inner password override path"): password
        for path, password in (inner_password_overrides or {}).items()
    }
    results: list[InnerFileDecryptionResult] = []

    for record in password_table_payload.get("records", []):
        encrypted_relative_path = _normalize_encrypted_member_name(str(record["encrypted_name"]))
        encrypted_path = _resolve_inside_root(root_path, root_resolved, encrypted_relative_path)
        decrypted_relative_path = _remove_trailing_hse_suffix(encrypted_relative_path)
        decrypted_path = _resolve_inside_root(root_path, root_resolved, decrypted_relative_path)
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
    expected_encrypted_names: list[str] | None = None,
) -> dict:
    """Load or build the password payload used to decrypt inner package members."""

    if password_table_path is not None:
        payload = load_password_table_artifact(
            password_table_path,
            metadata_password,
            discovered_binding,
        )
        _validate_password_payload_records(payload, expected_encrypted_names)
        return payload
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
    template_encrypted_names = [
        _normalize_encrypted_member_name(str(row["encrypted_name"]))
        for row in template_payload.get("rows", [])
    ]
    if expected_encrypted_names is not None:
        _validate_name_set(template_encrypted_names, expected_encrypted_names, "internal template")
    missing_passwords = [name for name in template_encrypted_names if name not in resolved_passwords]
    if missing_passwords:
        raise KeyError(
            "missing runtime passwords for internal encrypted members: "
            + ", ".join(sorted(missing_passwords))
        )
    payload = {
        "kind": "password_table",
        "records": [
            {
                "source_name": normalize_safe_relative_member_path(str(row["source_name"]), "internal source name"),
                "encrypted_name": _normalize_encrypted_member_name(str(row["encrypted_name"])),
                "password": resolved_passwords[_normalize_encrypted_member_name(str(row["encrypted_name"]))],
            }
            for row in template_payload.get("rows", [])
            if _normalize_encrypted_member_name(str(row["encrypted_name"])) in resolved_passwords
        ],
        "binding": discovered_binding.as_dict(),
    }
    _validate_password_payload_records(payload, expected_encrypted_names)
    return payload


def _remove_trailing_hse_suffix(relative_path: str) -> str:
    """Remove the final `.hse` suffix from a relative member path."""

    pure_path = PurePosixPath(relative_path)
    if pure_path.suffix != ".hse":
        raise ValueError(f"expected .hse member path, got: {relative_path}")
    return str(pure_path.with_suffix(""))


def _normalize_encrypted_member_name(relative_path: str) -> str:
    normalized = normalize_safe_relative_member_path(relative_path, "internal encrypted member")
    if PurePosixPath(normalized).suffix != ".hse":
        raise ValueError(f"expected .hse member path, got: {relative_path}")
    return normalized


def _resolve_inside_root(root_path: Path, root_resolved: Path, relative_path: str) -> Path:
    target = root_path / Path(*PurePosixPath(relative_path).parts)
    try:
        target.resolve().relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"internal member escapes extracted root: {relative_path}") from exc
    return target


def _validate_password_payload_records(payload: dict, expected_encrypted_names: list[str] | None) -> None:
    encrypted_names: list[str] = []
    for record in payload.get("records", []):
        normalize_safe_relative_member_path(str(record["source_name"]), "internal source name")
        encrypted_names.append(_normalize_encrypted_member_name(str(record["encrypted_name"])))
        if not str(record.get("password", "")):
            raise ValueError(f"empty password for internal encrypted member: {record.get('encrypted_name')}")
    if len(encrypted_names) != len(set(encrypted_names)):
        raise ValueError("internal password table contains duplicate encrypted members")
    if expected_encrypted_names is not None:
        _validate_name_set(encrypted_names, expected_encrypted_names, "internal password table")


def _validate_name_set(actual_names: list[str], expected_names: list[str], context: str) -> None:
    normalized_actual = sorted(_normalize_encrypted_member_name(name) for name in actual_names)
    normalized_expected = sorted(_normalize_encrypted_member_name(name) for name in expected_names)
    if normalized_actual != normalized_expected:
        raise ValueError(f"{context} encrypted member set does not match manifest")
