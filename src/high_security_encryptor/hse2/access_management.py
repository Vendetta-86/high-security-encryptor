"""HSE2 wrapper management and explicit access destruction workflows."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
from typing import Any

from .file_io import read_hse2_container, write_hse2_container
from .header_auth import attach_header_auth_tag, require_valid_header_auth_tag
from .models import HSE2ModelError, WrapperRecord
from .unlock import HSE2UnlockFactors, unlock_wrapper
from .wrapper_builders import UnwrappedContentKeys

DESTROY_ACCESS_CONFIRMATION_PHRASE = "I UNDERSTAND THIS WILL MAKE THE DATA PERMANENTLY UNRECOVERABLE"


@dataclass(frozen=True)
class HSE2WrapperSummary:
    """Safe-to-print metadata for one HSE2 wrapper record."""

    id: str
    type: str
    created_utc: str
    label: str | None
    wrap_cipher: str
    kdf_profile: str | None
    has_kdf: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "created_utc": self.created_utc,
            "label": self.label,
            "wrap_cipher": self.wrap_cipher,
            "kdf_profile": self.kdf_profile,
            "has_kdf": self.has_kdf,
        }


@dataclass(frozen=True)
class HSE2WrapperListResult:
    """Summary returned by the wrapper list workflow."""

    input_path: str
    access_destroyed: bool
    wrappers: tuple[HSE2WrapperSummary, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-wrapper list",
            "experimental": True,
            "input_path": self.input_path,
            "access_destroyed": self.access_destroyed,
            "wrapper_count": len(self.wrappers),
            "wrappers": [wrapper.to_dict() for wrapper in self.wrappers],
        }


@dataclass(frozen=True)
class HSE2WrapperRemoveResult:
    """Summary returned by the wrapper remove workflow."""

    input_path: str
    output_path: str
    removed_wrapper_id: str
    unlocked_wrapper_type: str
    original_wrapper_count: int
    remaining_wrapper_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-wrapper remove",
            "experimental": True,
            "container_written": True,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "removed_wrapper_id": self.removed_wrapper_id,
            "unlocked_wrapper_type": self.unlocked_wrapper_type,
            "original_wrapper_count": self.original_wrapper_count,
            "remaining_wrapper_count": self.remaining_wrapper_count,
        }


@dataclass(frozen=True)
class HSE2AccessDestroyResult:
    """Summary returned by the access destroy workflow."""

    input_path: str
    output_path: str
    removed_wrapper_count: int
    access_destroyed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-access destroy",
            "experimental": True,
            "container_written": True,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "removed_wrapper_count": self.removed_wrapper_count,
            "access_destroyed": self.access_destroyed,
        }


@dataclass(frozen=True)
class _SelectedUnlock:
    wrapper: WrapperRecord
    keys: UnwrappedContentKeys


def list_hse2_wrappers(input_path: str | os.PathLike[str]) -> HSE2WrapperListResult:
    """Return safe metadata for all wrappers in an HSE2 container."""

    path = Path(input_path)
    container = read_hse2_container(path)
    return HSE2WrapperListResult(
        input_path=str(path),
        access_destroyed=container.header.access_destroyed,
        wrappers=tuple(_summarize_wrapper(wrapper) for wrapper in container.header.wrappers),
    )


def remove_hse2_wrapper(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    wrapper_id: str,
    password: str | None = None,
    keyfile_bytes: bytes | None = None,
    allow_dpapi: bool = False,
    overwrite: bool = False,
) -> HSE2WrapperRemoveResult:
    """Remove one wrapper after authenticating the current header with unlock material."""

    if not wrapper_id:
        raise HSE2ModelError("wrapper id must not be empty")
    if not password and keyfile_bytes is None and not allow_dpapi:
        raise HSE2ModelError("wrapper remove requires password, keyfile, or DPAPI unlock material")

    input_target = Path(input_path)
    output_target = Path(output_path)
    container = read_hse2_container(input_target)
    header = container.header
    if header.access_destroyed:
        raise HSE2ModelError("cannot remove wrappers from an access-destroyed HSE2 container")

    factors = HSE2UnlockFactors(password=password, keyfile_bytes=keyfile_bytes, allow_dpapi=allow_dpapi)
    selected = _unlock_first_matching_wrapper_with_record(header.wrappers, factors=factors)
    require_valid_header_auth_tag(header, mek=selected.keys.mek)

    original_count = len(header.wrappers)
    remaining_wrappers = tuple(wrapper for wrapper in header.wrappers if wrapper.id != wrapper_id)
    if len(remaining_wrappers) == original_count:
        raise HSE2ModelError(f"wrapper not found: {wrapper_id}")
    if not remaining_wrappers:
        raise HSE2ModelError("cannot remove the last wrapper; use hse2-access destroy for explicit access destruction")

    new_header = replace(header, wrappers=remaining_wrappers, access_destroyed=False, header_auth_tag=None)
    new_header = attach_header_auth_tag(new_header, mek=selected.keys.mek)
    write_hse2_container(
        output_target,
        header=new_header,
        manifest=container.manifest,
        payload_chunks=container.payload_chunks,
        overwrite=overwrite,
    )
    return HSE2WrapperRemoveResult(
        input_path=str(input_target),
        output_path=str(output_target),
        removed_wrapper_id=wrapper_id,
        unlocked_wrapper_type=selected.wrapper.type,
        original_wrapper_count=original_count,
        remaining_wrapper_count=len(remaining_wrappers),
    )


def destroy_hse2_access(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    confirmation_phrase: str,
    overwrite: bool = False,
) -> HSE2AccessDestroyResult:
    """Write a copy of an HSE2 container with all unlock wrappers removed."""

    if confirmation_phrase != DESTROY_ACCESS_CONFIRMATION_PHRASE:
        raise HSE2ModelError("destroy access confirmation phrase did not match")

    input_target = Path(input_path)
    output_target = Path(output_path)
    container = read_hse2_container(input_target)
    removed_count = len(container.header.wrappers)
    new_header = replace(
        container.header,
        wrappers=tuple(),
        access_destroyed=True,
        header_auth_tag=None,
    )
    write_hse2_container(
        output_target,
        header=new_header,
        manifest=container.manifest,
        payload_chunks=container.payload_chunks,
        overwrite=overwrite,
    )
    return HSE2AccessDestroyResult(
        input_path=str(input_target),
        output_path=str(output_target),
        removed_wrapper_count=removed_count,
        access_destroyed=True,
    )


def _unlock_first_matching_wrapper_with_record(
    records: tuple[WrapperRecord, ...],
    *,
    factors: HSE2UnlockFactors,
) -> _SelectedUnlock:
    errors: list[str] = []
    for record in records:
        if not _factors_can_attempt(record, factors):
            continue
        try:
            return _SelectedUnlock(wrapper=record, keys=unlock_wrapper(record, factors=factors))
        except HSE2ModelError as exc:
            errors.append(str(exc))
    if errors:
        raise HSE2ModelError("no wrapper could be unlocked with supplied factors")
    raise HSE2ModelError("no wrapper is compatible with supplied factors")


def _factors_can_attempt(record: WrapperRecord, factors: HSE2UnlockFactors) -> bool:
    if record.type == "password":
        return factors.password is not None
    if record.type == "keyfile":
        return factors.keyfile_bytes is not None
    if record.type == "password_keyfile":
        return factors.password is not None and factors.keyfile_bytes is not None
    if record.type == "dpapi":
        return factors.allow_dpapi
    return False


def _summarize_wrapper(wrapper: WrapperRecord) -> HSE2WrapperSummary:
    kdf_profile = None
    if isinstance(wrapper.kdf, dict) and isinstance(wrapper.kdf.get("profile"), str):
        kdf_profile = wrapper.kdf["profile"]
    return HSE2WrapperSummary(
        id=wrapper.id,
        type=wrapper.type,
        created_utc=wrapper.created_utc,
        label=wrapper.label,
        wrap_cipher=wrapper.wrap_cipher,
        kdf_profile=kdf_profile,
        has_kdf=wrapper.kdf is not None,
    )
