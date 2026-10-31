"""HSE2 wrapper management and explicit access destruction workflows."""

from __future__ import annotations

from dataclasses import dataclass, replace
from io import BytesIO
import os
from pathlib import Path
from typing import Any

from ..atomic_io import atomic_output_path, flush_file
from .container_codec import (
    HSE2_MAGIC,
    HSE2_PREAMBLE_SIZE,
    HSE2_PREAMBLE_STRUCT,
    decode_header_frame,
    encode_header_frame,
)
from .container_stream import read_v3_header_frame, write_v3_header_frame
from .header_auth import attach_header_auth_tag, require_valid_header_auth_tag
from .keys import HSE2KeyMaterial
from .models import HSE2Header, HSE2ModelError, WrapperRecord
from .unlock import HSE2UnlockFactors, unlock_first_matching_wrapper
from .wrapper_builders import (
    BuiltWrapper,
    build_dpapi_wrapper,
    build_keyfile_wrapper,
    build_password_keyfile_wrapper,
    build_password_wrapper,
)

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
    format_version: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-wrapper list",
            "experimental": True,
            "input_path": self.input_path,
            "access_destroyed": self.access_destroyed,
            "wrapper_count": len(self.wrappers),
            "format_version": self.format_version,
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
class HSE2WrapperRewrapResult:
    """Summary returned after atomically replacing one unlock wrapper."""

    input_path: str
    output_path: str
    replaced_wrapper_id: str
    new_wrapper_id: str
    unlocked_wrapper_type: str
    original_wrapper_count: int
    resulting_wrapper_count: int
    format_version: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-wrapper rewrap",
            "experimental": True,
            "container_written": True,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "replaced_wrapper_id": self.replaced_wrapper_id,
            "new_wrapper_id": self.new_wrapper_id,
            "unlocked_wrapper_type": self.unlocked_wrapper_type,
            "original_wrapper_count": self.original_wrapper_count,
            "resulting_wrapper_count": self.resulting_wrapper_count,
            "format_version": self.format_version,
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


def list_hse2_wrappers(input_path: str | os.PathLike[str]) -> HSE2WrapperListResult:
    """Return safe metadata for all wrappers in an HSE2 container."""

    path = Path(input_path)
    header, _body_offset = _read_header_only(path)
    return HSE2WrapperListResult(
        input_path=str(path),
        access_destroyed=header.access_destroyed,
        wrappers=tuple(_summarize_wrapper(wrapper) for wrapper in header.wrappers),
        format_version=header.format_version,
    )


def add_hse2_wrapper(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    wrapper_id: str,
    new_password: str | None = None,
    new_keyfile_bytes: bytes | None = None,
    unlock_password: str | None = None,
    unlock_keyfile_bytes: bytes | None = None,
    allow_dpapi: bool = False,
    new_wrapper_dpapi: bool = False,
    profile_name: str = "hardened",
    label: str | None = None,
    created_utc: str | None = None,
    overwrite: bool = False,
) -> Path:
    """Add a wrapper while preserving the encrypted body byte for byte."""

    if not wrapper_id:
        raise HSE2ModelError("wrapper id must not be empty")
    _validate_new_wrapper_material(new_password, new_keyfile_bytes, new_wrapper_dpapi)
    if not unlock_password and unlock_keyfile_bytes is None and not allow_dpapi:
        raise HSE2ModelError("wrapper add requires unlock material")

    source = Path(input_path)
    target = Path(output_path)
    header, body_offset = _read_header_only(source)
    if header.access_destroyed:
        raise HSE2ModelError("cannot add wrappers to an access-destroyed HSE2 container")
    if any(wrapper.id == wrapper_id for wrapper in header.wrappers):
        raise HSE2ModelError(f"wrapper id already exists: {wrapper_id}")
    factors = HSE2UnlockFactors(
        password=unlock_password,
        keyfile_bytes=unlock_keyfile_bytes,
        allow_dpapi=allow_dpapi,
    )
    unlocked = unlock_first_matching_wrapper(header.wrappers, factors=factors)
    require_valid_header_auth_tag(header, mek=unlocked.mek)
    built = _build_new_wrapper(
        wrapper_id=wrapper_id, created_utc=created_utc or header.created_utc,
        password=new_password, keyfile_bytes=new_keyfile_bytes, use_dpapi=new_wrapper_dpapi,
        profile_name=profile_name, label=label, dek=unlocked.dek, mek=unlocked.mek,
    )
    new_header = replace(
        header,
        wrappers=header.wrappers + (built.record,),
        header_auth_tag=None,
    )
    new_header = attach_header_auth_tag(new_header, mek=unlocked.mek)
    _rewrite_header_preserving_body(source, target, new_header, body_offset=body_offset, overwrite=overwrite)
    return target


def rewrap_hse2_wrapper(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    replaced_wrapper_id: str,
    new_wrapper_id: str,
    new_password: str | None = None,
    new_keyfile_bytes: bytes | None = None,
    unlock_password: str | None = None,
    unlock_keyfile_bytes: bytes | None = None,
    allow_dpapi: bool = False,
    new_wrapper_dpapi: bool = False,
    profile_name: str = "hardened",
    label: str | None = None,
    created_utc: str | None = None,
    overwrite: bool = False,
) -> HSE2WrapperRewrapResult:
    """Replace one wrapper in a single header rewrite without touching body bytes."""

    if not replaced_wrapper_id or not new_wrapper_id:
        raise HSE2ModelError("old and new wrapper ids must not be empty")
    _validate_new_wrapper_material(new_password, new_keyfile_bytes, new_wrapper_dpapi)
    if not unlock_password and unlock_keyfile_bytes is None and not allow_dpapi:
        raise HSE2ModelError("wrapper rewrap requires unlock material")

    source = Path(input_path)
    target = Path(output_path)
    header, body_offset = _read_header_only(source)
    if header.access_destroyed:
        raise HSE2ModelError("cannot rewrap an access-destroyed HSE2 container")
    original_count = len(header.wrappers)
    if not any(wrapper.id == replaced_wrapper_id for wrapper in header.wrappers):
        raise HSE2ModelError(f"wrapper not found: {replaced_wrapper_id}")

    unlocked = unlock_first_matching_wrapper(
        header.wrappers,
        factors=HSE2UnlockFactors(
            password=unlock_password,
            keyfile_bytes=unlock_keyfile_bytes,
            allow_dpapi=allow_dpapi,
        ),
    )
    require_valid_header_auth_tag(header, mek=unlocked.mek)

    remaining = tuple(wrapper for wrapper in header.wrappers if wrapper.id != replaced_wrapper_id)
    if any(wrapper.id == new_wrapper_id for wrapper in remaining):
        raise HSE2ModelError(f"new wrapper id already exists: {new_wrapper_id}")
    built = _build_new_wrapper(
        wrapper_id=new_wrapper_id,
        created_utc=created_utc or header.created_utc,
        password=new_password,
        keyfile_bytes=new_keyfile_bytes,
        use_dpapi=new_wrapper_dpapi,
        profile_name=profile_name,
        label=label,
        dek=unlocked.dek,
        mek=unlocked.mek,
    )
    new_header = replace(
        header,
        wrappers=remaining + (built.record,),
        access_destroyed=False,
        header_auth_tag=None,
    )
    new_header = attach_header_auth_tag(new_header, mek=unlocked.mek)
    _rewrite_header_preserving_body(source, target, new_header, body_offset=body_offset, overwrite=overwrite)
    return HSE2WrapperRewrapResult(
        input_path=str(source),
        output_path=str(target),
        replaced_wrapper_id=replaced_wrapper_id,
        new_wrapper_id=new_wrapper_id,
        unlocked_wrapper_type=unlocked.wrapper.type,
        original_wrapper_count=original_count,
        resulting_wrapper_count=len(new_header.wrappers),
        format_version=header.format_version,
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
    header, body_offset = _read_header_only(input_target)
    if header.access_destroyed:
        raise HSE2ModelError("cannot remove wrappers from an access-destroyed HSE2 container")

    factors = HSE2UnlockFactors(password=password, keyfile_bytes=keyfile_bytes, allow_dpapi=allow_dpapi)
    unlocked = unlock_first_matching_wrapper(header.wrappers, factors=factors)
    require_valid_header_auth_tag(header, mek=unlocked.mek)

    original_count = len(header.wrappers)
    remaining_wrappers = tuple(wrapper for wrapper in header.wrappers if wrapper.id != wrapper_id)
    if len(remaining_wrappers) == original_count:
        raise HSE2ModelError(f"wrapper not found: {wrapper_id}")
    if not remaining_wrappers:
        raise HSE2ModelError("cannot remove the last wrapper; use hse2-access destroy for explicit access destruction")

    new_header = replace(header, wrappers=remaining_wrappers, access_destroyed=False, header_auth_tag=None)
    new_header = attach_header_auth_tag(new_header, mek=unlocked.mek)
    _rewrite_header_preserving_body(input_target, output_target, new_header, body_offset=body_offset, overwrite=overwrite)
    return HSE2WrapperRemoveResult(
        input_path=str(input_target),
        output_path=str(output_target),
        removed_wrapper_id=wrapper_id,
        unlocked_wrapper_type=unlocked.wrapper.type,
        original_wrapper_count=original_count,
        remaining_wrapper_count=len(remaining_wrappers),
    )


def destroy_hse2_access(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    confirmation_phrase: str,
    password: str | None = None,
    keyfile_bytes: bytes | None = None,
    allow_dpapi: bool = False,
    overwrite: bool = False,
) -> HSE2AccessDestroyResult:
    """Write a copy of an HSE2 container with all unlock wrappers removed."""

    if confirmation_phrase != DESTROY_ACCESS_CONFIRMATION_PHRASE:
        raise HSE2ModelError("destroy access confirmation phrase did not match")

    input_target = Path(input_path)
    output_target = Path(output_path)
    header, body_offset = _read_header_only(input_target)
    removed_count = len(header.wrappers)
    unlocked = None
    if header.format_version == 3:
        if not password and keyfile_bytes is None and not allow_dpapi:
            raise HSE2ModelError("v3 access destruction requires unlock material to authenticate the new header")
        unlocked = unlock_first_matching_wrapper(
            header.wrappers,
            factors=HSE2UnlockFactors(password=password, keyfile_bytes=keyfile_bytes, allow_dpapi=allow_dpapi),
        )
        require_valid_header_auth_tag(header, mek=unlocked.mek)
    new_header = replace(
        header,
        wrappers=tuple(),
        access_destroyed=True,
        header_auth_tag=None,
    )
    if unlocked is not None:
        new_header = attach_header_auth_tag(new_header, mek=unlocked.mek)
    _rewrite_header_preserving_body(input_target, output_target, new_header, body_offset=body_offset, overwrite=overwrite)
    return HSE2AccessDestroyResult(
        input_path=str(input_target),
        output_path=str(output_target),
        removed_wrapper_count=removed_count,
        access_destroyed=True,
    )


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


def _validate_new_wrapper_material(
    password: str | None,
    keyfile_bytes: bytes | None,
    use_dpapi: bool,
) -> None:
    if use_dpapi and (password or keyfile_bytes is not None):
        raise HSE2ModelError("DPAPI wrapper cannot be combined with password or keyfile material")
    if not use_dpapi and not password and keyfile_bytes is None:
        raise HSE2ModelError("new wrapper requires password, keyfile, or DPAPI material")


def _build_new_wrapper(
    *,
    wrapper_id: str,
    created_utc: str,
    password: str | None,
    keyfile_bytes: bytes | None,
    use_dpapi: bool,
    profile_name: str,
    label: str | None,
    dek: HSE2KeyMaterial,
    mek: HSE2KeyMaterial,
) -> BuiltWrapper:
    if use_dpapi:
        return build_dpapi_wrapper(
            wrapper_id=wrapper_id, created_utc=created_utc, dek=dek, mek=mek, label=label,
        )
    if password and keyfile_bytes is not None:
        return build_password_keyfile_wrapper(
            wrapper_id=wrapper_id, created_utc=created_utc, password=password,
            keyfile_bytes=keyfile_bytes, profile_name=profile_name, dek=dek, mek=mek, label=label,
        )
    if password:
        return build_password_wrapper(
            wrapper_id=wrapper_id, created_utc=created_utc, password=password,
            profile_name=profile_name, dek=dek, mek=mek, label=label,
        )
    return build_keyfile_wrapper(
        wrapper_id=wrapper_id, created_utc=created_utc, keyfile_bytes=keyfile_bytes or b"",
        dek=dek, mek=mek, label=label,
    )


def _read_header_only(path: Path) -> tuple[HSE2Header, int]:
    try:
        with path.open("rb") as stream:
            preamble_bytes = stream.read(HSE2_PREAMBLE_SIZE)
            if len(preamble_bytes) != HSE2_PREAMBLE_SIZE:
                raise HSE2ModelError("HSE2 preamble is truncated")
            magic, version, _encoding, _reserved, header_length = HSE2_PREAMBLE_STRUCT.unpack(preamble_bytes)
            if magic != HSE2_MAGIC:
                raise HSE2ModelError("invalid HSE2 magic")
            stream.seek(0)
            if version == 3:
                _frame, header = read_v3_header_frame(stream)
            elif version == 2:
                header_bytes = stream.read(HSE2_PREAMBLE_SIZE + header_length)
                _preamble, header, _trailing = decode_header_frame(header_bytes)
                stream.seek(HSE2_PREAMBLE_SIZE + header_length)
            else:
                raise HSE2ModelError(f"unsupported HSE2 container version: {version}")
            return header, stream.tell()
    except OSError as exc:
        raise HSE2ModelError(f"cannot read HSE2 header: {path}") from exc


def _rewrite_header_preserving_body(
    source: Path,
    target: Path,
    header: HSE2Header,
    *,
    body_offset: int,
    overwrite: bool,
) -> None:
    if target.exists() and not overwrite:
        raise HSE2ModelError(f"target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with atomic_output_path(target) as temp_path:
        with temp_path.open("wb") as dst:
            with source.open("rb") as src:
                src.seek(body_offset)
                if header.format_version == 3:
                    write_v3_header_frame(dst, header)
                else:
                    dst.write(encode_header_frame(header))
                body_size = 0
                while True:
                    block = src.read(128 * 1024)
                    if not block:
                        break
                    dst.write(block)
                    body_size += len(block)
                if body_size == 0:
                    raise HSE2ModelError("container body is missing")
            flush_file(dst)
