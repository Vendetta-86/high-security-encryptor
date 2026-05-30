"""Wrapper unlock orchestration for HSE2.

This module dispatches already-collected user factors to the provider-specific
wrapper unwrapping helpers. It does not prompt users, read keyfile paths, perform
CLI/GUI work, or decrypt manifests/payload chunks.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import HSE2ModelError, WrapperRecord
from .wrapper_builders import (
    UnwrappedContentKeys,
    unwrap_dpapi_wrapper,
    unwrap_keyfile_wrapper,
    unwrap_password_keyfile_wrapper,
    unwrap_password_wrapper,
)


@dataclass(frozen=True)
class HSE2UnlockFactors:
    """Already-collected unlock factors for wrapper orchestration."""

    password: str | None = None
    keyfile_bytes: bytes | None = None
    allow_dpapi: bool = True


def unlock_wrapper(record: WrapperRecord, *, factors: HSE2UnlockFactors) -> UnwrappedContentKeys:
    """Unlock one wrapper record with the supplied factors."""

    if record.type == "password":
        if factors.password is None:
            raise HSE2ModelError("password wrapper requires password factor")
        return unwrap_password_wrapper(record, password=factors.password)

    if record.type == "keyfile":
        if factors.keyfile_bytes is None:
            raise HSE2ModelError("keyfile wrapper requires keyfile bytes factor")
        return unwrap_keyfile_wrapper(record, keyfile_bytes=factors.keyfile_bytes)

    if record.type == "password_keyfile":
        if factors.password is None:
            raise HSE2ModelError("password_keyfile wrapper requires password factor")
        if factors.keyfile_bytes is None:
            raise HSE2ModelError("password_keyfile wrapper requires keyfile bytes factor")
        return unwrap_password_keyfile_wrapper(record, password=factors.password, keyfile_bytes=factors.keyfile_bytes)

    if record.type == "dpapi":
        if not factors.allow_dpapi:
            raise HSE2ModelError("DPAPI wrapper unlock is disabled")
        return unwrap_dpapi_wrapper(record)

    raise HSE2ModelError(f"unsupported wrapper type: {record.type}")


def unlock_first_matching_wrapper(
    records: tuple[WrapperRecord, ...],
    *,
    factors: HSE2UnlockFactors,
) -> UnwrappedContentKeys:
    """Unlock the first wrapper compatible with the supplied factors."""

    errors: list[str] = []
    for record in records:
        if not _factors_can_attempt(record, factors):
            continue
        try:
            return unlock_wrapper(record, factors=factors)
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
