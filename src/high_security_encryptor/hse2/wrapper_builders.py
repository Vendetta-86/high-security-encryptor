"""Pure wrapper construction helpers for HSE2.

This module combines existing KEK derivation helpers with DEK/MEK wrapping. It
performs no file I/O, no CLI handling, and no GUI work.
"""

from __future__ import annotations

from dataclasses import dataclass

from .combined_kdf import derive_kek_from_password_and_keyfile
from .keyfile_kdf import derive_kek_from_keyfile
from .keys import HSE2KeyMaterial
from .models import WrapperRecord
from .password_kdf import derive_kek_from_password
from .wrapper_serialization import WrappedKeyPairBlobs, build_wrapper_record
from .wrapping import key_confirmation_tag, wrap_key_material


@dataclass(frozen=True)
class BuiltWrapper:
    """A generated wrapper record and its non-secret metadata."""

    record: WrapperRecord
    kdf_metadata: dict[str, object] | None


def build_wrapper_from_kek(
    *,
    wrapper_id: str,
    wrapper_type: str,
    created_utc: str,
    dek: HSE2KeyMaterial,
    mek: HSE2KeyMaterial,
    kek: HSE2KeyMaterial,
    label: str | None = None,
    kdf_metadata: dict[str, object] | None = None,
) -> BuiltWrapper:
    """Build a wrapper record from an already-derived KEK."""

    wrapped_dek = wrap_key_material(dek, kek=kek)
    wrapped_mek = wrap_key_material(mek, kek=kek)
    wrapped_mek = type(wrapped_mek)(
        nonce=wrapped_dek.nonce,
        ciphertext=wrapped_mek.ciphertext,
        auth_tag=wrapped_mek.auth_tag,
    )
    record = build_wrapper_record(
        wrapper_id=wrapper_id,
        wrapper_type=wrapper_type,
        label=label,
        created_utc=created_utc,
        wrapped_blobs=WrappedKeyPairBlobs(dek=wrapped_dek, mek=wrapped_mek),
        auth_tag=key_confirmation_tag(kek=kek, context=wrapper_id.encode("utf-8"))[:16],
        kdf=kdf_metadata,
    )
    return BuiltWrapper(record=record, kdf_metadata=kdf_metadata)


def build_password_wrapper(*, wrapper_id: str, created_utc: str, password: str, dek: HSE2KeyMaterial, mek: HSE2KeyMaterial, profile_name: str = "hardened", salt: bytes | None = None, label: str | None = None) -> BuiltWrapper:
    result = derive_kek_from_password(password, profile_name=profile_name, salt=salt)
    return build_wrapper_from_kek(wrapper_id=wrapper_id, wrapper_type="password", created_utc=created_utc, dek=dek, mek=mek, kek=result.kek, label=label, kdf_metadata=result.kdf_metadata())


def build_keyfile_wrapper(*, wrapper_id: str, created_utc: str, keyfile_bytes: bytes, dek: HSE2KeyMaterial, mek: HSE2KeyMaterial, label: str | None = None) -> BuiltWrapper:
    result = derive_kek_from_keyfile(keyfile_bytes)
    return build_wrapper_from_kek(wrapper_id=wrapper_id, wrapper_type="keyfile", created_utc=created_utc, dek=dek, mek=mek, kek=result.kek, label=label, kdf_metadata=result.metadata())


def build_password_keyfile_wrapper(*, wrapper_id: str, created_utc: str, password: str, keyfile_bytes: bytes, dek: HSE2KeyMaterial, mek: HSE2KeyMaterial, profile_name: str = "hardened", salt: bytes | None = None, label: str | None = None) -> BuiltWrapper:
    result = derive_kek_from_password_and_keyfile(password, keyfile_bytes, profile_name=profile_name, salt=salt)
    return build_wrapper_from_kek(wrapper_id=wrapper_id, wrapper_type="password_keyfile", created_utc=created_utc, dek=dek, mek=mek, kek=result.kek, label=label, kdf_metadata=result.kdf_metadata())
