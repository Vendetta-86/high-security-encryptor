"""Pure wrapper construction helpers for HSE2.

This module combines existing KEK derivation helpers with DEK/MEK wrapping. It
performs no file I/O, no CLI handling, and no GUI work.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from Crypto.Cipher import AES

from .combined_kdf import derive_kek_from_password_and_keyfile
from .encoding import b64decode_bytes
from .keyfile_kdf import derive_kek_from_keyfile
from .keys import HSE2_KEY_SIZE, HSE2KeyMaterial
from .models import HSE2ModelError, WrapperRecord
from .password_kdf import derive_kek_from_password
from .wrapper_serialization import WrappedKeyPairBlobs, build_wrapper_record
from .wrapping import HSE2_WRAP_NONCE_SIZE, WrappedKeyBlob


@dataclass(frozen=True)
class BuiltWrapper:
    """A generated wrapper record and its non-secret metadata."""

    record: WrapperRecord
    kdf_metadata: dict[str, object] | None


@dataclass(frozen=True)
class UnwrappedContentKeys:
    """DEK and MEK recovered from one wrapper record."""

    dek: HSE2KeyMaterial
    mek: HSE2KeyMaterial


def _wrapper_aad(wrapper_type: str) -> bytes:
    return f"HSE2:wrapper-record:{wrapper_type}".encode("ascii")


def _wrap_dek_mek_together(
    *,
    dek: HSE2KeyMaterial,
    mek: HSE2KeyMaterial,
    kek: HSE2KeyMaterial,
    wrapper_type: str,
) -> tuple[WrappedKeyPairBlobs, bytes]:
    """Wrap DEK and MEK in one AES-GCM operation.

    A single wrapper record has one nonce and one authentication tag, so the two
    content keys are encrypted as one 64-byte plaintext and then split into DEK
    and MEK ciphertext fields for the JSON header model.
    """

    if dek.purpose != "DEK":
        raise HSE2ModelError("wrapper construction requires a DEK")
    if mek.purpose != "MEK":
        raise HSE2ModelError("wrapper construction requires a MEK")
    if kek.purpose != "KEK":
        raise HSE2ModelError("wrapper construction requires a KEK")

    nonce = secrets.token_bytes(HSE2_WRAP_NONCE_SIZE)
    cipher = AES.new(kek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_wrapper_aad(wrapper_type))
    ciphertext, auth_tag = cipher.encrypt_and_digest(dek.as_bytes() + mek.as_bytes())
    if len(ciphertext) != HSE2_KEY_SIZE * 2:
        raise HSE2ModelError("combined wrapped key ciphertext has invalid length")

    wrapped_dek = WrappedKeyBlob(
        nonce=nonce,
        ciphertext=ciphertext[:HSE2_KEY_SIZE],
        auth_tag=auth_tag,
    )
    wrapped_mek = WrappedKeyBlob(
        nonce=nonce,
        ciphertext=ciphertext[HSE2_KEY_SIZE:],
        auth_tag=auth_tag,
    )
    return WrappedKeyPairBlobs(dek=wrapped_dek, mek=wrapped_mek), auth_tag


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

    wrapped_blobs, auth_tag = _wrap_dek_mek_together(
        dek=dek,
        mek=mek,
        kek=kek,
        wrapper_type=wrapper_type,
    )
    record = build_wrapper_record(
        wrapper_id=wrapper_id,
        wrapper_type=wrapper_type,
        label=label,
        created_utc=created_utc,
        wrapped_blobs=wrapped_blobs,
        auth_tag=auth_tag,
        kdf=kdf_metadata,
    )
    return BuiltWrapper(record=record, kdf_metadata=kdf_metadata)


def unwrap_wrapper_with_kek(record: WrapperRecord, *, kek: HSE2KeyMaterial) -> UnwrappedContentKeys:
    """Recover DEK and MEK from a wrapper record using an already-derived KEK."""

    if kek.purpose != "KEK":
        raise HSE2ModelError("wrapper unwrapping requires a KEK")
    nonce = b64decode_bytes(record.nonce, field_name="wrapper nonce")
    dek_ciphertext = b64decode_bytes(record.wrapped_keys.dek, field_name="wrapped DEK")
    mek_ciphertext = b64decode_bytes(record.wrapped_keys.mek, field_name="wrapped MEK")
    auth_tag = b64decode_bytes(record.auth_tag, field_name="wrapper auth_tag")
    ciphertext = dek_ciphertext + mek_ciphertext
    if len(ciphertext) != HSE2_KEY_SIZE * 2:
        raise HSE2ModelError("combined wrapped key ciphertext has invalid length")

    cipher = AES.new(kek.as_bytes(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_wrapper_aad(record.type))
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
    except ValueError as exc:
        raise HSE2ModelError("wrapper authentication failed") from exc
    if len(plaintext) != HSE2_KEY_SIZE * 2:
        raise HSE2ModelError("unwrapped content key material has invalid length")
    return UnwrappedContentKeys(
        dek=HSE2KeyMaterial(purpose="DEK", value=plaintext[:HSE2_KEY_SIZE]),
        mek=HSE2KeyMaterial(purpose="MEK", value=plaintext[HSE2_KEY_SIZE:]),
    )


def build_password_wrapper(*, wrapper_id: str, created_utc: str, password: str, dek: HSE2KeyMaterial, mek: HSE2KeyMaterial, profile_name: str = "hardened", salt: bytes | None = None, label: str | None = None) -> BuiltWrapper:
    result = derive_kek_from_password(password, profile_name=profile_name, salt=salt)
    return build_wrapper_from_kek(wrapper_id=wrapper_id, wrapper_type="password", created_utc=created_utc, dek=dek, mek=mek, kek=result.kek, label=label, kdf_metadata=result.kdf_metadata())


def build_keyfile_wrapper(*, wrapper_id: str, created_utc: str, keyfile_bytes: bytes, dek: HSE2KeyMaterial, mek: HSE2KeyMaterial, label: str | None = None) -> BuiltWrapper:
    result = derive_kek_from_keyfile(keyfile_bytes)
    return build_wrapper_from_kek(wrapper_id=wrapper_id, wrapper_type="keyfile", created_utc=created_utc, dek=dek, mek=mek, kek=result.kek, label=label, kdf_metadata=result.metadata())


def build_password_keyfile_wrapper(*, wrapper_id: str, created_utc: str, password: str, keyfile_bytes: bytes, dek: HSE2KeyMaterial, mek: HSE2KeyMaterial, profile_name: str = "hardened", salt: bytes | None = None, label: str | None = None) -> BuiltWrapper:
    result = derive_kek_from_password_and_keyfile(password, keyfile_bytes, profile_name=profile_name, salt=salt)
    return build_wrapper_from_kek(wrapper_id=wrapper_id, wrapper_type="password_keyfile", created_utc=created_utc, dek=dek, mek=mek, kek=result.kek, label=label, kdf_metadata=result.kdf_metadata())
