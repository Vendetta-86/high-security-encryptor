"""Password-derived KEK primitives for HSE2 wrappers."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from argon2.low_level import Type, hash_secret_raw

from .keys import HSE2KeyMaterial
from .models import HSE2ModelError, KDFProfile, get_kdf_profile


HSE2_KDF_SALT_SIZE = 16


@dataclass(frozen=True)
class PasswordKDFResult:
    """A password-derived KEK plus the salt and profile used to derive it."""

    kek: HSE2KeyMaterial
    profile: KDFProfile
    salt: bytes

    def __post_init__(self) -> None:
        if self.kek.purpose != "KEK":
            raise HSE2ModelError("password KDF result must contain a KEK")
        if len(self.salt) != HSE2_KDF_SALT_SIZE:
            raise HSE2ModelError(f"password KDF salt must be {HSE2_KDF_SALT_SIZE} bytes")

    def kdf_metadata(self) -> dict[str, object]:
        """Return JSON-safe KDF metadata without exposing the password or KEK."""

        import base64

        return self.profile.to_dict(salt=base64.b64encode(self.salt).decode("ascii"))


def normalize_password(password: str) -> bytes:
    """Normalize an interactive password into UTF-8 bytes for Argon2id."""

    if not isinstance(password, str):
        raise HSE2ModelError("password must be a string")
    if not password:
        raise HSE2ModelError("password must not be empty")
    return password.encode("utf-8")


def derive_kek_from_password(
    password: str,
    *,
    profile_name: str = "hardened",
    salt: bytes | None = None,
) -> PasswordKDFResult:
    """Derive a 32-byte KEK from a password using a named Argon2id profile."""

    profile = get_kdf_profile(profile_name)
    password_bytes = normalize_password(password)
    actual_salt = salt if salt is not None else secrets.token_bytes(HSE2_KDF_SALT_SIZE)
    if not isinstance(actual_salt, bytes):
        raise HSE2ModelError("password KDF salt must be bytes")
    if len(actual_salt) != HSE2_KDF_SALT_SIZE:
        raise HSE2ModelError(f"password KDF salt must be {HSE2_KDF_SALT_SIZE} bytes")

    raw = hash_secret_raw(
        secret=password_bytes,
        salt=actual_salt,
        time_cost=profile.time_cost,
        memory_cost=profile.memory_cost_kib,
        parallelism=profile.parallelism,
        hash_len=profile.hash_len,
        type=Type.ID,
    )
    return PasswordKDFResult(kek=HSE2KeyMaterial(purpose="KEK", value=raw), profile=profile, salt=actual_salt)
