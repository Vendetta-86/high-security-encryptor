"""Combined password + keyfile KEK primitives for HSE2 wrappers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets

from argon2.low_level import Type, hash_secret_raw

from .keyfile_kdf import HSE2_KEYFILE_MIN_SIZE, validate_keyfile_bytes
from .keys import HSE2KeyMaterial
from .models import HSE2ModelError, KDFProfile, get_kdf_profile
from .password_kdf import HSE2_KDF_SALT_SIZE, normalize_password


HSE2_COMBINED_KDF_CONTEXT = b"HSE2:password-keyfile-kek:v1"


@dataclass(frozen=True)
class CombinedKDFResult:
    """A password+keyfile-derived KEK plus non-secret derivation metadata."""

    kek: HSE2KeyMaterial
    profile: KDFProfile
    salt: bytes
    keyfile_size: int
    keyfile_sha256: str

    def __post_init__(self) -> None:
        if self.kek.purpose != "KEK":
            raise HSE2ModelError("combined KDF result must contain a KEK")
        if len(self.salt) != HSE2_KDF_SALT_SIZE:
            raise HSE2ModelError(f"combined KDF salt must be {HSE2_KDF_SALT_SIZE} bytes")
        if self.keyfile_size < HSE2_KEYFILE_MIN_SIZE:
            raise HSE2ModelError("keyfile size is below the minimum")
        if len(self.keyfile_sha256) != 64:
            raise HSE2ModelError("keyfile sha256 metadata must be hex-encoded")

    def kdf_metadata(self) -> dict[str, object]:
        """Return JSON-safe metadata without exposing password, keyfile, or KEK."""

        import base64

        data = self.profile.to_dict(salt=base64.b64encode(self.salt).decode("ascii"))
        data["mode"] = "password_keyfile"
        data["keyfile_size"] = self.keyfile_size
        data["keyfile_sha256"] = self.keyfile_sha256
        return data


def derive_kek_from_password_and_keyfile(
    password: str,
    keyfile_bytes: bytes,
    *,
    profile_name: str = "hardened",
    salt: bytes | None = None,
) -> CombinedKDFResult:
    """Derive a KEK from both a password and keyfile bytes.

    The password and keyfile material are domain-separated before Argon2id so a
    missing or substituted keyfile changes the derived KEK even when the password
    is correct.
    """

    profile = get_kdf_profile(profile_name)
    password_bytes = normalize_password(password)
    keyfile_material = validate_keyfile_bytes(keyfile_bytes)
    actual_salt = salt if salt is not None else secrets.token_bytes(HSE2_KDF_SALT_SIZE)
    if not isinstance(actual_salt, bytes):
        raise HSE2ModelError("combined KDF salt must be bytes")
    if len(actual_salt) != HSE2_KDF_SALT_SIZE:
        raise HSE2ModelError(f"combined KDF salt must be {HSE2_KDF_SALT_SIZE} bytes")

    keyfile_digest = hashlib.sha256(keyfile_material).digest()
    secret = HSE2_COMBINED_KDF_CONTEXT + b":" + password_bytes + b":" + keyfile_digest
    raw = hash_secret_raw(
        secret=secret,
        salt=actual_salt,
        time_cost=profile.time_cost,
        memory_cost=profile.memory_cost_kib,
        parallelism=profile.parallelism,
        hash_len=profile.hash_len,
        type=Type.ID,
    )
    return CombinedKDFResult(
        kek=HSE2KeyMaterial(purpose="KEK", value=raw),
        profile=profile,
        salt=actual_salt,
        keyfile_size=len(keyfile_material),
        keyfile_sha256=hashlib.sha256(keyfile_material).hexdigest(),
    )
