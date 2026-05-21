"""Argon2id KDF profiles used by encrypted container formats.

HSE1 currently stores no KDF parameters in the file header, so it must continue
using the historical fixed profile. Newer formats can serialize these profile
fields into the container header and can support rewrapping without rewriting
large ciphertext payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw


ARGON2ID_ALGORITHM = "argon2id"
KDF_PROFILE_COMPATIBLE = "compatible"
KDF_PROFILE_HARDENED = "hardened"
KDF_PROFILE_PARANOID = "paranoid"
DEFAULT_KDF_PROFILE = KDF_PROFILE_COMPATIBLE
KEY_LEN = 32


@dataclass(frozen=True)
class Argon2idProfile:
    """Parameters for deriving a key with Argon2id."""

    name: str
    time_cost: int
    memory_cost_kib: int
    parallelism: int
    hash_len: int = KEY_LEN

    def validate(self) -> None:
        if self.time_cost <= 0:
            raise ValueError("Argon2id time_cost must be greater than zero")
        if self.memory_cost_kib <= 0:
            raise ValueError("Argon2id memory_cost_kib must be greater than zero")
        if self.parallelism <= 0:
            raise ValueError("Argon2id parallelism must be greater than zero")
        if self.hash_len <= 0:
            raise ValueError("Argon2id hash_len must be greater than zero")

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": ARGON2ID_ALGORITHM,
            "profile": self.name,
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }


KDF_PROFILES: dict[str, Argon2idProfile] = {
    # HSE1 compatibility profile. Do not change these values without creating a
    # new self-describing container format.
    KDF_PROFILE_COMPATIBLE: Argon2idProfile(
        name=KDF_PROFILE_COMPATIBLE,
        time_cost=3,
        memory_cost_kib=65536,
        parallelism=4,
    ),
    # Conservative high-security default for future self-describing containers.
    KDF_PROFILE_HARDENED: Argon2idProfile(
        name=KDF_PROFILE_HARDENED,
        time_cost=3,
        memory_cost_kib=262144,
        parallelism=4,
    ),
    # Expensive profile for small, high-value archives on machines with enough RAM.
    KDF_PROFILE_PARANOID: Argon2idProfile(
        name=KDF_PROFILE_PARANOID,
        time_cost=4,
        memory_cost_kib=1048576,
        parallelism=4,
    ),
}


def get_kdf_profile(name: str = DEFAULT_KDF_PROFILE) -> Argon2idProfile:
    """Return a named Argon2id profile."""

    try:
        profile = KDF_PROFILES[name]
    except KeyError as exc:
        allowed = ", ".join(sorted(KDF_PROFILES))
        raise ValueError(f"unknown KDF profile: {name}; expected one of: {allowed}") from exc
    profile.validate()
    return profile


def derive_argon2id_key(password: str, salt: bytes, profile: Argon2idProfile | None = None) -> bytes:
    """Derive a raw key using Argon2id and the selected profile."""

    if not password:
        raise ValueError("password is required")
    if not salt:
        raise ValueError("salt is required")
    effective_profile = profile or get_kdf_profile(DEFAULT_KDF_PROFILE)
    effective_profile.validate()
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=effective_profile.time_cost,
        memory_cost=effective_profile.memory_cost_kib,
        parallelism=effective_profile.parallelism,
        hash_len=effective_profile.hash_len,
        type=Type.ID,
    )
