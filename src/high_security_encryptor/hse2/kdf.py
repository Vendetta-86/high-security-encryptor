"""Argon2id KDF profile definitions for HSE2."""

from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    PROFILE_COMPATIBLE,
    PROFILE_HARDENED,
    PROFILE_PARANOID,
    SUPPORTED_KDF_ALGORITHM,
)
from .errors import HSE2UnsupportedProfileError


@dataclass(frozen=True, slots=True)
class KdfProfile:
    """A memory-hard KDF parameter profile stored in HSE2 wrapper metadata."""

    name: str
    algorithm: str
    memory_cost_kib: int
    time_cost: int
    parallelism: int
    hash_len: int = 32

    def to_dict(self) -> dict[str, int | str]:
        """Return a stable JSON-serializable profile representation."""

        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "memory_cost_kib": self.memory_cost_kib,
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }


KDF_PROFILES: dict[str, KdfProfile] = {
    PROFILE_COMPATIBLE: KdfProfile(
        name=PROFILE_COMPATIBLE,
        algorithm=SUPPORTED_KDF_ALGORITHM,
        memory_cost_kib=64 * 1024,
        time_cost=3,
        parallelism=4,
    ),
    PROFILE_HARDENED: KdfProfile(
        name=PROFILE_HARDENED,
        algorithm=SUPPORTED_KDF_ALGORITHM,
        memory_cost_kib=256 * 1024,
        time_cost=3,
        parallelism=4,
    ),
    PROFILE_PARANOID: KdfProfile(
        name=PROFILE_PARANOID,
        algorithm=SUPPORTED_KDF_ALGORITHM,
        memory_cost_kib=1024 * 1024,
        time_cost=4,
        parallelism=4,
    ),
}


def get_kdf_profile(name: str) -> KdfProfile:
    """Return a supported KDF profile by name.

    The requested profile name is stored in HSE2 wrapper metadata. Rejecting
    unknown profiles early prevents silently falling back to weaker settings.
    """

    try:
        return KDF_PROFILES[name]
    except KeyError as exc:
        supported = ", ".join(sorted(KDF_PROFILES))
        raise HSE2UnsupportedProfileError(
            f"Unsupported HSE2 KDF profile {name!r}; supported profiles: {supported}"
        ) from exc
