"""Config objects for explicit single-file HSE2 workflows."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .config_parsing import normalize_secret_spec, read_optional_string, read_string, require_config_object
from .kdf_profiles import KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED, KDF_PROFILE_PARANOID
from .password_sources import PasswordResolver, SecretSpec
from .streaming_primitives import DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE

HSE2_KDF_PROFILES = {KDF_PROFILE_COMPATIBLE, KDF_PROFILE_HARDENED, KDF_PROFILE_PARANOID}


@dataclass(frozen=True)
class HSE2EncryptConfig:
    """Serializable config for one HSE2 encryption operation."""

    input: str
    output: str
    wrapper: SecretSpec
    kdf_profile: str = KDF_PROFILE_HARDENED
    chunk_size: int = DEFAULT_CHUNK_SIZE

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2EncryptConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2EncryptConfig":
        obj = require_config_object(payload)
        config = cls(
            input=read_string(obj, "input", ""),
            output=read_string(obj, "output", ""),
            wrapper=normalize_secret_spec(obj.get("wrapper", ""), "wrapper"),
            kdf_profile=read_string(obj, "kdf_profile", KDF_PROFILE_HARDENED),
            chunk_size=_read_chunk_size(obj),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.input:
            raise ValueError("input is required")
        if not self.output:
            raise ValueError("output is required")
        if not self.wrapper:
            raise ValueError("wrapper is required")
        _validate_kdf_profile(self.kdf_profile)
        _validate_chunk_size(self.chunk_size)

    def resolve_wrapper(self, resolver: PasswordResolver) -> str:
        return resolver.resolve(self.wrapper, "hse2_encrypt.wrapper")


@dataclass(frozen=True)
class HSE2DecryptConfig:
    """Serializable config for one HSE2 decryption operation."""

    input: str
    output: str
    wrapper: SecretSpec

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2DecryptConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2DecryptConfig":
        obj = require_config_object(payload)
        config = cls(
            input=read_string(obj, "input", ""),
            output=read_string(obj, "output", ""),
            wrapper=normalize_secret_spec(obj.get("wrapper", ""), "wrapper"),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.input:
            raise ValueError("input is required")
        if not self.output:
            raise ValueError("output is required")
        if not self.wrapper:
            raise ValueError("wrapper is required")

    def resolve_wrapper(self, resolver: PasswordResolver) -> str:
        return resolver.resolve(self.wrapper, "hse2_decrypt.wrapper")


@dataclass(frozen=True)
class HSE2RewrapConfig:
    """Serializable config for one HSE2 rewrap operation."""

    input: str
    output: str
    old_wrapper: SecretSpec
    new_wrapper: SecretSpec
    new_kdf_profile: str = KDF_PROFILE_HARDENED

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2RewrapConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2RewrapConfig":
        obj = require_config_object(payload)
        config = cls(
            input=read_string(obj, "input", ""),
            output=read_string(obj, "output", ""),
            old_wrapper=normalize_secret_spec(obj.get("old_wrapper", ""), "old_wrapper"),
            new_wrapper=normalize_secret_spec(obj.get("new_wrapper", ""), "new_wrapper"),
            new_kdf_profile=read_string(obj, "new_kdf_profile", KDF_PROFILE_HARDENED),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.input:
            raise ValueError("input is required")
        if not self.output:
            raise ValueError("output is required")
        if not self.old_wrapper:
            raise ValueError("old_wrapper is required")
        if not self.new_wrapper:
            raise ValueError("new_wrapper is required")
        _validate_kdf_profile(self.new_kdf_profile)

    def resolve_old_wrapper(self, resolver: PasswordResolver) -> str:
        return resolver.resolve(self.old_wrapper, "hse2_rewrap.old_wrapper")

    def resolve_new_wrapper(self, resolver: PasswordResolver) -> str:
        return resolver.resolve(self.new_wrapper, "hse2_rewrap.new_wrapper")


def _read_chunk_size(payload: dict[str, object]) -> int:
    if "chunk_size" not in payload:
        return DEFAULT_CHUNK_SIZE
    value = payload["chunk_size"]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("chunk_size must be an integer")
    return value


def _validate_chunk_size(value: int) -> None:
    if value <= 0 or value > MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_SIZE}")


def _validate_kdf_profile(value: str) -> None:
    if value not in HSE2_KDF_PROFILES:
        allowed = ", ".join(sorted(HSE2_KDF_PROFILES))
        raise ValueError(f"unknown HSE2 KDF profile: {value}; expected one of: {allowed}")
