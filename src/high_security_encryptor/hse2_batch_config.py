"""Config objects for explicit HSE2 multi-file batch workflows."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .config_parsing import normalize_secret_spec, read_string, require_config_object
from .hse2_config import HSE2_KDF_PROFILES
from .kdf_profiles import KDF_PROFILE_HARDENED
from .password_sources import PasswordResolver, SecretSpec
from .streaming_primitives import DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE


@dataclass(frozen=True)
class HSE2BatchEncryptItem:
    """One input/output pair for HSE2 batch encryption."""

    input: str
    output: str
    wrapper: SecretSpec | None = None

    @classmethod
    def from_dict(cls, payload: object, *, index: int) -> "HSE2BatchEncryptItem":
        obj = require_config_object(payload)
        item = cls(
            input=read_string(obj, "input", ""),
            output=read_string(obj, "output", ""),
            wrapper=normalize_secret_spec(obj["wrapper"], f"items[{index}].wrapper") if "wrapper" in obj else None,
        )
        item.validate(index=index)
        return item

    def validate(self, *, index: int) -> None:
        if not self.input:
            raise ValueError(f"items[{index}].input is required")
        if not self.output:
            raise ValueError(f"items[{index}].output is required")


@dataclass(frozen=True)
class HSE2BatchDecryptItem:
    """One input/output pair for HSE2 batch decryption."""

    input: str
    output: str
    wrapper: SecretSpec | None = None

    @classmethod
    def from_dict(cls, payload: object, *, index: int) -> "HSE2BatchDecryptItem":
        obj = require_config_object(payload)
        item = cls(
            input=read_string(obj, "input", ""),
            output=read_string(obj, "output", ""),
            wrapper=normalize_secret_spec(obj["wrapper"], f"items[{index}].wrapper") if "wrapper" in obj else None,
        )
        item.validate(index=index)
        return item

    def validate(self, *, index: int) -> None:
        if not self.input:
            raise ValueError(f"items[{index}].input is required")
        if not self.output:
            raise ValueError(f"items[{index}].output is required")


@dataclass(frozen=True)
class HSE2BatchEncryptConfig:
    """Serializable config for HSE2 batch encryption."""

    items: tuple[HSE2BatchEncryptItem, ...]
    wrapper: SecretSpec | None = None
    kdf_profile: str = KDF_PROFILE_HARDENED
    chunk_size: int = DEFAULT_CHUNK_SIZE
    continue_on_error: bool = False

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2BatchEncryptConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2BatchEncryptConfig":
        obj = require_config_object(payload)
        raw_items = _read_items(obj)
        config = cls(
            items=tuple(HSE2BatchEncryptItem.from_dict(item, index=index) for index, item in enumerate(raw_items)),
            wrapper=normalize_secret_spec(obj["wrapper"], "wrapper") if "wrapper" in obj else None,
            kdf_profile=read_string(obj, "kdf_profile", KDF_PROFILE_HARDENED),
            chunk_size=_read_chunk_size(obj),
            continue_on_error=_read_bool(obj, "continue_on_error", False),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.items:
            raise ValueError("items must contain at least one entry")
        _validate_kdf_profile(self.kdf_profile)
        _validate_chunk_size(self.chunk_size)
        for index, item in enumerate(self.items):
            if item.wrapper is None and self.wrapper is None:
                raise ValueError(f"items[{index}].wrapper is required when batch wrapper is omitted")

    def resolve_wrapper_for_item(self, item: HSE2BatchEncryptItem, resolver: PasswordResolver, *, index: int) -> str:
        spec = item.wrapper if item.wrapper is not None else self.wrapper
        if spec is None:
            raise ValueError(f"items[{index}].wrapper is required")
        return resolver.resolve(spec, f"hse2_batch_encrypt.items[{index}].wrapper")


@dataclass(frozen=True)
class HSE2BatchDecryptConfig:
    """Serializable config for HSE2 batch decryption."""

    items: tuple[HSE2BatchDecryptItem, ...]
    wrapper: SecretSpec | None = None
    continue_on_error: bool = False

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2BatchDecryptConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2BatchDecryptConfig":
        obj = require_config_object(payload)
        raw_items = _read_items(obj)
        config = cls(
            items=tuple(HSE2BatchDecryptItem.from_dict(item, index=index) for index, item in enumerate(raw_items)),
            wrapper=normalize_secret_spec(obj["wrapper"], "wrapper") if "wrapper" in obj else None,
            continue_on_error=_read_bool(obj, "continue_on_error", False),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.items:
            raise ValueError("items must contain at least one entry")
        for index, item in enumerate(self.items):
            if item.wrapper is None and self.wrapper is None:
                raise ValueError(f"items[{index}].wrapper is required when batch wrapper is omitted")

    def resolve_wrapper_for_item(self, item: HSE2BatchDecryptItem, resolver: PasswordResolver, *, index: int) -> str:
        spec = item.wrapper if item.wrapper is not None else self.wrapper
        if spec is None:
            raise ValueError(f"items[{index}].wrapper is required")
        return resolver.resolve(spec, f"hse2_batch_decrypt.items[{index}].wrapper")


def _read_items(payload: dict[str, object]) -> list[object]:
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("items must be a list")
    if not raw_items:
        raise ValueError("items must contain at least one entry")
    return raw_items


def _read_bool(payload: dict[str, object], key: str, default: bool) -> bool:
    if key not in payload:
        return default
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


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
