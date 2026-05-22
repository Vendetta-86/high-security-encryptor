"""Config objects for explicit HSE2 keyfile rotation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .config_parsing import read_string, require_config_object
from .hse2_config import HSE2_KDF_PROFILES
from .kdf_profiles import KDF_PROFILE_HARDENED


@dataclass(frozen=True)
class HSE2KeyfileRotationItem:
    """One input/output pair for HSE2 keyfile rotation."""

    input: str
    output: str

    @classmethod
    def from_dict(cls, payload: object, *, index: int) -> "HSE2KeyfileRotationItem":
        obj = require_config_object(payload)
        item = cls(input=read_string(obj, "input", ""), output=read_string(obj, "output", ""))
        item.validate(index=index)
        return item

    def validate(self, *, index: int) -> None:
        if not self.input:
            raise ValueError(f"items[{index}].input is required")
        if not self.output:
            raise ValueError(f"items[{index}].output is required")


@dataclass(frozen=True)
class HSE2KeyfileRotationConfig:
    """Serializable config for rotating HSE2 files between two keyfiles."""

    items: tuple[HSE2KeyfileRotationItem, ...]
    old_keyfile: str
    new_keyfile: str
    new_kdf_profile: str = KDF_PROFILE_HARDENED
    continue_on_error: bool = False

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2KeyfileRotationConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2KeyfileRotationConfig":
        obj = require_config_object(payload)
        raw_items = obj.get("items")
        if not isinstance(raw_items, list):
            raise ValueError("items must be a list")
        if not raw_items:
            raise ValueError("items must contain at least one entry")
        config = cls(
            items=tuple(HSE2KeyfileRotationItem.from_dict(item, index=index) for index, item in enumerate(raw_items)),
            old_keyfile=read_string(obj, "old_keyfile", ""),
            new_keyfile=read_string(obj, "new_keyfile", ""),
            new_kdf_profile=read_string(obj, "new_kdf_profile", KDF_PROFILE_HARDENED),
            continue_on_error=_read_bool(obj, "continue_on_error", False),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.old_keyfile:
            raise ValueError("old_keyfile is required")
        if not self.new_keyfile:
            raise ValueError("new_keyfile is required")
        if self.old_keyfile == self.new_keyfile:
            raise ValueError("old_keyfile and new_keyfile must be different")
        if self.new_kdf_profile not in HSE2_KDF_PROFILES:
            allowed = ", ".join(sorted(HSE2_KDF_PROFILES))
            raise ValueError(f"unknown HSE2 KDF profile: {self.new_kdf_profile}; expected one of: {allowed}")


def _read_bool(payload: dict[str, object], key: str, default: bool) -> bool:
    if key not in payload:
        return default
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value
