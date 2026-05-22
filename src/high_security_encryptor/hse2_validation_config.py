"""Config objects for read-only HSE2 validation reports."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .config_parsing import normalize_secret_spec, require_config_object
from .password_sources import PasswordResolver, SecretSpec


@dataclass(frozen=True)
class HSE2ValidationItem:
    """One HSE2 container validation item."""

    input: str
    wrapper: SecretSpec | None = None

    @classmethod
    def from_dict(cls, payload: object, *, index: int) -> "HSE2ValidationItem":
        obj = require_config_object(payload)
        raw_input = obj.get("input", "")
        if not isinstance(raw_input, str):
            raise ValueError(f"items[{index}].input must be a string")
        item = cls(
            input=raw_input,
            wrapper=normalize_secret_spec(obj["wrapper"], f"items[{index}].wrapper") if "wrapper" in obj else None,
        )
        item.validate(index=index)
        return item

    def validate(self, *, index: int) -> None:
        if not self.input:
            raise ValueError(f"items[{index}].input is required")


@dataclass(frozen=True)
class HSE2ValidationConfig:
    """Serializable config for read-only HSE2 validation reports."""

    items: tuple[HSE2ValidationItem, ...]
    wrapper: SecretSpec | None = None
    continue_on_error: bool = True

    @classmethod
    def from_json_file(cls, path: str | Path) -> "HSE2ValidationConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: object) -> "HSE2ValidationConfig":
        obj = require_config_object(payload)
        raw_items = obj.get("items")
        if not isinstance(raw_items, list):
            raise ValueError("items must be a list")
        if not raw_items:
            raise ValueError("items must contain at least one entry")
        config = cls(
            items=tuple(HSE2ValidationItem.from_dict(item, index=index) for index, item in enumerate(raw_items)),
            wrapper=normalize_secret_spec(obj["wrapper"], "wrapper") if "wrapper" in obj else None,
            continue_on_error=_read_bool(obj, "continue_on_error", True),
        )
        config.validate()
        return config

    def validate(self) -> None:
        for index, item in enumerate(self.items):
            if item.wrapper is None and self.wrapper is None:
                raise ValueError(f"items[{index}].wrapper is required when batch wrapper is omitted")

    def resolve_wrapper_for_item(self, item: HSE2ValidationItem, resolver: PasswordResolver, *, index: int) -> str:
        spec = item.wrapper if item.wrapper is not None else self.wrapper
        if spec is None:
            raise ValueError(f"items[{index}].wrapper is required")
        return resolver.resolve(spec, f"hse2_validate.items[{index}].wrapper")


def _read_bool(payload: dict[str, object], key: str, default: bool) -> bool:
    if key not in payload:
        return default
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value
