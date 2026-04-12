"""Strict JSON config parsing helpers."""

from __future__ import annotations

from .password_sources import SecretSpec


def require_config_object(payload: object) -> dict[str, object]:
    """Reject non-object top-level JSON payloads before field parsing."""

    if not isinstance(payload, dict):
        raise ValueError("config must be a JSON object")
    return payload


def read_string(payload: dict[str, object], field_name: str, default: str) -> str:
    """Read an optional string field without coercing non-strings."""

    if field_name not in payload:
        return default
    value = payload[field_name]
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


def read_optional_string(payload: dict[str, object], field_name: str) -> str | None:
    """Read a nullable or blank-as-missing string field."""

    if field_name not in payload or payload[field_name] is None:
        return None
    value = payload[field_name]
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or null")
    normalized = value.strip()
    return normalized or None


def read_bool(payload: dict[str, object], field_name: str, default: bool) -> bool:
    """Read a boolean field without accepting string truthiness."""

    if field_name not in payload:
        return default
    value = payload[field_name]
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def read_object_mapping(payload: dict[str, object], field_name: str) -> dict[str, object]:
    """Read a JSON object field and preserve key names."""

    if field_name not in payload:
        return {}
    value = payload[field_name]
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    result: dict[str, object] = {}
    for key, inner_value in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{field_name} keys must be strings")
        result[key] = inner_value
    return result


def read_string_list(payload: dict[str, object], field_name: str) -> list[str]:
    """Read a list of strings without iterating accidental scalar values."""

    if field_name not in payload:
        return []
    value = payload[field_name]
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{field_name}[{index}] must be a string")
        result.append(item)
    return result


def read_string_list_mapping(payload: dict[str, object], field_name: str) -> dict[str, list[str]]:
    """Read a JSON object whose values are string lists."""

    raw_mapping = read_object_mapping(payload, field_name)
    result: dict[str, list[str]] = {}
    for key, value in raw_mapping.items():
        if not isinstance(value, list):
            raise ValueError(f"{field_name}[{key}] must be a list")
        items: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str):
                raise ValueError(f"{field_name}[{key}][{index}] must be a string")
            items.append(item)
        result[key] = items
    return result


def read_secret_mapping(payload: dict[str, object], field_name: str) -> dict[str, SecretSpec]:
    """Read a JSON object whose values are password source specs."""

    raw_mapping = read_object_mapping(payload, field_name)
    return {
        key: normalize_secret_spec(value, f"{field_name}[{key}]")
        for key, value in raw_mapping.items()
    }


def read_nested_secret_mapping(payload: dict[str, object], field_name: str) -> dict[str, dict[str, SecretSpec]]:
    """Read a two-level JSON object whose leaf values are password source specs."""

    raw_mapping = read_object_mapping(payload, field_name)
    result: dict[str, dict[str, SecretSpec]] = {}
    for key, inner_value in raw_mapping.items():
        if not isinstance(inner_value, dict):
            raise ValueError(f"{field_name}[{key}] must be an object")
        result[key] = {}
        for inner_key, secret_value in inner_value.items():
            if not isinstance(inner_key, str):
                raise ValueError(f"{field_name}[{key}] keys must be strings")
            result[key][inner_key] = normalize_secret_spec(
                secret_value,
                f"{field_name}[{key}][{inner_key}]",
            )
    return result


def read_folder_template_passwords(
    payload: dict[str, object],
    field_name: str,
) -> dict[str, dict[str, dict[str, SecretSpec]]]:
    """Read package-scoped runtime password plans for folder internals."""

    raw_mapping = read_object_mapping(payload, field_name)
    result: dict[str, dict[str, dict[str, SecretSpec]]] = {}
    for package_name, package_plan in raw_mapping.items():
        if not isinstance(package_plan, dict):
            raise ValueError(f"{field_name}[{package_name}] must be an object")
        normalized_package_plan: dict[str, dict[str, SecretSpec]] = {}
        for scope, scope_map in package_plan.items():
            if not isinstance(scope, str):
                raise ValueError(f"{field_name}[{package_name}] keys must be strings")
            if scope not in {"by_encrypted_name", "by_source_name"}:
                raise ValueError(f"{field_name}[{package_name}] has unsupported scope: {scope}")
            if not isinstance(scope_map, dict):
                raise ValueError(f"{field_name}[{package_name}][{scope}] must be an object")
            normalized_package_plan[scope] = {}
            for name, secret_value in scope_map.items():
                if not isinstance(name, str):
                    raise ValueError(f"{field_name}[{package_name}][{scope}] keys must be strings")
                normalized_package_plan[scope][name] = normalize_secret_spec(
                    secret_value,
                    f"{field_name}[{package_name}][{scope}][{name}]",
                )
        result[package_name] = normalized_package_plan
    return result


def normalize_secret_spec(value: object, context: str) -> SecretSpec:
    """Normalize JSON password-source config without scalar coercion."""

    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, inner_value in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{context}: password source keys must be strings")
            result[key] = _normalize_secret_spec_value(inner_value, f"{context}.{key}")
        return result
    raise ValueError(f"{context} must be a string or password source object")


def _normalize_secret_spec_value(value: object, context: str) -> object:
    """Normalize nested password-source values without scalar coercion."""

    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [
            _normalize_secret_spec_value(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, inner_value in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{context}: password source keys must be strings")
            result[key] = _normalize_secret_spec_value(inner_value, f"{context}.{key}")
        return result
    raise ValueError(f"{context} must be a string, list, or object")
