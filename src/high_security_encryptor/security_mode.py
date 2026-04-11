"""安全模式定义与默认值展开。"""

from __future__ import annotations

from dataclasses import dataclass


SECURITY_MODE_COMPATIBLE = "compatible"
SECURITY_MODE_HARDENED = "hardened"
SECURITY_MODE_NO_PASSWORD_TABLES = "no-password-tables"


@dataclass(frozen=True)
class SecurityModeProfile:
    """描述一个命名安全模式对应的默认开关。"""

    name: str
    write_password_table: bool
    write_internal_password_tables: bool


SECURITY_MODE_PROFILES = {
    SECURITY_MODE_COMPATIBLE: SecurityModeProfile(
        name=SECURITY_MODE_COMPATIBLE,
        write_password_table=True,
        write_internal_password_tables=True,
    ),
    SECURITY_MODE_HARDENED: SecurityModeProfile(
        name=SECURITY_MODE_HARDENED,
        write_password_table=False,
        write_internal_password_tables=True,
    ),
    SECURITY_MODE_NO_PASSWORD_TABLES: SecurityModeProfile(
        name=SECURITY_MODE_NO_PASSWORD_TABLES,
        write_password_table=False,
        write_internal_password_tables=False,
    ),
}


def get_security_mode_profile(mode: str | None) -> SecurityModeProfile:
    """读取安全模式配置并返回对应的默认策略。"""

    normalized_mode = (mode or SECURITY_MODE_COMPATIBLE).strip().lower()
    try:
        return SECURITY_MODE_PROFILES[normalized_mode]
    except KeyError as exc:
        raise ValueError(f"unsupported security_mode: {mode!r}") from exc
