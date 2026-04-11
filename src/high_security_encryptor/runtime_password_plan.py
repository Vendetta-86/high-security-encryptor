"""基于模板的运行时密码计划辅助逻辑。"""

from __future__ import annotations

from dataclasses import dataclass

from .password_sources import PasswordResolver, SecretSpec


@dataclass(frozen=True)
class RuntimePasswordPlan:
    """描述如何用运行时密码来源填充一个带绑定关系的模板。"""

    by_encrypted_name: dict[str, SecretSpec]
    by_source_name: dict[str, SecretSpec]


def resolve_password_plan_from_template(
    template_payload: dict,
    resolver: PasswordResolver,
    plan: RuntimePasswordPlan,
) -> dict[str, str]:
    """在不使用持久化密码表的前提下，为模板行解析密码。"""

    mapping: dict[str, str] = {}
    for row in template_payload.get("rows", []):
        encrypted_name = str(row["encrypted_name"])
        source_name = str(row["source_name"])
        if encrypted_name in plan.by_encrypted_name:
            mapping[encrypted_name] = resolver.resolve(
                plan.by_encrypted_name[encrypted_name],
                f"template.by_encrypted_name[{encrypted_name}]",
            )
        elif source_name in plan.by_source_name:
            mapping[encrypted_name] = resolver.resolve(
                plan.by_source_name[source_name],
                f"template.by_source_name[{source_name}]",
            )
    return mapping
