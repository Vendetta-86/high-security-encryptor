"""Shared user-facing warnings for Windows DPAPI usage."""

DPAPI_WRAPPER_PORTABILITY_WARNING = (
    "DPAPI wrapper is tied to its protecting Windows user context and usually to the same computer. "
    "Reinstalling Windows, changing users, or moving the container may make it unusable. "
    "Keep an independent password or keyfile wrapper for recovery."
)

DPAPI_LOCAL_MACHINE_SCOPE_WARNING = (
    "安全提示：local_machine scope 绑定当前 Windows 计算机；同一计算机上的任何用户都可能解密该 blob。"
    "仅在确实需要本机多用户访问时使用；换机或重装后可能无法解密。"
)
