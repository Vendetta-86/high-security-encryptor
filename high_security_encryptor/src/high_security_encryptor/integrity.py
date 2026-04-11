"""加密条目集合的完整性校验辅助逻辑。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class IntegrityValidationError(Exception):
    """当实际加密条目与 manifest 预期不一致时抛出。"""


@dataclass(frozen=True)
class EntrySetComparison:
    """汇总 manifest 与实际文件集合的比较结果。"""

    expected_entries: list[str]
    actual_entries: list[str]
    missing_entries: list[str]
    extra_entries: list[str]
    duplicate_entries: list[str]


def compare_entry_sets(expected_entries: list[str], actual_entries: list[str]) -> EntrySetComparison:
    """以确定性归一化形式比较两组加密条目列表。"""

    normalized_expected = [_normalize_entry_name(name) for name in expected_entries]
    normalized_actual = [_normalize_entry_name(name) for name in actual_entries]

    expected_set = set(normalized_expected)
    actual_set = set(normalized_actual)
    duplicate_entries = sorted({name for name in normalized_actual if normalized_actual.count(name) > 1})

    return EntrySetComparison(
        expected_entries=sorted(expected_set),
        actual_entries=sorted(actual_set),
        missing_entries=sorted(expected_set - actual_set),
        extra_entries=sorted(actual_set - expected_set),
        duplicate_entries=duplicate_entries,
    )


def validate_entry_sets_match(expected_entries: list[str], actual_entries: list[str], context: str) -> EntrySetComparison:
    """当实际加密条目集合与 manifest 集合不一致时抛出异常。"""

    comparison = compare_entry_sets(expected_entries, actual_entries)
    if comparison.duplicate_entries:
        raise IntegrityValidationError(
            f"{context}: duplicate encrypted entries found: {', '.join(comparison.duplicate_entries)}"
        )
    if comparison.missing_entries or comparison.extra_entries:
        details: list[str] = []
        if comparison.missing_entries:
            details.append(f"missing: {', '.join(comparison.missing_entries)}")
        if comparison.extra_entries:
            details.append(f"extra: {', '.join(comparison.extra_entries)}")
        raise IntegrityValidationError(f"{context}: entry set mismatch ({'; '.join(details)})")
    return comparison


def collect_internal_encrypted_entries(extracted_root: str | Path, sidecar_dir_name: str) -> list[str]:
    """收集已解压文件夹包中的 `.hse` 成员。"""

    root_path = Path(extracted_root)
    entries: list[str] = []
    for file_path in sorted(root_path.rglob("*.hse")):
        try:
            relative_path = file_path.relative_to(root_path)
        except ValueError:
            continue
        if relative_path.parts and relative_path.parts[0] == sidecar_dir_name:
            continue
        entries.append(PurePosixPath(relative_path.as_posix()).as_posix())
    return entries


def _normalize_entry_name(name: str) -> str:
    """把加密条目名称归一化为 manifest 使用的标准形式。"""

    return PurePosixPath(str(name).replace("\\", "/")).as_posix()
