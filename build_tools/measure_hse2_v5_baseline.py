"""Measure v5 create, replace, compact, restore, size, and peak memory.

Run from the repository root with the project environment:

    python build_tools/measure_hse2_v5_baseline.py

The script creates disposable zero-filled inputs in a temporary directory and
uses test-only passwords. It does not read or modify user files.
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from high_security_encryptor.hse2.container_v5_migration import compact_v5_archive
from high_security_encryptor.hse2.container_v5_workflows import (
    create_v5_archive,
    replace_v5_view,
    restore_v5_archive,
)

TEST_PASSWORDS = ("v5-baseline-primary-only", "v5-baseline-secondary-only")
INPUT_BLOCK_SIZE = 1024 * 1024


def _peak_working_set_bytes() -> int:
    if os.name == "nt":
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.WinDLL("Kernel32.dll").GetCurrentProcess()
        get_info = ctypes.WinDLL("Psapi.dll").GetProcessMemoryInfo
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        if not get_info(process, ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(counters.PeakWorkingSetSize)

    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _write_zero_file(path: Path, byte_count: int) -> None:
    with path.open("wb") as output:
        remaining = byte_count
        block = bytes(min(INPUT_BLOCK_SIZE, max(remaining, 1)))
        while remaining:
            length = min(remaining, len(block))
            output.write(block[:length])
            remaining -= length


def _timed(callable_obj) -> float:
    started = time.perf_counter()
    callable_obj()
    return time.perf_counter() - started


def _worker(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    root = Path(config["work_dir"])
    output = root / "created.hse2"
    replaced = root / "replaced.hse2"
    compacted = root / "compacted.hse2"
    views = tuple(
        tuple((archive_path, Path(source_path)) for archive_path, source_path in view)
        for view in config["view_files"]
    )
    replacement_source = Path(config["replacement_source"])

    create_seconds = _timed(lambda: create_v5_archive(
        output_path=output, view_passwords=TEST_PASSWORDS, view_files=views,
    ))
    replace_seconds = _timed(lambda: replace_v5_view(
        input_path=output, output_path=replaced, password=TEST_PASSWORDS[0],
        view_files=(("replacement.bin", replacement_source),),
    ))
    compact_seconds = _timed(lambda: compact_v5_archive(
        input_path=replaced, output_path=compacted, view_passwords=TEST_PASSWORDS,
    ))
    restore_seconds = _timed(lambda: restore_v5_archive(
        input_path=compacted, password=TEST_PASSWORDS[0], output_dir=root / "restored-primary",
    ))
    print(json.dumps({
        "create_seconds": create_seconds,
        "replace_seconds": replace_seconds,
        "compact_seconds": compact_seconds,
        "restore_seconds": restore_seconds,
        "peak_working_set_bytes": _peak_working_set_bytes(),
        "created_bytes": output.stat().st_size,
        "replaced_bytes": replaced.stat().st_size,
        "compacted_bytes": compacted.stat().st_size,
    }))


def _format_mib(byte_count: int) -> str:
    return f"{byte_count / (1024 * 1024):.1f}"


def _build_report(rows: list[dict[str, object]]) -> str:
    lines = [
        "# HSE2 v5 local performance baseline",
        "",
        f"- Captured (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Platform: {platform.platform()}",
        f"- Python: {platform.python_version()} ({sys.executable})",
        "- Inputs: temporary zero-filled test files; no user files are read.",
        "- Password profile: compatible; fixed test-only passwords are in the script.",
        "- Memory metric: per-worker peak process working set, including interpreter and Argon2.",
        "- Each case measures create, replace-one-view, compact-both-views, and primary restore in one fresh worker.",
        "",
        "| Case | Created bytes | Replaced bytes | Compacted bytes | Create s | Replace s | Compact s | Restore s | Peak WS MiB |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['case']} | {row['created_bytes']:,} | {row['replaced_bytes']:,} | {row['compacted_bytes']:,} "
            f"| {row['create_seconds']:.3f} | {row['replace_seconds']:.3f} | {row['compact_seconds']:.3f} "
            f"| {row['restore_seconds']:.3f} | {_format_mib(int(row['peak_working_set_bytes']))} |"
        )
    lines.extend([
        "",
        "These are single-run observations, not performance guarantees or release thresholds. Compare with v4 only on the same machine, Python build, storage, and equivalent inputs. Replace always copies the existing container to a new output; compact/export re-encrypt active contents. Peak working set is the maximum over the full sequence, not an operation-specific value.",
        "",
        "Re-run with `python build_tools/measure_hse2_v5_baseline.py` from the repository root.",
        "",
    ])
    return "\n".join(lines)


def _run_parent() -> None:
    with tempfile.TemporaryDirectory(prefix="hse2-v5-baseline-") as temp_dir:
        root = Path(temp_dir)
        inputs = {
            "one_byte": root / "one-byte.bin",
            "one_mib": root / "one-mib.bin",
            "sixteen_mib": root / "sixteen-mib.bin",
            "sixty_four_mib": root / "sixty-four-mib.bin",
        }
        for name, size in (("one_byte", 1), ("one_mib", 1 << 20),
                           ("sixteen_mib", 16 << 20), ("sixty_four_mib", 64 << 20)):
            _write_zero_file(inputs[name], size)
        small_files = []
        for index in range(32):
            source = root / f"small-{index:02}.bin"
            _write_zero_file(source, 1)
            small_files.append((f"small-{index:02}.bin", source))
        replacement = root / "replacement.bin"
        _write_zero_file(replacement, 1)

        cases: list[tuple[str, list[tuple[str, Path]], list[tuple[str, Path]]]] = [
            ("empty-both-views", [], []),
            ("one-byte-primary", [("one-byte.bin", inputs["one_byte"])], []),
            ("one-byte-each-view", [("primary.bin", inputs["one_byte"])], [("secondary.bin", inputs["one_byte"])]),
            ("one-mib-primary", [("one-mib.bin", inputs["one_mib"])], []),
            ("sixteen-mib-primary", [("sixteen-mib.bin", inputs["sixteen_mib"])], []),
            ("sixty-four-mib-primary", [("sixty-four-mib.bin", inputs["sixty_four_mib"])], []),
            ("thirty-two-small-primary-files", small_files, []),
        ]
        rows: list[dict[str, object]] = []
        for case_name, primary, secondary in cases:
            work_dir = root / case_name
            work_dir.mkdir()
            config_path = root / f"{case_name}.json"
            config_path.write_text(json.dumps({
                "work_dir": str(work_dir),
                "replacement_source": str(replacement),
                "view_files": [
                    [[archive_path, str(source_path)] for archive_path, source_path in primary],
                    [[archive_path, str(source_path)] for archive_path, source_path in secondary],
                ],
            }), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--worker-config", str(config_path)],
                cwd=REPO_ROOT, check=True, capture_output=True, text=True,
            )
            rows.append({"case": case_name, **json.loads(completed.stdout)})
        print(_build_report(rows))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_config is not None:
        _worker(args.worker_config)
    else:
        _run_parent()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
