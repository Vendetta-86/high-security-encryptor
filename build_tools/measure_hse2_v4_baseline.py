"""Measure v4 container size, create time, and peak process working set.

Run with the project's test environment:

    python build_tools/measure_hse2_v4_baseline.py

The script creates disposable zero-filled files under a temporary directory,
uses fixed test-only passwords, and deletes each generated container after
recording its measurements. It never reads or modifies user files.
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from high_security_encryptor.hse2.container_v4_records import V4_RECORD_PAYLOAD_SIZE
from high_security_encryptor.hse2.container_v4_workflows import create_v4_archive


TEST_PASSWORDS = ("baseline-only-primary-password", "baseline-only-secondary-password")
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


def _worker(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    output_path = Path(config["output_path"])
    views = tuple(tuple((archive_path, source_path) for archive_path, source_path in view) for view in config["view_files"])
    started = time.perf_counter()
    create_v4_archive(
        output_path=output_path,
        view_passwords=TEST_PASSWORDS,
        view_files=views,
        capacity_records=config["capacity_records"],
        profile_name="compatible",
    )
    elapsed = time.perf_counter() - started
    print(json.dumps({"elapsed_seconds": elapsed, "peak_working_set_bytes": _peak_working_set_bytes()}))


def _write_zero_file(path: Path, byte_count: int) -> None:
    with path.open("wb") as output:
        remaining = byte_count
        block = bytes(min(INPUT_BLOCK_SIZE, max(remaining, 1)))
        while remaining:
            chunk_length = min(remaining, len(block))
            output.write(block[:chunk_length])
            remaining -= chunk_length


def _record_count(view: list[tuple[str, Path]]) -> int:
    return sum(math.ceil(path.stat().st_size / V4_RECORD_PAYLOAD_SIZE) for _, path in view)


def _format_mib(byte_count: int) -> str:
    return f"{byte_count / (1024 * 1024):.1f}"


def _build_report(rows: list[dict[str, object]]) -> str:
    lines = [
        "# HSE2 v4 creation baseline",
        "",
        f"- Captured (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Platform: {platform.platform()}",
        f"- Python: {platform.python_version()} ({sys.executable})",
        "- Inputs: temporary zero-filled test files; no user files are read.",
        "- Password profile: compatible; passwords are fixed test-only values in the script.",
        "- Peak memory: per-worker peak process working set (includes interpreter and KDF).",
        "",
        "| Case | Capacity records | Container bytes | Container MiB | Create seconds | Peak working set MiB |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['case']} | {row['capacity_records']:,} | {row['container_bytes']:,} "
            f"| {_format_mib(int(row['container_bytes']))} | {row['elapsed_seconds']:.3f} "
            f"| {_format_mib(int(row['peak_working_set_bytes']))} |"
        )
    lines.extend([
        "",
        "Re-run with `python build_tools/measure_hse2_v4_baseline.py` from the repository root. "
        "Create time is measured inside each fresh worker after imports. Results vary by CPU, storage, "
        "Python, PyCryptodome, and filesystem; compare runs on the same machine before drawing conclusions.",
        "",
    ])
    return "\n".join(lines)


def _run_parent() -> None:
    with tempfile.TemporaryDirectory(prefix="hse2-v4-baseline-") as temp_dir:
        root = Path(temp_dir)
        source_1_byte = root / "one-byte.bin"
        source_1_mib = root / "one-mib.bin"
        source_16_mib = root / "sixteen-mib.bin"
        source_64_mib = root / "sixty-four-mib.bin"
        _write_zero_file(source_1_byte, 1)
        _write_zero_file(source_1_mib, 1024 * 1024)
        _write_zero_file(source_16_mib, 16 * 1024 * 1024)
        _write_zero_file(source_64_mib, 64 * 1024 * 1024)
        small_files = []
        for index in range(32):
            source = root / f"small-{index:02}.bin"
            _write_zero_file(source, 1)
            small_files.append((f"small-{index:02}.bin", source))

        cases: list[tuple[str, list[tuple[str, Path]], list[tuple[str, Path]]]] = [
            ("empty-both-views", [], []),
            ("one-byte-primary", [("one-byte.bin", source_1_byte)], []),
            ("one-byte-each-view", [("primary.bin", source_1_byte)], [("secondary.bin", source_1_byte)]),
            ("one-mib-primary", [("one-mib.bin", source_1_mib)], []),
            ("sixteen-mib-primary", [("sixteen-mib.bin", source_16_mib)], []),
            ("sixty-four-mib-primary", [("sixty-four-mib.bin", source_64_mib)], []),
            ("thirty-two-small-primary-files", small_files, []),
        ]
        rows: list[dict[str, object]] = []
        for case_name, primary, secondary in cases:
            capacity_records = 2 * max(1, _record_count(primary), _record_count(secondary))
            output_path = root / f"{case_name}.hse2"
            config_path = root / f"{case_name}.json"
            config_path.write_text(
                json.dumps({
                    "output_path": str(output_path),
                    "capacity_records": capacity_records,
                    "view_files": [
                        [[archive_path, str(source_path)] for archive_path, source_path in primary],
                        [[archive_path, str(source_path)] for archive_path, source_path in secondary],
                    ],
                }),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--worker-config", str(config_path)],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            worker_metrics = json.loads(completed.stdout)
            rows.append({
                "case": case_name,
                "capacity_records": capacity_records,
                "container_bytes": output_path.stat().st_size,
                **worker_metrics,
            })
            output_path.unlink()

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
