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
import statistics
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
    operation = config.get("operation")
    if operation is not None:
        root = Path(config["work_dir"])
        started = time.perf_counter()
        if operation == "create":
            views = tuple(
                tuple((archive_path, Path(source_path)) for archive_path, source_path in view)
                for view in config["view_files"]
            )
            output = root / "created.hse2"
            create_v5_archive(output_path=output, view_passwords=TEST_PASSWORDS, view_files=views)
        elif operation == "replace":
            output = root / "replaced.hse2"
            replace_v5_view(
                input_path=config["input_path"], output_path=output,
                password=TEST_PASSWORDS[0],
                view_files=(("replacement.bin", Path(config["replacement_source"])),),
            )
        elif operation == "compact":
            output = root / "compacted.hse2"
            compact_v5_archive(
                input_path=config["input_path"], output_path=output,
                view_passwords=TEST_PASSWORDS,
            )
        elif operation == "restore":
            restore_v5_archive(
                input_path=config["input_path"], password=TEST_PASSWORDS[0],
                output_dir=root / "restored-primary",
            )
            output = None
        else:
            raise ValueError(f"unknown benchmark operation: {operation}")
        print(json.dumps({
            "operation": operation,
            "seconds": time.perf_counter() - started,
            "peak_working_set_bytes": _peak_working_set_bytes(),
            "output_bytes": output.stat().st_size if output is not None else None,
        }))
        return

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
        "- Memory metric: process peak working set, including interpreter and Argon2; each operation's memory run uses a fresh worker.",
        f"- Repeats per case and operation: {rows[0]['repeat_count'] if rows else 0}; each operation sample uses a fresh worker.",
        "- A separate setup worker prepares create/replace/compact fixtures. Each measured operation consumes a fixture in an isolated worker.",
        "",
        "| Case | Created bytes | Replaced bytes | Compacted bytes | Create s median (min-max) | Replace s median (min-max) | Compact s median (min-max) | Restore s median (min-max) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        def duration(name: str) -> str:
            samples = row[name]
            assert isinstance(samples, list)
            return f"{statistics.median(samples):.3f} ({min(samples):.3f}-{max(samples):.3f})"

        lines.append(
            f"| {row['case']} | {row['created_bytes']:,} | {row['replaced_bytes']:,} | {row['compacted_bytes']:,} "
            f"| {duration('create_seconds')} | {duration('replace_seconds')} | {duration('compact_seconds')} "
            f"| {duration('restore_seconds')} |"
        )
    lines.extend([
        "",
        "## Isolated operation peak working set",
        "",
        "Each sample runs one operation in a fresh process. Values include interpreter and cryptographic runtime overhead.",
        "",
        "| Case | Create WS MiB median (min-max) | Replace WS MiB median (min-max) | Compact WS MiB median (min-max) | Restore WS MiB median (min-max) |",
        "|---|---:|---:|---:|---:|",
    ])
    for row in rows:
        def memory(name: str) -> str:
            samples = row["operation_peak_working_set_bytes"][name]
            return (
                f"{_format_mib(int(statistics.median(samples)))} "
                f"({_format_mib(min(samples))}-{_format_mib(max(samples))})"
            )
        lines.append(
            f"| {row['case']} | {memory('create')} | {memory('replace')} "
            f"| {memory('compact')} | {memory('restore')} |"
        )
    lines.extend([
        "",
        "These are repeated local observations, not performance guarantees or release thresholds. Tables show medians and min-max ranges; a small sample does not characterize all machine and storage noise. Compare with v4 only on the same machine, Python build, storage, and equivalent inputs. Replace always copies the existing container to a new output; compact/export re-encrypt active contents. Isolated operation working sets include process startup and may vary with allocator behavior.",
        "",
        "Re-run with `python build_tools/measure_hse2_v5_baseline.py --repeat 3` from the repository root.",
        "",
    ])
    return "\n".join(lines)


def _run_parent(repeat: int) -> None:
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
            setup_observations = []
            operation_observations: dict[str, list[dict[str, object]]] = {
                name: [] for name in ("create", "replace", "compact", "restore")
            }
            serialized_views = [
                [[archive_path, str(source_path)] for archive_path, source_path in primary],
                [[archive_path, str(source_path)] for archive_path, source_path in secondary],
            ]
            for run_index in range(repeat):
                work_dir = root / case_name / f"run-{run_index + 1:02}"
                work_dir.mkdir(parents=True)
                setup_config_path = root / f"{case_name}-{run_index + 1:02}-setup.json"
                setup_config_path.write_text(json.dumps({
                    "work_dir": str(work_dir),
                    "replacement_source": str(replacement),
                    "view_files": serialized_views,
                }), encoding="utf-8")
                setup_completed = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()), "--worker-config", str(setup_config_path)],
                    cwd=REPO_ROOT, check=True, capture_output=True, text=True,
                )
                setup_observation = json.loads(setup_completed.stdout)
                setup_observations.append(setup_observation)

                operation_configs = {
                    "create": {"view_files": serialized_views},
                    "replace": {
                        "input_path": str(work_dir / "created.hse2"),
                        "replacement_source": str(replacement),
                    },
                    "compact": {"input_path": str(work_dir / "replaced.hse2")},
                    "restore": {"input_path": str(work_dir / "compacted.hse2")},
                }
                expected_sizes = {
                    "create": setup_observation["created_bytes"],
                    "replace": setup_observation["replaced_bytes"],
                    "compact": setup_observation["compacted_bytes"],
                    "restore": None,
                }
                for operation, operation_config in operation_configs.items():
                    operation_dir = work_dir / f"isolated-{operation}"
                    operation_dir.mkdir()
                    operation_config_path = root / f"{case_name}-{run_index + 1:02}-{operation}.json"
                    operation_config_path.write_text(json.dumps({
                        **operation_config,
                        "operation": operation,
                        "work_dir": str(operation_dir),
                    }), encoding="utf-8")
                    completed = subprocess.run(
                        [sys.executable, str(Path(__file__).resolve()), "--worker-config",
                         str(operation_config_path)],
                        cwd=REPO_ROOT, check=True, capture_output=True, text=True,
                    )
                    operation_observation = json.loads(completed.stdout)
                    if operation_observation["output_bytes"] != expected_sizes[operation]:
                        raise RuntimeError(
                            f"isolated {operation} output size differs for {case_name}: "
                            f"{operation_observation['output_bytes']} != {expected_sizes[operation]}"
                        )
                    operation_observations[operation].append(operation_observation)

            byte_fields = ("created_bytes", "replaced_bytes", "compacted_bytes")
            for field in byte_fields:
                if len({sample[field] for sample in setup_observations}) != 1:
                    raise RuntimeError(f"non-repeatable container size for {case_name}: {field}")
            rows.append({
                "case": case_name,
                "repeat_count": repeat,
                **{field: setup_observations[0][field] for field in byte_fields},
                **{
                    f"{operation}_seconds": [sample["seconds"] for sample in samples]
                    for operation, samples in operation_observations.items()
                },
                "operation_peak_working_set_bytes": {
                    operation: [sample["peak_working_set_bytes"] for sample in samples]
                    for operation, samples in operation_observations.items()
                },
            })
        print(_build_report(rows))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--repeat", type=int, default=3, help="fresh worker repetitions per case (default: 3)")
    args = parser.parse_args()
    if args.worker_config is not None:
        _worker(args.worker_config)
    else:
        if not 1 <= args.repeat <= 10:
            parser.error("--repeat must be between 1 and 10")
        _run_parent(args.repeat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
