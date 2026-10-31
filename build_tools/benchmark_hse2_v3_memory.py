"""Compare HSE2 v3 peak memory for small and large payloads on Windows."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tracemalloc


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _peak_working_set(pid: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    psapi.GetProcessMemoryInfo.argtypes = (ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), ctypes.c_ulong)
    psapi.GetProcessMemoryInfo.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x410, False, pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _write_payload(path: Path, size_bytes: int) -> None:
    block = bytes(range(256)) * 4096
    remaining = size_bytes
    with path.open("wb") as stream:
        while remaining:
            part = block[: min(len(block), remaining)]
            stream.write(part)
            remaining -= len(part)


def _worker(operation: str, source: Path, archive: Path, output_dir: Path, keyfile: Path) -> dict[str, int]:
    from high_security_encryptor.hse2_create_cli import main as create_main
    from high_security_encryptor.hse2_open_cli import main as open_main

    if operation == "create":
        call = create_main
        args = ["--root", str(source), "--output", str(archive), "--keyfile", str(keyfile),
                "--chunk-size", "1048576", "--format-version", "3", "--compact"]
    else:
        call = open_main
        args = ["--input", str(archive), "--output-dir", str(output_dir), "--keyfile", str(keyfile), "--compact"]

    tracemalloc.start()
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = call(args)
    _current_bytes, peak_python_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if exit_code:
        raise RuntimeError(f"{operation} failed ({exit_code}): {stderr.getvalue().strip()}")
    return {"peak_python_bytes": peak_python_bytes, "peak_working_set_bytes": _peak_working_set(os.getpid())}


def _measure(operation: str, source: Path, archive: Path, output_dir: Path, keyfile: Path) -> dict[str, int]:
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", operation,
               "--source", str(source), "--archive", str(archive),
               "--output-dir", str(output_dir), "--keyfile", str(keyfile)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError(f"{operation} worker failed: {completed.stderr.strip() or completed.stdout.strip()}")
    result = json.loads(completed.stdout)
    size_mib = source.stat().st_size // (1024 * 1024)
    print(json.dumps({
        "operation": f"{operation}-{size_mib}MiB",
        "peak_python_heap_mib": round(result["peak_python_bytes"] / (1024 * 1024), 2),
        "peak_working_set_mib": round(result["peak_working_set_bytes"] / (1024 * 1024), 2),
    }, sort_keys=True))
    return result


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    if args_list and args_list[0] == "--worker":
        parser = argparse.ArgumentParser()
        parser.add_argument("--worker", choices=("create", "open"), required=True)
        parser.add_argument("--source", type=Path, required=True)
        parser.add_argument("--archive", type=Path, required=True)
        parser.add_argument("--output-dir", type=Path, required=True)
        parser.add_argument("--keyfile", type=Path, required=True)
        args = parser.parse_args(args_list)
        try:
            print(json.dumps(_worker(args.worker, args.source, args.archive, args.output_dir, args.keyfile)))
            return 0
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--small-mib", type=int, default=8)
    parser.add_argument("--large-mib", type=int, default=128)
    parser.add_argument("--max-growth-mib", type=float, default=32.0)
    args = parser.parse_args(args_list)
    if os.name != "nt":
        parser.error("this benchmark measures Windows working set and must run on Windows")
    if args.small_mib <= 0 or args.large_mib <= args.small_mib or args.max_growth_mib <= 0:
        parser.error("require 0 < --small-mib < --large-mib and a positive --max-growth-mib")

    with tempfile.TemporaryDirectory(prefix="hse2-v3-memory-") as temp_dir:
        base = Path(temp_dir)
        keyfile = base / "benchmark.key"
        keyfile.write_bytes(b"HSE2-MEMORY-BENCHMARK-KEY-000000")
        measurements: dict[str, dict[str, dict[str, int]]] = {}
        for size_mib in (args.small_mib, args.large_mib):
            source = base / f"payload-{size_mib}MiB.bin"
            archive = base / f"archive-{size_mib}MiB.hse2"
            output_dir = base / f"opened-{size_mib}MiB"
            _write_payload(source, size_mib * 1024 * 1024)
            measurements[str(size_mib)] = {
                operation: _measure(operation, source, archive, output_dir, keyfile)
                for operation in ("create", "open")
            }

        growth: dict[str, dict[str, float]] = {}
        for operation in ("create", "open"):
            small = measurements[str(args.small_mib)][operation]
            large = measurements[str(args.large_mib)][operation]
            growth[operation] = {
                metric: round((large[field] - small[field]) / (1024 * 1024), 2)
                for metric, field in (("python_heap_mib", "peak_python_bytes"), ("working_set_mib", "peak_working_set_bytes"))
            }
        print(json.dumps({"growth_mib": growth, "budget_mib": args.max_growth_mib}, sort_keys=True))
        exceeded = {op: metrics for op, metrics in growth.items()
                    if any(value > args.max_growth_mib for value in metrics.values())}
        if exceeded:
            print(f"FAIL: memory growth exceeded budget: {exceeded}", file=sys.stderr)
            return 1
        print("PASS: Python heap and peak working-set growth stayed within budget")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
