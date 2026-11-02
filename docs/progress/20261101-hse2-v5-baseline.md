# HSE2 v5 local performance baseline

- Captured (UTC): 2026-11-02T11:48:01+00:00
- Platform: Windows 11 x64, build 10.0.26300
- Python: 3.13.15, isolated `work/hse2-test-venv`
- Inputs: temporary zero-filled test files; no user files were read.
- Password profile: compatible; fixed test-only passwords are in the benchmark script.
- Repeats: 3 per operation and scenario; every sample runs in a fresh worker process.
- Fixture setup: a separate worker creates source, replacement, and compacted archives; operation workers consume those fixtures and write to separate outputs.
- Memory metric: process peak working set, including interpreter and cryptographic runtime overhead.
- Replace uses a 1-byte replacement file; compact therefore removes the original primary payload in those cases.

## Operation time and container sizes

| Case | Created bytes | Replaced bytes | Compacted bytes | Create s median (min-max) | Replace s median (min-max) | Compact s median (min-max) | Restore s median (min-max) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Empty, both views | 484 | 755 | 630 | 0.080 (0.078-0.085) | 0.082 (0.079-0.082) | 0.216 (0.216-0.217) | 0.084 (0.084-0.085) |
| One-byte primary | 627 | 898 | 630 | 0.080 (0.080-0.081) | 0.081 (0.078-0.082) | 0.219 (0.217-0.220) | 0.084 (0.084-0.084) |
| One byte in each view | 770 | 1,041 | 774 | 0.083 (0.081-0.086) | 0.078 (0.077-0.085) | 0.222 (0.219-0.224) | 0.084 (0.084-0.085) |
| 1 MiB primary | 1,049,213 | 1,049,488 | 630 | 0.086 (0.083-0.089) | 0.082 (0.080-0.083) | 0.228 (0.219-0.238) | 0.085 (0.083-0.089) |
| 16 MiB primary | 16,779,506 | 16,779,784 | 630 | 0.116 (0.115-0.184) | 0.108 (0.093-0.119) | 0.266 (0.234-0.267) | 0.096 (0.095-0.106) |
| 64 MiB primary | 67,116,485 | 67,116,763 | 630 | 0.229 (0.208-0.233) | 0.123 (0.116-0.128) | 0.258 (0.219-0.274) | 0.094 (0.086-0.128) |
| 32 one-byte primary files | 5,132 | 5,406 | 630 | 0.094 (0.092-0.095) | 0.082 (0.080-0.084) | 0.225 (0.219-0.231) | 0.085 (0.083-0.151) |

## Isolated operation peak working set

Each sample runs one operation in a fresh process. Values include process startup and cryptographic runtime overhead.

| Case | Create WS MiB median (min-max) | Replace WS MiB median (min-max) | Compact WS MiB median (min-max) | Restore WS MiB median (min-max) |
|---|---:|---:|---:|---:|
| Empty, both views | 98.2 (98.2-98.4) | 98.1 (98.1-98.4) | 98.2 (98.2-98.3) | 98.2 (98.1-98.4) |
| One-byte primary | 98.1 (98.1-98.3) | 98.1 (98.0-98.1) | 98.2 (98.1-98.2) | 98.2 (98.1-98.2) |
| One byte in each view | 98.2 (98.2-98.3) | 98.2 (98.2-98.3) | 98.2 (98.1-98.2) | 98.3 (98.2-98.3) |
| 1 MiB primary | 98.2 (98.2-98.2) | 98.2 (98.2-98.4) | 98.3 (98.2-98.4) | 98.3 (98.2-98.4) |
| 16 MiB primary | 98.2 (98.2-98.3) | 98.2 (98.1-98.4) | 98.2 (98.2-98.4) | 98.3 (98.3-98.3) |
| 64 MiB primary | 98.3 (98.2-98.3) | 98.2 (98.1-98.3) | 98.3 (98.1-98.4) | 98.2 (98.2-98.4) |
| 32 one-byte primary files | 98.2 (98.1-98.2) | 98.1 (98.1-98.2) | 98.3 (98.2-98.3) | 98.3 (98.2-98.4) |

## Interpretation and limits

The smallest empty container is 484 bytes. A 64 MiB payload creates a 67,116,485-byte container. In these isolated runs, the median create working set was 98.3 MiB and the median restore working set was 98.2 MiB for that case. The range across three samples is narrow for memory, while some elapsed-time ranges show visible system noise.

This replaces the prior combined-worker memory figure with per-operation process measurements. The earlier v4 peak-memory figure used a different measurement boundary, so it is not directly comparable to the isolated v5 values. Do not treat these observations as performance guarantees or release thresholds. Storage cache, CPU load, Python, and cryptographic library versions can change results.

The replacement case intentionally replaces the complete primary view with a 1-byte file, so compacted sizes are small even for the 1/16/64 MiB original cases. It measures normal replacement-copy cost and the resulting compaction path, not equal-size replacement throughput.

Reproduce with `python build_tools/measure_hse2_v5_baseline.py --repeat 3` from the repository root. The script uses disposable zero-filled files and fixed test-only passwords; it does not read user files.
