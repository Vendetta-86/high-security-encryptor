# HSE2 v5 local performance baseline

- Captured (UTC): 2026-11-01 12:49:55
- Platform: Windows 11 x64, build 10.0.26300
- Python: 3.13.15, isolated `work/hse2-test-venv`
- Inputs: temporary zero-filled test files; no user files were read.
- Password profile: compatible; fixed test-only passwords are in the benchmark script.
- Memory metric: per-worker peak working set across the full sequence, including interpreter and Argon2.
- Each fresh worker measured create, replace-one-view, compact-both-views, and primary restore. Replace uses a 1-byte replacement file; compaction therefore removes the original primary payload in those cases.

| Case | Created bytes | Replaced bytes | Compacted bytes | Create s | Replace s | Compact s | Restore s | Peak WS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Empty, both views | 484 | 755 | 630 | 0.083 | 0.073 | 0.218 | 0.088 | 97.4 |
| One-byte primary | 627 | 898 | 630 | 0.106 | 0.098 | 0.259 | 0.097 | 97.5 |
| One byte in each view | 770 | 1,041 | 774 | 0.094 | 0.088 | 0.244 | 0.089 | 97.5 |
| 1 MiB primary | 1,049,213 | 1,049,488 | 630 | 0.103 | 0.083 | 0.232 | 0.087 | 97.4 |
| 16 MiB primary | 16,779,506 | 16,779,784 | 630 | 0.124 | 0.090 | 0.212 | 0.088 | 97.4 |
| 64 MiB primary | 67,116,485 | 67,116,763 | 630 | 0.212 | 0.119 | 0.226 | 0.084 | 97.4 |
| 32 one-byte primary files | 5,132 | 5,406 | 630 | 0.114 | 0.092 | 0.265 | 0.096 | 97.7 |

## Interpretation and limits

The smallest empty container is 484 bytes. A 64 MiB payload creates a 67,116,485-byte container, with a measured peak working set of 97.4 MiB across all four operations in that worker. On the same Windows/Python environment, the recorded v4 64 MiB case was 270,532,778 bytes, 0.690 seconds to create, and 353.0 MiB peak working set. The v5 run observed 0.212 seconds to create. This is a single-run comparison; it is not an acceptance threshold or a performance guarantee. Storage cache, CPU load, Python and cryptographic library versions can materially change the results.

The benchmark's replacement case intentionally replaces the complete primary view with a 1-byte file, so the compacted sizes are small even for the 1/16/64 MiB original cases. It measures the normal replacement-copy cost and the resulting compaction path, not equal-size replacement throughput. Peak working set is the maximum over the complete sequence, not an operation-specific measurement.

Reproduce with `python build_tools/measure_hse2_v5_baseline.py` from the repository root. The script uses disposable zero-filled files and fixed test-only passwords; it does not read user files.
