# HSE2 v5 local performance baseline

- Captured (UTC): 2026-11-01T12:55:40+00:00
- Platform: Windows 11 x64, build 10.0.26300
- Python: 3.13.15, isolated `work/hse2-test-venv`
- Inputs: temporary zero-filled test files; no user files were read.
- Password profile: compatible; fixed test-only passwords are in the benchmark script.
- Memory metric: per-worker peak working set across the full sequence, including interpreter and Argon2.
- Repeats per case: 3, each in a fresh worker process.
- Each worker measures create, replace-one-view, compact-both-views, and primary restore. Replace uses a 1-byte replacement file; compaction therefore removes the original primary payload in those cases.

| Case | Created bytes | Replaced bytes | Compacted bytes | Create s median (min-max) | Replace s median (min-max) | Compact s median (min-max) | Restore s median (min-max) | Peak WS MiB median (min-max) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Empty, both views | 484 | 755 | 630 | 0.082 (0.080-0.083) | 0.077 (0.077-0.078) | 0.218 (0.215-0.221) | 0.079 (0.078-0.083) | 98.0 (97.8-98.0) |
| One-byte primary | 627 | 898 | 630 | 0.088 (0.083-0.088) | 0.084 (0.080-0.085) | 0.222 (0.219-0.234) | 0.079 (0.077-0.080) | 98.0 (98.0-98.0) |
| One byte in each view | 770 | 1,041 | 774 | 0.085 (0.083-0.094) | 0.080 (0.074-0.084) | 0.244 (0.216-0.251) | 0.090 (0.079-0.091) | 98.0 (97.8-98.1) |
| 1 MiB primary | 1,049,213 | 1,049,488 | 630 | 0.086 (0.083-0.097) | 0.078 (0.078-0.080) | 0.212 (0.212-0.217) | 0.080 (0.079-0.083) | 97.9 (97.9-98.1) |
| 16 MiB primary | 16,779,506 | 16,779,784 | 630 | 0.115 (0.115-0.127) | 0.087 (0.083-0.096) | 0.226 (0.220-0.234) | 0.082 (0.079-0.083) | 97.9 (97.9-98.0) |
| 64 MiB primary | 67,116,485 | 67,116,763 | 630 | 0.203 (0.199-0.206) | 0.111 (0.109-0.111) | 0.227 (0.221-0.250) | 0.084 (0.082-0.091) | 98.1 (97.9-98.1) |
| 32 one-byte primary files | 5,132 | 5,406 | 630 | 0.099 (0.099-0.101) | 0.083 (0.082-0.087) | 0.233 (0.228-0.240) | 0.085 (0.083-0.087) | 98.0 (97.9-98.2) |

## Interpretation and limits

The smallest empty container is 484 bytes. A 64 MiB payload creates a 67,116,485-byte container. On this machine, Python build, and test set, the three-run median peak working set across the complete sequence was 98.1 MiB. The recorded v4 64 MiB case was 270,532,778 bytes, 0.690 seconds to create, and 353.0 MiB peak working set; the v5 three-run median was 0.203 seconds to create. The earlier v4 figure was not rerun three times, so this comparison remains indicative and is not an acceptance threshold or performance guarantee. Storage cache, CPU load, Python, and cryptographic library versions can change results.

The replacement case intentionally replaces the complete primary view with a 1-byte file, so compacted sizes are small even for the 1/16/64 MiB original cases. It measures the normal replacement-copy cost and resulting compaction path, not equal-size replacement throughput. Peak working set is the maximum over the complete sequence, not an operation-specific measurement. Three samples provide a small local range and do not characterize all system or storage noise.

Reproduce with `python build_tools/measure_hse2_v5_baseline.py --repeat 3` from the repository root. The script uses disposable zero-filled files and fixed test-only passwords; it does not read user files.
