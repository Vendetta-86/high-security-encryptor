# HSE2 v4 local creation baseline

- Captured (UTC): 2026-11-01 11:49
- Platform: Windows 11 x64, build 10.0.26300
- Python: 3.13.15, isolated `work/hse2-test-venv`
- Password KDF: compatible profile
- Inputs: temporary zero-filled files created by the benchmark script; no user files were read.
- Memory metric: per-process peak working set, including interpreter, KDF, and format processing.
- Reproduction: `python build_tools/measure_hse2_v4_baseline.py`

| Case | Capacity records | Container bytes | Container MiB | Create seconds | Peak working set MiB |
|---|---:|---:|---:|---:|---:|
| Empty, both views | 2 | 136,315,050 | 130.0 | 0.514 | 353.1 |
| One-byte primary view | 2 | 136,315,050 | 130.0 | 0.481 | 353.3 |
| One byte in each view | 2 | 136,315,050 | 130.0 | 0.513 | 353.1 |
| 1 MiB primary file | 4 | 138,412,202 | 132.0 | 0.516 | 353.0 |
| 16 MiB primary file | 34 | 169,869,482 | 162.0 | 0.557 | 353.1 |
| 64 MiB primary file | 130 | 270,532,778 | 258.0 | 0.690 | 353.0 |
| 32 one-byte primary files | 64 | 201,326,762 | 192.0 | 0.602 | 353.1 |

## Reading the results

The empty and one-byte cases both produce a 130 MiB container. The two fixed 64 MiB descriptor regions account for 128 MiB; two 1 MiB record slots account for most of the rest. The 64 MiB input case produces a 258 MiB container because the fixed record capacity must also reserve space for the unused peer view. These results justify measuring compact v5 layouts before selecting the next format.

The measured creation times are a single-run baseline on this machine, not an acceptance threshold. Peak working set stays near 353 MiB across cases because v4 descriptor processing and the compatible Argon2 profile dominate these samples. Repeat on the same machine after performance changes and compare multiple runs before claiming improvement. This benchmark measures create only; it does not establish update, restore, cold-start, or power-loss behavior.

The executable benchmark is [`build_tools/measure_hse2_v4_baseline.py`](https://github.com/Vendetta-86/high-security-encryptor/blob/master/build_tools/measure_hse2_v4_baseline.py).
