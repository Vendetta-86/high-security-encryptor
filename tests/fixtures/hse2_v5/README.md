# HSE2 v5 complete archive fixture

`complete_archive.hse2` is a small frozen container used to check that later
code can still parse and restore a complete v5 archive written by the current
format implementation. `complete_archive.json` records the expected path and
size for each restored file in both views. `complete_archive.sha256` pins the
archive and restored-file digests. Its hash lines are marked as public fixture
checksums for the secret scanner. The plaintext samples under `expected/` are
synthetic test data.

The view credentials are deliberately public test-only values named
`PRIMARY_FIXTURE_CREDENTIAL` and `SECONDARY_FIXTURE_CREDENTIAL` in
`tests/test_hse2_v5_fixtures.py`. They must never be reused for real archives.

To regenerate the fixture from the repository root with the project virtual
environment installed:

```powershell
.\.venv\Scripts\python.exe tests\fixtures\hse2_v5\generate_fixture.py
```

The generator substitutes deterministic bytes only in its own short-lived
process. It does not add a production setting or change production CSPRNG
calls. Tests read the checked-in archive and never generate their expected
archive at runtime, so a writer change cannot silently rewrite the compatibility
baseline.
