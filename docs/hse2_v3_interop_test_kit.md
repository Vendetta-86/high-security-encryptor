# HSE2 v3 Interoperability Test Kit

This kit defines a two-way exchange check for an independent HSE2 v3 implementation. It is a test vector, not a stable-format certification. The checked-in v3 archive was created by this repository's writer, so opening it alone does not prove interoperability.

## Test-only vector

- Archive: `tests/fixtures/hse2/archive-v3.hse2`
- Archive SHA-256: `8676572a59a12cfc513dc4dd9a7a9c63fe867d4241dfc8ba3ff4fdc1a0b4c163`
- Wrapper: keyfile, using the ASCII bytes below with no trailing newline
- Keyfile bytes: `HSE2-FIXTURE-KEY-MATERIAL-000000` (32 bytes; public test material only)
- Restored relative path: `fixture-payload.txt`
- Expected payload: UTF-8 bytes `Codex HSE2 compatibility fixture v1` followed by one LF byte
- Expected payload length: 36 bytes
- Expected payload SHA-256: `9721a2f0536d250e525e9e7e097e90da36a1f40435c04ca396c93ebe2c913adb`

Never reuse the fixture key for real data.

## Direction A: this repository writes, independent implementation reads

1. Verify the archive SHA-256 before decoding it.
2. Use the exact keyfile bytes above and open the archive as HSE2 format version 3.
3. Require exactly one restored file at `fixture-payload.txt`.
4. Compare the restored byte length and SHA-256 with the expected payload values above.
5. Record the independent implementation name, version or commit, platform, command, and result.

## Direction B: independent implementation writes, this repository reads

1. Have the independent implementation create a version 3 archive containing the same relative path and exact payload bytes, protected by a keyfile wrapper using the same 32-byte test key.
2. Confirm that both preamble and authenticated header declare version 3. Record the produced archive SHA-256.
3. Open that archive with this repository's reader, using a fresh output directory:

```powershell
$independentArchive = 'C:\path\to\independent-v3.hse2'
$fixtureKeyFile = 'C:\path\to\fixture.key'
$outputDir = Join-Path $env:TEMP 'hse2-v3-interop-independent'
if (Test-Path $outputDir) { throw "Choose a fresh output directory: $outputDir" }

$env:PYTHONPATH = 'src'
& .\work\hse2-test-venv\Scripts\python.exe -m high_security_encryptor.hse2_open_cli `
  --input $independentArchive `
  --output-dir $outputDir `
  --keyfile $fixtureKeyFile `
  --compact
if ($LASTEXITCODE -ne 0) { throw "HSE2 open failed with exit code $LASTEXITCODE" }

$restoredFile = Join-Path $outputDir 'fixture-payload.txt'
$expectedSha256 = '9721a2f0536d250e525e9e7e097e90da36a1f40435c04ca396c93ebe2c913adb' # pragma: allowlist secret
if ((Get-Item $restoredFile).Length -ne 36) { throw 'Unexpected restored file length' }
$actualSha256 = (Get-FileHash $restoredFile -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) { throw "Unexpected payload SHA-256: $actualSha256" }
Write-Output 'PASS: independent v3 archive opened; payload length and SHA-256 match.'
```

4. Require exactly one output file at `fixture-payload.txt`, 36 bytes, and the expected payload SHA-256.
5. Record the independent writer name, version or commit, platform, command, archive SHA-256, and result.

## Acceptance gate

The local independent-code-path gate passes when both directions are exercised using the checked-in reference implementation and plaintext checks match. The broader M1.7 external-implementation gate passes only when both directions also pass with an implementation maintained outside this repository, with its exact identity and plaintext checks recorded. A current-writer/current-reader round trip, the checked-in fixture alone, or matching format-version fields do not satisfy either gate. The local gate is now covered; external interoperability and stable-format certification remain pending.

## Evidence record template

```text
Date:
Platform:
Repository implementation revision:
Independent implementation name and exact version/commit:
Independent reader command:
Direction A -> B: PASS / FAIL
  Fixture archive SHA-256:
  Restored relative path:
  Restored byte length:
  Restored plaintext SHA-256:
Independent writer command:
Direction B -> A: PASS / FAIL
  Independent archive SHA-256:
  Restored relative path:
  Restored byte length:
  Restored plaintext SHA-256:
Notes / deviations:
```

The framing and cryptographic fields are specified in [HSE2 Framing Reference](hse2_framing_reference.md). The project roadmap and current gate status are in [M1 HSE2 Streaming Design](progress/m1-hse2-streaming-design-2026-10.md).

## Local independent reference comparison

`tests/interop_reference/hse2_v3_reference.py` is a deliberately small implementation that imports no `high_security_encryptor` code. It implements the documented keyfile, password, and password+keyfile wrapper profiles, authenticated canonical header, manifest record, payload chunks, and strict EOF handling. Password-based checks use the bounded `compatible` Argon2id profile. The two directions are exercised by `tests/test_hse2_v3_independent_interop.py`:

1. Reference writer -> repository `open_hse2_archive` for keyfile, password, and password+keyfile wrappers.
2. Repository `create_hse2_archive` -> reference reader for all three wrapper profiles.
3. Wrong-password rejection for the reference password reader.

The focused test run on 2026-10-31 passed both directions for all three wrapper profiles and rejected an incorrect password and incorrect combined-wrapper keyfile (`Ran 5 tests ... OK`). Reference implementation identity: repository test code at commit `fc278607bbcd001c174525677c118abc08e6bbad`, tested on Windows 11 with Python 3.13.15. The source payload checks are:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `alpha.txt` | 114 | `cb9ee1058efd314121e803864a3034e6bf2330bbb920ab1d80e2a8956488dbd0` |
| `nested/beta.bin` | 131328 | `91f86bc16210e6eab1715b5e77465cc1a906243e758bcecb884060dbe9a26fe3` |
| `empty.dat` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

This is a local independent-code-path compatibility check, not certification by an external implementation. The reference writer and reader use separate HSE2 framing and wrapper code but share the project's installed Argon2 and AES primitive libraries; password interoperability is limited to the `compatible` Argon2id profile. DPAPI and other KDF profiles remain outside this evidence.
