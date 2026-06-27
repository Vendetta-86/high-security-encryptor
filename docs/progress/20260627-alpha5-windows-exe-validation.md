# v0.6.0-alpha.5 Windows EXE Validation

Date: 2026-06-27

## Artifact

Validated Windows artifact:

```text
high-security-encryptor-v0.6.0-alpha.5-windows-x64.zip
```

The extracted artifact directory was not captured in this validation note.

## Expected executable set

The alpha.5 Windows zip is expected to include these executables:

- `high-security-encryptor.exe`
- `high-security-encryptor-gui.exe`
- `high-security-encryptor-hse2-gui.exe`
- `high-security-encryptor-hse2-create.exe`
- `high-security-encryptor-hse2-open.exe`
- `high-security-encryptor-hse2-header-backup.exe`
- `high-security-encryptor-hse2-inspect.exe`
- `high-security-encryptor-hse2-wrapper.exe`
- `high-security-encryptor-hse2-access.exe`

## Smoke fixture

The validation used a disposable folder and keyfile:

```powershell
$base = (Get-Location).ProviderPath
$root = Join-Path $base "smoke-root"
$keyPath = Join-Path $base "archive.key"
$archive = Join-Path $base "alpha5.hse2"
$restored = Join-Path $base "restored"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Set-Content -Path (Join-Path $root "a.txt") -Value "hello alpha5" -NoNewline
```

A keyfile was generated or provided at:

```text
archive.key
```

The archive smoke used a disposable `.hse2` archive:

```text
alpha5.hse2
```

## Commands validated

The validation ran the alpha.5 HSE2 helper executables with absolute paths:

```powershell
.\high-security-encryptor-hse2-create.exe --root $root --output $archive --keyfile $keyPath --chunk-size 4
.\high-security-encryptor-hse2-inspect.exe --input $archive
.\high-security-encryptor-hse2-open.exe --input $archive --output-dir $restored --keyfile $keyPath
Get-Content (Join-Path $restored "smoke-root\a.txt")
```

## CLI smoke result

The final restored content output was:

```text
hello alpha5
```

This confirms the alpha.5 Windows EXE artifact can:

- create an HSE2 archive from a folder;
- inspect the archive metadata through the inspect helper;
- open the archive with the matching keyfile;
- restore the original file content.

## HSE2 GUI inspect smoke

The standalone HSE2 GUI executable was launched from the extracted artifact:

```powershell
.\high-security-encryptor-hse2-gui.exe
```

The GUI smoke selected `检查 HSE2 元数据`, provided the `alpha5.hse2` input path, and confirmed the inspect path behaved normally.

The GUI inspect log was confirmed to show:

- raw JSON stdout from `hse2-inspect`;
- a readable `结果摘要` block;
- metadata-only inspect output.

The GUI inspect smoke did not report exposure of ciphertext, nonces, authentication tags, wrapped-key blobs, or local key material.

## Result

Windows EXE smoke validation for the alpha.5 HSE2 CLI and GUI inspect path passed.

## Status

Windows EXE smoke validation for `v0.6.0-alpha.5` passed.
