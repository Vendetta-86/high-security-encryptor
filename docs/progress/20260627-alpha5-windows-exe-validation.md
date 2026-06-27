# v0.6.0-alpha.5 Windows EXE Validation

Date: 2026-06-27

## Artifact

Expected extracted Windows artifact directory:

```text
<EXTRACTED_ARTIFACT_DIR>
```

Expected artifact name:

```text
high-security-encryptor-v0.6.0-alpha.5-windows-x64.zip
```

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

Use a disposable folder and keyfile:

```powershell
$base = (Get-Location).ProviderPath
$root = Join-Path $base "smoke-root"
$keyPath = Join-Path $base "archive.key"
$archive = Join-Path $base "alpha5.hse2"
$restored = Join-Path $base "restored"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Set-Content -Path (Join-Path $root "a.txt") -Value "hello alpha5" -NoNewline
```

Generate or provide a 64-byte keyfile at:

```text
archive.key
```

Before running the archive smoke, confirm the keyfile exists and has length 64 bytes.

## Commands to validate

Run the alpha.5 HSE2 helper executables with absolute paths:

```powershell
.\high-security-encryptor-hse2-create.exe --root $root --output $archive --keyfile $keyPath --chunk-size 4
.\high-security-encryptor-hse2-inspect.exe --input $archive
.\high-security-encryptor-hse2-open.exe --input $archive --output-dir $restored --keyfile $keyPath
Get-Content (Join-Path $restored "smoke-root\a.txt")
```

Expected restored content:

```text
hello alpha5
```

## HSE2 GUI inspect smoke

Run the standalone HSE2 GUI executable from the extracted artifact:

```powershell
.\high-security-encryptor-hse2-gui.exe
```

Select `检查 HSE2 元数据`, provide the `alpha5.hse2` input path, and confirm the log shows:

- raw JSON stdout from `hse2-inspect`;
- a readable `结果摘要` block;
- only metadata fields such as container path, format version, container size, wrapper count/types, payload chunk count, manifest encrypted status, and access-destroyed status;
- no ciphertext, nonces, authentication tags, wrapped-key blobs, or local key material.

## Result

Pending Windows EXE validation.

After validation, replace this section with the observed final restored content and GUI inspect result.

## Status

Windows EXE smoke validation for the alpha.5 HSE2 GUI inspect path is pending.
