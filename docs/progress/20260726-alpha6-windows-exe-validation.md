# v0.6.0-alpha.6 Windows EXE Validation

Date: 2026-07-26

## Artifact

Expected extracted Windows artifact directory:

```text
<EXTRACTED_ARTIFACT_DIR>
```

Expected artifact name:

```text
high-security-encryptor-v0.6.0-alpha.6-windows-x64.zip
```

## Expected executable set

The alpha.6 Windows zip is expected to include these executables:

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
$archive = Join-Path $base "alpha6.hse2"
$restored = Join-Path $base "restored"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Set-Content -Path (Join-Path $root "a.txt") -Value "hello alpha6" -NoNewline
```

Generate or provide a 64-byte keyfile at:

```text
archive.key
```

Before running the archive smoke, confirm the keyfile exists and has length 64 bytes.

## Commands to validate

Run the alpha.6 HSE2 helper executables with absolute paths:

```powershell
.\high-security-encryptor-hse2-create.exe --root $root --output $archive --keyfile $keyPath --chunk-size 4
.\high-security-encryptor-hse2-inspect.exe --input $archive
.\high-security-encryptor-hse2-open.exe --input $archive --output-dir $restored --keyfile $keyPath
Get-Content (Join-Path $restored "smoke-root\a.txt")
```

Expected restored content:

```text
hello alpha6
```

## HSE2 GUI dynamic field smoke

Run the standalone HSE2 GUI executable from the extracted artifact:

```powershell
.\high-security-encryptor-hse2-gui.exe
```

Switch through the HSE2 action dropdown and confirm action-specific fields hide/show correctly:

- config actions show only the config path;
- `HSE2 只读校验` shows the config path, validation report output, and validation flags;
- `检查 HSE2 元数据` shows only the `.hse2` input container field;
- `生成 keyfile` shows output path, keyfile size, and overwrite;
- `Windows DPAPI 保护 keyfile` shows input path, output path, DPAPI scope, and overwrite;
- `列出 HSE2 wrapper` shows only the `.hse2` input container field;
- `移除指定 HSE2 wrapper` shows input/output paths, wrapper id, optional password/keyfile/DPAPI fields, and overwrite;
- `永久禁用 HSE2 访问` shows input/output paths, overwrite, exact confirmation phrase, and the warning phrase.

For the inspect action, provide the `alpha6.hse2` input path and confirm the log shows:

- raw JSON stdout from `hse2-inspect`;
- a readable `结果摘要` block;
- only metadata fields such as container path, format version, container size, wrapper count/types, payload chunk count, manifest encrypted status, and access-destroyed status;
- no ciphertext, nonces, authentication tags, wrapped-key blobs, or local key material.

## Main GUI smoke

Run the main GUI executable smoke test:

```powershell
.\high-security-encryptor-gui.exe --smoke-test
```

Then launch the main GUI manually and confirm the `打开 HSE2 实验工具` entry opens the standalone HSE2 experimental window.

## Result

Pending Windows EXE validation.

After validation, replace this section with the observed final restored content, GUI dynamic field smoke result, and main GUI entry result.

## Status

Windows EXE smoke validation for the alpha.6 HSE2 dynamic-field GUI release is pending.
