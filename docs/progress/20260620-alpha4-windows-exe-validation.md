# v0.6.0-alpha.4 Windows EXE Validation

Date: 2026-06-20

## Artifact

Validated extracted Windows artifact directory:

```text
F:\test\high-security-encryptor-v0.6.0-alpha.4-windows-x64
```

Expected artifact name:

```text
high-security-encryptor-v0.6.0-alpha.4-windows-x64.zip
```

## Expected executable set

The alpha.4 Windows zip is expected to include these executables:

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
$archive = Join-Path $base "alpha4.hse2"
$restored = Join-Path $base "restored"
```

A smoke source file was created with this content:

```text
hello alpha4
```

A 64-byte keyfile was generated at:

```text
archive.key
```

The keyfile was confirmed present with length 64 bytes.

## Commands validated

The validation then ran the alpha.4 HSE2 helper executables with absolute paths:

```powershell
.\high-security-encryptor-hse2-create.exe --root $root --output $archive --keyfile $keyPath --chunk-size 4
.\high-security-encryptor-hse2-inspect.exe --input $archive
.\high-security-encryptor-hse2-open.exe --input $archive --output-dir $restored --keyfile $keyPath
Get-Content (Join-Path $restored "smoke-root\a.txt")
```

## Result

The final restored content output was:

```text
hello alpha4
```

This confirms the alpha.4 Windows EXE artifact can:

- create an HSE2 archive from a folder;
- inspect the archive metadata through the new inspect helper;
- open the archive with the matching keyfile;
- restore the original file content.

## Note

An earlier attempt failed because `archive.key` did not exist at the expected path. After regenerating the keyfile with an absolute path and confirming it existed, the create/inspect/open smoke test completed successfully.

## Status

Windows EXE smoke validation for the alpha.4 HSE2 inspect path passed.
