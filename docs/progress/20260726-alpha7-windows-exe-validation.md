# v0.6.0-alpha.7 Windows EXE Validation

Date: 2026-07-26

## Artifact

Validated Windows artifact:

```text
high-security-encryptor-v0.6.0-alpha.7-windows-x64.zip
```

Validation was reported by the maintainer from a Windows environment after the alpha.7 Windows executable build was available.

Working directory used for the reported smoke run:

```text
F:\high-security-encryptor
```

## Expected executable set

The alpha.7 Windows zip is expected to include these executables:

- `high-security-encryptor.exe`
- `high-security-encryptor-gui.exe`
- `high-security-encryptor-hse2-gui.exe`
- `high-security-encryptor-hse2-create.exe`
- `high-security-encryptor-hse2-open.exe`
- `high-security-encryptor-hse2-header-backup.exe`
- `high-security-encryptor-hse2-inspect.exe`
- `high-security-encryptor-hse2-wrapper.exe`
- `high-security-encryptor-hse2-access.exe`

The main GUI executable is expected to expose the `打开 HSE2 实验工具` entry point that opens the standalone HSE2 experimental window.

## Smoke fixture

The maintainer reported a disposable fixture equivalent to:

```powershell
$base = (Get-Location).ProviderPath
$root = Join-Path $base "smoke-root"
$keyPath = Join-Path $base "archive.key"
$archive = Join-Path $base "alpha7.hse2"
$restored = Join-Path $base "restored"

Remove-Item $root, $keyPath, $archive, $restored -Recurse -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $root -Force | Out-Null
Set-Content -Path (Join-Path $root "a.txt") -Value "hello alpha7" -NoNewline
```

The keyfile path was:

```text
archive.key
```

The archive path was:

```text
alpha7.hse2
```

## CLI round-trip smoke

The alpha.7 HSE2 helper executables were validated with the create -> inspect -> open flow:

```powershell
.\high-security-encryptor-hse2-create.exe --root $root --output $archive --keyfile $keyPath --chunk-size 4
.\high-security-encryptor-hse2-inspect.exe --input $archive
.\high-security-encryptor-hse2-open.exe --input $archive --output-dir $restored --keyfile $keyPath
Get-Content (Join-Path $restored "smoke-root\a.txt")
```

Observed restored content:

```text
hello alpha7
```

## HSE2 GUI localized-action smoke

The alpha.7 GUI localized action label fix was validated against the standalone HSE2 GUI executable:

```powershell
.\high-security-encryptor-hse2-gui.exe
```

The maintainer reported that the action dropdown now shows the localized inspect label:

```text
检查 HSE2 元数据
```

Selecting `检查 HSE2 元数据` showed only the `.hse2` input field and built the expected inspect command against the reported archive:

```text
hse2-inspect --input alpha7.hse2
```

## GUI inspect metadata-only summary

The standalone HSE2 GUI inspect run against `alpha7.hse2` returned exit code 0 and produced this readable metadata-only summary:

```text
结果摘要：
- 命令：hse2-inspect
- 容器：alpha7.hse2
- format_version：2
- container_size：1833
- wrapper_count：1
- wrapper_types：keyfile
- payload_chunk_count：3
- manifest_encrypted：true
- access_destroyed：false

退出码：0
```

This confirms that the GUI inspect path reports container metadata without exposing ciphertext, nonces, authentication tags, wrapped-key blobs, or local key material.

## Main GUI HSE2 entry smoke

The maintainer also reported that the main GUI entry path is normal:

```powershell
.\high-security-encryptor-gui.exe --smoke-test
.\high-security-encryptor-gui.exe
```

Observed result:

```text
主 GUI 入口正常
```

The main GUI `打开 HSE2 实验工具` entry successfully opened the HSE2 experimental window.

## Result

Maintainer-reported Windows EXE validation passed for alpha.7:

- CLI create -> inspect -> open round trip restored `hello alpha7`;
- standalone HSE2 GUI localized action label smoke passed;
- `检查 HSE2 元数据` showed the correct `.hse2` input-only field set;
- GUI inspect returned metadata-only summary output with exit code 0;
- main GUI HSE2 entry opened the HSE2 experimental window.

## Status

Windows EXE smoke validation for the alpha.7 HSE2 GUI localized-action path passed.
