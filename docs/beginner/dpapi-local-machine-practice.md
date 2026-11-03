# DPAPI local-machine scope：同机共享保护练习

本练习用 Windows CLI 把一份虚构的 32 字节练习材料保护成 DPAPI blob，并确认输出标注的范围。它不创建真实凭据，也不改变其他用户或系统配置。

## 先理解风险

- `current_user`（默认）通常要求同一 Windows 用户在同一台电脑上解密。
- `local_machine` 把保护范围绑定到这台电脑，而不是某一个账户。Microsoft 明确说明：在这台电脑上的任何用户都可以调用 DPAPI 解密该 blob。只有在你信任这台电脑上的每个用户、确实需要同机多账户访问时才考虑它。[CryptProtectData 文档](https://learn.microsoft.com/en-us/windows/desktop/api/Dpapi/nf-dpapi-cryptprotectdata)；[DataProtectionScope 文档](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope?view=netframework-4.8.1)
- Windows 文件权限仍会决定谁能读取 `.dpapi` 文件；但若其他账户能够读到一个 `local_machine` blob，DPAPI 范围本身不会把它限制回创建者账户。
- blob 绑定本机，不是跨电脑备份。重装 Windows、换电脑或丢失源材料时，不要假设能从 blob 恢复。
- `dpapi-protect` **不会删除或安全擦除输入文件**。DPAPI 保护只为输入内容另写一个 blob；本练习的输入只是公开的虚构样例。

## 1. 选择主 CLI

PowerShell 5.1 或更新版本中，使用已安装命令：

```powershell
$HSE = "high-security-encryptor"
```

如果你使用 Windows ZIP，在解压目录中改为：

```powershell
$HSE = (Resolve-Path .\high-security-encryptor.exe).Path
```

先确认 `$HSE` 指向本项目主 CLI；不要使用不明来源的同名程序。

## 2. 生成虚构样例材料并保护

下面的随机字节只用于本次练习。临时目录以随机标识创建，不要把真实 keyfile 或口令复制到本练习：

```powershell
$Practice = Join-Path $env:TEMP ("hse-dpapi-machine-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Practice | Out-Null
$InputPath = Join-Path $Practice "fake-material.bin"
$BlobPath = Join-Path $Practice "fake-material.dpapi"
$FakeMaterial = New-Object byte[] 32
$Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$Rng.GetBytes($FakeMaterial)
$Rng.Dispose()
[System.IO.File]::WriteAllBytes($InputPath, $FakeMaterial)

$SummaryLines = & $HSE dpapi-protect `
  --input $InputPath `
  --output $BlobPath `
  --scope local_machine
$Code = $LASTEXITCODE
if ($Code -ne 0) { throw "DPAPI protect failed, exit code $Code" }
$Summary = ($SummaryLines -join "`n") | ConvertFrom-Json
if ($Summary.scope -ne "local_machine") { throw "The output does not report local_machine scope" }
if (-not (Test-Path -LiteralPath $BlobPath)) { throw "The DPAPI blob was not created" }
if (-not (Test-Path -LiteralPath $InputPath)) { throw "Expected source sample is missing" }
if (-not ($Summary.recovery_warnings -match "任何用户")) { throw "Expected shared-machine warning was not reported" }
"练习 blob 已创建：$BlobPath"
```

成功时，CLI 的 JSON 摘要会报告 `scope` 为 `local_machine` 和输出路径；标准错误会显示可移植性及同机共享警告；原始虚构输入仍保留。若脚本使用 PowerShell 旧版且 `[RandomNumberGenerator]::Create()` 调用失败，可停止本练习并记录错误，不要改用真实密钥材料。

## 3. 怎么理解结果

| 对象 | 结果 |
|---|---|
| `fake-material.bin` | 本练习的源材料；DPAPI 命令不删除它。 |
| `fake-material.dpapi` | 包含 DPAPI 保护内容的 blob；能否解密由 Windows scope 决定。 |
| `scope: local_machine` | 当前电脑上的任何账户都可能解密；不表示可在其他电脑打开。 |

项目已有 Windows 自动化测试会以临时虚构材料运行 `dpapi-protect --scope local_machine`，验证 CLI 返回范围、显示共享机器风险，并能在当前测试账户解开 blob。它没有切换到另一 Windows 账户；“同机任何账户可解密”的边界依据 Microsoft API 文档。不要为了演示而把真实秘密交给其他账户。

## 4. 什么时候不该用

- 只有一个 Windows 用户需要访问材料时，保留默认 `current_user`。
- 电脑由多人共用、存在不受信任账户或服务时，不要用 `local_machine` 作为账户隔离手段。
- 需要跨机器迁移或长期恢复时，另建经过验证的、独立保管的恢复材料；DPAPI blob 本身不满足该需求。
- 使用 `local_machine` 的 blob 也应放在受限 ACL 目录。NTFS ACL 限制文件读取者；它不会把 DPAPI blob 改回用户 scope。

更完整的 DPAPI keyfile 与 HSE2 配置式加解密流程见[DPAPI keyfile 练习](hse2-dpapi-keyfile-practice.md)。该练习默认选择 `current_user`；如需理解 `local_machine`，请把本页的风险作为前置条件，并且只用可删除的临时资料。

## 完成标准

- 能说明 `current_user` 与 `local_machine` 的区别，并知道后者允许同机账户解密。
- 能使用临时虚构材料运行 `dpapi-protect`，核对 JSON 摘要的 `scope`、blob 路径和标准错误警告。
- 知道输入源不会被删除、文件 ACL 仍需保护，且 blob 不是跨设备备份。

完成后先检查 `$Practice` 的完整路径，确认其中没有需要保留的数据，再删除该随机临时目录。
