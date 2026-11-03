# v5 维护练习：更换口令、替换视图、compact 和迁移

- **预计时间：**约 30 分钟
- **适用对象：**已完成 [v5 创建、校验和恢复练习](v5-practice.md) 的用户
- **需要准备：**从 Windows ZIP 解压出的 `high-security-encryptor.exe`，以及 PowerShell
- **练习数据：**本教程会在 `%TEMP%` 下生成虚构文本、口令和归档；不读取真实资料

本练习使用 Windows ZIP 中的命令行程序，体验四种不同的维护操作。所有命令都在现有归档旁边创建新文件；练习中不使用 `--force`，也不覆盖旧档。

> **实验格式提示：**v5 是实验性格式，双视图是公开设计，不提供也不承诺隐藏数据、可否认性、抗胁迫或反取证。请使用两组不同的虚构口令，不把唯一副本放在实验归档中。`compact` 不会安全擦除原归档、旧副本、快照或 SSD 上的残留数据。

## 1. 准备独立练习目录

先在 PowerShell 中进入解压后的 ZIP 根目录；该目录应能看到 `high-security-encryptor.exe`。

```powershell
$HSE2 = Join-Path $PWD "high-security-encryptor.exe"
if (-not (Test-Path -LiteralPath $HSE2)) { throw "当前目录没有 high-security-encryptor.exe；请先进入 ZIP 解压目录" }

$PracticeRoot = Join-Path $env:TEMP ("HSE2-v5-maintenance-" + [guid]::NewGuid().ToString("N"))
$InputDir = Join-Path $PracticeRoot "input"
$OutputDir = Join-Path $PracticeRoot "output"
New-Item -ItemType Directory -Path $InputDir,$OutputDir | Out-Null

$PrimaryFile = Join-Path $InputDir "primary.txt"
$SecondaryFile = Join-Path $InputDir "secondary.txt"
$ReplacementFile = Join-Path $InputDir "primary-updated.txt"
$LegacyPrimaryFile = Join-Path $InputDir "legacy-primary.txt"
$LegacySecondaryFile = Join-Path $InputDir "legacy-secondary.txt"
Set-Content -LiteralPath $PrimaryFile -Value "Primary view before replacement" -NoNewline
Set-Content -LiteralPath $SecondaryFile -Value "Secondary view stays unchanged" -NoNewline
Set-Content -LiteralPath $ReplacementFile -Value "Primary view after replacement" -NoNewline
Set-Content -LiteralPath $LegacyPrimaryFile -Value "Legacy v4 primary sample" -NoNewline
Set-Content -LiteralPath $LegacySecondaryFile -Value "Legacy v4 secondary sample" -NoNewline

$OriginalV5 = Join-Path $OutputDir "original-v5.hse2"
$UpdatedV5 = Join-Path $OutputDir "password-updated-v5.hse2"
$ReplacedV5 = Join-Path $OutputDir "view-replaced-v5.hse2"
$CompactedV5 = Join-Path $OutputDir "compacted-v5.hse2"
$LegacyV4 = Join-Path $OutputDir "legacy-v4.hse2"
$MigratedV5 = Join-Path $OutputDir "migrated-v5.hse2"
```

确认 `$PracticeRoot` 位于临时目录，且你没有把练习输出指向真实归档。

## 2. 创建练习用 v5 归档

```powershell
& $HSE2 hse2 v5-create `
  --output $OriginalV5 `
  --profile compatible `
  --primary-file "primary.txt=$PrimaryFile" `
  --secondary-file "secondary.txt=$SecondaryFile"
if ($LASTEXITCODE -ne 0) { throw "v5-create 失败：$LASTEXITCODE" }
```

程序会隐藏输入的口令。按提示输入 primary 口令两次，再输入另一组 secondary 口令两次。记住每个口令对应哪个视图。输入确认后，检查 `$OriginalV5` 已生成；两个原始样例仍在 `$InputDir`。

## 3. 只更换 primary 视图口令

```powershell
& $HSE2 hse2 v5-password-update --input $OriginalV5 --output $UpdatedV5
if ($LASTEXITCODE -ne 0) { throw "v5-password-update 失败：$LASTEXITCODE" }
```

按提示输入当前 primary 口令，再输入并确认新的 primary 口令。新口令必须不同于 secondary 口令。该操作只询问所选视图，无法替你检查两组口令是否相同。

用新旧口令分别检查副本和原档：

```powershell
& $HSE2 hse2 v5-verify --input $UpdatedV5
if ($LASTEXITCODE -ne 0) { throw "更新后的 primary 校验失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-verify --input $UpdatedV5
if ($LASTEXITCODE -ne 0) { throw "更新后的 secondary 校验失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-verify --input $OriginalV5
if ($LASTEXITCODE -ne 0) { throw "原档 primary 校验失败：$LASTEXITCODE" }
```

三次提示依次输入：更新后的 primary 口令、原 secondary 口令、原 primary 口令。成功表示新副本接受新 primary 口令，secondary 仍可用，而原档仍接受旧 primary 口令。更新不会改写原档或其备份。

## 4. 替换 primary 视图的内容

```powershell
& $HSE2 hse2 v5-replace `
  --input $UpdatedV5 `
  --output $ReplacedV5 `
  --file "primary.txt=$ReplacementFile"
if ($LASTEXITCODE -ne 0) { throw "v5-replace 失败：$LASTEXITCODE" }
```

按提示输入更新后的 primary 口令。此示例把 primary 视图的文件清单整体设为一个新文件；若要让该视图保留多个文件，应为每个文件重复添加 `--file "归档内相对路径=本机源文件路径"`。secondary 视图不会被这一步替换。

分别把两个视图恢复到全新的目录，再比较 SHA-256：

```powershell
$PrimaryCheck = Join-Path $OutputDir "check-primary"
$SecondaryCheck = Join-Path $OutputDir "check-secondary"
& $HSE2 hse2 v5-open --input $ReplacedV5 --output-dir $PrimaryCheck
if ($LASTEXITCODE -ne 0) { throw "替换后 primary 恢复失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-open --input $ReplacedV5 --output-dir $SecondaryCheck
if ($LASTEXITCODE -ne 0) { throw "替换后 secondary 恢复失败：$LASTEXITCODE" }
if ((Get-FileHash (Join-Path $PrimaryCheck "primary.txt")).Hash -ne (Get-FileHash $ReplacementFile).Hash) { throw "primary 内容与替换样例不一致" }
if ((Get-FileHash (Join-Path $SecondaryCheck "secondary.txt")).Hash -ne (Get-FileHash $SecondaryFile).Hash) { throw "secondary 内容与原样例不一致" }
```

第一次恢复输入更新后的 primary 口令；第二次输入原 secondary 口令。两次都应成功，并分别与对应样例哈希一致。若密码或校验失败，停止并保留三个归档和输入样例。

## 5. 用 compact 重建当前活动内容

```powershell
& $HSE2 hse2 v5-compact `
  --input $ReplacedV5 `
  --output $CompactedV5 `
  --profile compatible
if ($LASTEXITCODE -ne 0) { throw "v5-compact 失败：$LASTEXITCODE" }
```

按提示输入当前 primary 和 secondary 口令。compact 读取两个视图，只把当前仍活动的内容写入新归档；这可清理**新副本内部**因多次替换留下的过期记录。它保留输入 `$ReplacedV5`，不会从磁盘安全擦除旧记录。

分别校验并恢复 compact 输出到两个新的空目录：

```powershell
$CompactedPrimaryCheck = Join-Path $OutputDir "compact-primary"
$CompactedSecondaryCheck = Join-Path $OutputDir "compact-secondary"
& $HSE2 hse2 v5-verify --input $CompactedV5
if ($LASTEXITCODE -ne 0) { throw "compact 后 primary 校验失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-verify --input $CompactedV5
if ($LASTEXITCODE -ne 0) { throw "compact 后 secondary 校验失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-open --input $CompactedV5 --output-dir $CompactedPrimaryCheck
if ($LASTEXITCODE -ne 0) { throw "compact 后 primary 恢复失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-open --input $CompactedV5 --output-dir $CompactedSecondaryCheck
if ($LASTEXITCODE -ne 0) { throw "compact 后 secondary 恢复失败：$LASTEXITCODE" }
if ((Get-FileHash (Join-Path $CompactedPrimaryCheck "primary.txt")).Hash -ne (Get-FileHash $ReplacementFile).Hash) { throw "compact 后 primary 内容不一致" }
if ((Get-FileHash (Join-Path $CompactedSecondaryCheck "secondary.txt")).Hash -ne (Get-FileHash $SecondaryFile).Hash) { throw "compact 后 secondary 内容不一致" }
```

依次输入当前 primary、secondary 口令；两视图的文件内容都应与替换后的当前版本一致。compact 的目的在于整理活动记录；文件少、没有过期记录时，输出不一定更小。

## 6. 把 v4 归档导出到新的 v5

先从虚构样例创建一个小型 v4 来源：

```powershell
& $HSE2 hse2 v4-create `
  --output $LegacyV4 `
  --capacity-records 2 `
  --primary-file "primary.txt=$LegacyPrimaryFile" `
  --secondary-file "secondary.txt=$LegacySecondaryFile"
if ($LASTEXITCODE -ne 0) { throw "v4-create 失败：$LASTEXITCODE" }
```

按提示为两个视图分别输入并确认不同的虚构口令。然后创建新的 v5 归档：

```powershell
& $HSE2 hse2 v4-to-v5 `
  --input $LegacyV4 `
  --output $MigratedV5 `
  --profile compatible
if ($LASTEXITCODE -ne 0) { throw "v4-to-v5 失败：$LASTEXITCODE" }
```

按提示输入旧 v4 的 primary 和 secondary 口令。迁移同时读取、验证两个 v4 视图，并将内容写入新的 v5 归档；它不原地转换 `$LegacyV4`。新 v5 继续使用这两组视图口令。运行以下命令验证并恢复两个视图：

```powershell
$MigratedPrimaryCheck = Join-Path $OutputDir "migrated-primary"
$MigratedSecondaryCheck = Join-Path $OutputDir "migrated-secondary"
& $HSE2 hse2 v5-verify --input $MigratedV5
if ($LASTEXITCODE -ne 0) { throw "迁移后 primary 校验失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-verify --input $MigratedV5
if ($LASTEXITCODE -ne 0) { throw "迁移后 secondary 校验失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-open --input $MigratedV5 --output-dir $MigratedPrimaryCheck
if ($LASTEXITCODE -ne 0) { throw "迁移后 primary 恢复失败：$LASTEXITCODE" }
& $HSE2 hse2 v5-open --input $MigratedV5 --output-dir $MigratedSecondaryCheck
if ($LASTEXITCODE -ne 0) { throw "迁移后 secondary 恢复失败：$LASTEXITCODE" }
if ((Get-FileHash (Join-Path $MigratedPrimaryCheck "primary.txt") -Algorithm SHA256).Hash -ne (Get-FileHash $LegacyPrimaryFile -Algorithm SHA256).Hash) { throw "迁移后 primary 与 v4 样例不一致" }
if ((Get-FileHash (Join-Path $MigratedSecondaryCheck "secondary.txt") -Algorithm SHA256).Hash -ne (Get-FileHash $LegacySecondaryFile -Algorithm SHA256).Hash) { throw "迁移后 secondary 与 v4 样例不一致" }
```

依次输入迁移后 primary、secondary 口令。两个恢复文件的 SHA-256 都应与原始 v4 输入相同。

只有在新 v5 的两个视图都能完整校验、恢复内容也与 v4 样例一致后，才可考虑如何保留旧 v4。不要在练习中删除它。

## 各操作会写什么

| 操作 | 输入 | 新输出 | 关键限制 |
|---|---|---|---|
| `v5-password-update` | 一个 v5 归档、所选视图旧口令 | 更新口令后的完整副本 | 原档仍用旧口令；此操作不检查新口令是否与另一视图相同。 |
| `v5-replace` | 一个 v5 归档、所选视图口令、该视图完整的新文件清单 | 内容替换后的副本 | 提供的 `--file` 项构成该视图新清单；另一视图保持可用。 |
| `v5-compact` | 一个 v5 归档、两组当前口令 | 仅含当前活动内容的新副本 | 可清理新文件中的过期记录；不等同于安全删除。 |
| `v4-to-v5` | 一个 v4 归档、两组视图口令 | 新 v5 副本 | v4 源文件保留；完成两个视图的校验与恢复核对后再处理旧档。 |

本教程所有目的路径都是不同的新文件或新目录；不要为了消除“已存在”错误而随意添加 `--force`。确认无需保留练习数据后，先核对 `$PracticeRoot` 确为本教程创建的 `%TEMP%` 子目录，再自行删除该目录。
