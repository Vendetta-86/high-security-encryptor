# HSE2 v4 实验练习：创建、替换和恢复双视图

- **预计时间：**约 20 分钟
- **适用对象：**已完成 [HSE2 命令行练习](hse2-cli-practice.md) 的用户
- **需要准备：**Windows ZIP 中的 `high-security-encryptor.exe` 和 PowerShell
- **练习数据：**本教程会在 `%TEMP%` 下生成虚构文本、口令和 v4 归档

本教程练习实验性 HSE2 v4 的创建、单视图内容替换和恢复。请只处理可删除的样例，不要把 v4 当作新手默认格式或唯一备份。

> **实验格式提示：**v4 使用固定记录容量，两个视图各占总记录槽的一半；归档会预留完整容量，因此即使内容很少，文件也较大（命令帮助标出的最小文件约 130 MiB）。视图由两组口令分别解锁，但这不构成隐藏内容或可否认性保证。替换会写出新文件，保留来源归档。

## 1. 准备样例

在 PowerShell 中进入 ZIP 解压目录，并确认当前路径下有 `high-security-encryptor.exe`：

```powershell
$HSE2 = Join-Path $PWD "high-security-encryptor.exe"
if (-not (Test-Path -LiteralPath $HSE2)) { throw "请先进入 ZIP 解压目录" }

$PracticeRoot = Join-Path $env:TEMP ("HSE2-v4-practice-" + [guid]::NewGuid().ToString("N"))
$InputDir = Join-Path $PracticeRoot "input"
$OutputDir = Join-Path $PracticeRoot "output"
New-Item -ItemType Directory -Path $InputDir,$OutputDir | Out-Null

$PrimaryFile = Join-Path $InputDir "primary.txt"
$SecondaryFile = Join-Path $InputDir "secondary.txt"
$ReplacementFile = Join-Path $InputDir "primary-updated.txt"
Set-Content -LiteralPath $PrimaryFile -Value "v4 primary sample" -NoNewline
Set-Content -LiteralPath $SecondaryFile -Value "v4 secondary sample" -NoNewline
Set-Content -LiteralPath $ReplacementFile -Value "v4 primary replacement sample" -NoNewline

$Original = Join-Path $OutputDir "original-v4.hse2"
$Replaced = Join-Path $OutputDir "replaced-v4.hse2"
```

所有输入和输出都应位于新建的 `$PracticeRoot` 下面。练习口令使用两组不同的虚构口令，按程序提示输入，不要把真实口令写进命令。

## 2. 创建 v4 归档

```powershell
& $HSE2 hse2 v4-create `
  --output $Original `
  --capacity-records 4 `
  --primary-file "primary.txt=$PrimaryFile" `
  --secondary-file "secondary.txt=$SecondaryFile"
if ($LASTEXITCODE -ne 0) { throw "v4-create 失败：$LASTEXITCODE" }
```

按提示分别为 primary、secondary 输入并确认不同的虚构口令。`--capacity-records 4` 表示容器总共预留 4 个记录槽，每个视图分到 2 个；这是槽位总数，不是文件数或字节数。文件按固定大小的数据块占用记录槽。容量不足时命令会报错，不会自动扩展现有归档。

创建结束后检查 `$Original` 存在，且文件明显大于两个小文本样例。这是固定容量预留空间的结果。

## 3. 只替换 primary 视图

```powershell
& $HSE2 hse2 v4-replace `
  --input $Original `
  --output $Replaced `
  --file "primary.txt=$ReplacementFile"
if ($LASTEXITCODE -ne 0) { throw "v4-replace 失败：$LASTEXITCODE" }
```

输入 primary 口令。`--file` 指定替换后 primary 视图的完整文件清单；本例因此只保留一个名为 `primary.txt` 的文件。替换会产生 `$Replaced`，不会改写 `$Original`。secondary 视图不参与本次替换。

固定容量针对每个视图分别计算。替换时程序可复用原视图已经占用的槽位，因此同样大小的内容可以再次替换；若新内容需要的槽位超过该视图的上限，操作会失败。不要通过增加 `--capacity-records` 试图修改现有文件的容量；要使用更大容量，需另行创建容器并迁移内容。

## 4. 恢复两个视图并逐字节核对样例

为每个视图指定不同的空目录：

```powershell
$PrimaryCheck = Join-Path $OutputDir "check-primary"
$SecondaryCheck = Join-Path $OutputDir "check-secondary"
& $HSE2 hse2 v4-open --input $Replaced --output-dir $PrimaryCheck
if ($LASTEXITCODE -ne 0) { throw "恢复 primary 失败：$LASTEXITCODE" }
& $HSE2 hse2 v4-open --input $Replaced --output-dir $SecondaryCheck
if ($LASTEXITCODE -ne 0) { throw "恢复 secondary 失败：$LASTEXITCODE" }
if ((Get-FileHash (Join-Path $PrimaryCheck "primary.txt") -Algorithm SHA256).Hash -ne (Get-FileHash $ReplacementFile -Algorithm SHA256).Hash) { throw "primary 恢复内容不匹配" }
if ((Get-FileHash (Join-Path $SecondaryCheck "secondary.txt") -Algorithm SHA256).Hash -ne (Get-FileHash $SecondaryFile -Algorithm SHA256).Hash) { throw "secondary 恢复内容不匹配" }
```

第一次输入 primary 口令，第二次输入 secondary 口令。两条命令都应成功，最后两个哈希比较不应报错。检查原始归档也仍可打开：

```powershell
$OriginalCheck = Join-Path $OutputDir "check-original-primary"
& $HSE2 hse2 v4-open --input $Original --output-dir $OriginalCheck
if ($LASTEXITCODE -ne 0) { throw "原归档恢复失败：$LASTEXITCODE" }
if ((Get-FileHash (Join-Path $OriginalCheck "primary.txt") -Algorithm SHA256).Hash -ne (Get-FileHash $PrimaryFile -Algorithm SHA256).Hash) { throw "原归档内容不匹配" }
```

最后输入原 primary 口令。该检查应证明替换写出新副本，原始归档仍包含替换前的 primary 内容。

## v4 术语和限制

| 名词 | 本练习中的意思 | 限制 |
|---|---|---|
| 视图 | 由一组口令解锁的一套文件清单和内容 | 两组口令对应两套可读取的内容；不表示隐藏其中任何一套 |
| 固定记录容量 | 创建时预留给归档的加密数据槽总数 | 每个视图只能使用总槽位的一半；文件越大，所需槽位越多 |
| 记录槽 | 存放一个有界加密数据块的位置 | 当前归档不能动态增加容量；替换内容超过所选视图上限会失败 |
| `v4-replace` | 将指定口令选中的视图换成新文件清单，并写到新归档 | 输入归档仍保留；新副本不是安全擦除旧内容 |

如需同时保留替换前后版本，分别保存原归档和替换输出，并自行验证备份可恢复。完成后只有在确认 `$PracticeRoot` 是本教程创建的临时目录时，才删除它。
