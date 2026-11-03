# HSE2 命令行：创建、校验并恢复练习归档

本练习用 Windows PowerShell 和随项目安装的命令行工具，创建临时 v2 归档、完整校验、列出 wrapper、导出 header backup，然后恢复并比较 SHA-256。你可以使用 Windows ZIP 中的命令行程序，也可以从源码安装 Python 环境。

> 全程只用临时目录和虚构样例。不要把真实口令写进命令参数、PowerShell 历史记录或脚本。keyfile 是可直接解锁归档的秘密文件，应与归档分开放置并单独备份。

## 1. 选择命令行程序所在目录

如果使用 Windows ZIP，先把 ZIP 解压到一个新文件夹，再在该文件夹根目录打开 PowerShell。该目录中应能看到 `high-security-encryptor.exe` 和 `high-security-encryptor-hse2-create.exe`。设置：

```powershell
$HSE2Bin = $PWD.Path
```

如果使用源码，需要 Python 3.11 或更高版本。打开 PowerShell，将当前位置切换到项目根目录（能看到 `pyproject.toml` 的目录），运行：

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
$HSE2Bin = Join-Path $PWD ".venv\Scripts"
```

源码方式会在项目目录创建 Python 虚拟环境并安装本地项目。无论哪种方式，都先确认 `$HSE2Bin` 是包含本项目命令行程序的目录；找不到程序时，先检查解压位置或当前目录，不要改用网上来历不明的可执行文件。Windows ZIP 的解压说明见 [Windows ZIP 说明](../windows_exe.md)。

## 2. 建立只用于练习的目录

仍在刚才设置 `$HSE2Bin` 的同一个 PowerShell 窗口中运行：

```powershell
if (-not (Test-Path -LiteralPath (Join-Path $HSE2Bin "high-security-encryptor-hse2-create.exe"))) { throw "没有找到 HSE2 create 命令；请检查 `$HSE2Bin 路径" }
$HSE2Main = Join-Path $HSE2Bin "high-security-encryptor.exe"
$HSE2Create = Join-Path $HSE2Bin "high-security-encryptor-hse2-create.exe"
$HSE2Validate = Join-Path $HSE2Bin "high-security-encryptor-hse2-archive-validate.exe"
$HSE2Wrapper = Join-Path $HSE2Bin "high-security-encryptor-hse2-wrapper.exe"
$HSE2Backup = Join-Path $HSE2Bin "high-security-encryptor-hse2-header-backup.exe"
$HSE2Open = Join-Path $HSE2Bin "high-security-encryptor-hse2-open.exe"
$HSE2Practice = Join-Path $env:TEMP ("HSE2-CLI-Practice-" + [guid]::NewGuid().ToString("N"))
$HSE2Input = Join-Path $HSE2Practice "待加密"
$HSE2Keys = Join-Path $HSE2Practice "keys"
$HSE2Archives = Join-Path $HSE2Practice "archives"
$HSE2Backups = Join-Path $HSE2Practice "backups"
$HSE2Restored = Join-Path $HSE2Practice "恢复"
New-Item -ItemType Directory -Path $HSE2Input,$HSE2Keys,$HSE2Archives,$HSE2Backups,$HSE2Restored | Out-Null
Set-Content -LiteralPath (Join-Path $HSE2Input "练习.txt") -Value "HSE2 CLI practice sample" -Encoding utf8
$HSE2Key = Join-Path $HSE2Keys "practice.key"
$HSE2Archive = Join-Path $HSE2Archives "practice.hse2"
$HSE2HeaderBackup = Join-Path $HSE2Backups "practice.hse2.header"
```

`$HSE2Practice` 是本次随机生成的临时根目录；输入、keyfile、归档、备份和恢复结果放在不同子目录。先确认变量路径都指向该练习目录，再继续。这里分开子目录只是为了练习，不等于另一块磁盘或离线备份。

## 3. 生成 keyfile 并创建归档

```powershell
& $HSE2Main generate-keyfile --output $HSE2Key --size 32
if ($LASTEXITCODE -ne 0) { throw "keyfile 生成失败" }

& $HSE2Create --root $HSE2Input --output $HSE2Archive --keyfile $HSE2Key --validate-after-create
if ($LASTEXITCODE -ne 0) { throw "归档创建或创建后校验失败" }
```

keyfile 是随机生成的二进制解锁材料。创建成功结果应显示 `format_version: 2`、`wrapper_type: keyfile`，并在 `post_create_validation` 中显示 `ok: true`、`payload_authenticated: true`、`plaintext_written: false`。这里的校验会认证归档内容，但不写出明文。

`--root` 是要加密的文件或目录，`--output` 是新归档路径。第一次运行不要加 `--overwrite`；如果目标已存在，停下来确认路径，不要随手覆盖。

## 4. 单独完整校验、检查 wrapper 并备份 header

```powershell
& $HSE2Validate --input $HSE2Archive --keyfile $HSE2Key
if ($LASTEXITCODE -ne 0) { throw "完整校验失败" }

& $HSE2Wrapper list --input $HSE2Archive
if ($LASTEXITCODE -ne 0) { throw "wrapper 列表读取失败" }

& $HSE2Backup export --input $HSE2Archive --output $HSE2HeaderBackup
if ($LASTEXITCODE -ne 0) { throw "header backup 导出失败" }
```

完整校验结果应包含 `ok: true`、`header_authenticated: true`、`manifest_authenticated: true` 和 `payload_authenticated: true`。wrapper 列表应显示一条 `type: keyfile` 记录，但不输出 keyfile 内容。header backup 保存归档头部元数据；它不是解锁因子，不能代替 keyfile。把它保存在独立备份位置，避免与唯一归档一起丢失。

## 5. 校验后恢复并比较文件

```powershell
& $HSE2Open --input $HSE2Archive --output-dir $HSE2Restored --keyfile $HSE2Key --validate-before-open
if ($LASTEXITCODE -ne 0) { throw "归档恢复失败" }

$HSE2OriginalFile = Join-Path $HSE2Input "练习.txt"
$HSE2RestoredFile = Join-Path (Join-Path $HSE2Restored "待加密") "练习.txt"
$HSE2OriginalHash = (Get-FileHash -LiteralPath $HSE2OriginalFile -Algorithm SHA256).Hash
$HSE2RestoredHash = (Get-FileHash -LiteralPath $HSE2RestoredFile -Algorithm SHA256).Hash
if ($HSE2OriginalHash -ne $HSE2RestoredHash) { throw "恢复文件 SHA-256 不匹配" }
Write-Output "PASS: 恢复文件 SHA-256 与练习源文件一致"
```

`--validate-before-open` 会先完整认证归档，再写恢复文件。最后一行 `PASS` 才表示本次练习文件的散列相同；它不构成独立审计或普遍安全结论。

## 密码来源和自动化注意事项

本练习使用 keyfile，所以口令没有出现在命令行中。其他入口的主要差别如下：

| 方式 | CLI 参数 | 需要理解的风险 |
|---|---|---|
| keyfile | `--keyfile <文件路径>` | 文件本身就是秘密；限制访问权限并独立备份。 |
| 密码文件 | `--password-file <文件路径>` | 文件以 UTF-8 保存口令；它不是加密保管库，需保护文件和备份。 |
| Windows DPAPI | `--dpapi` | 归档 wrapper 绑定当前 Windows 用户；账户或设备变化可能影响解锁，见 [DPAPI 归档练习](hse2-dpapi-practice.md)。 |

不要把 `--password`、真实口令或 keyfile 字节放进命令行参数、脚本源码或日志。本项目其他自动化入口提供标准输入选项；使用前查阅[完整 CLI 工作流说明](../hse2_cli_workflows.md)中的具体参数，不要假设所有命令支持相同的 stdin 格式。脚本应在每条外部命令后立即检查 `$LASTEXITCODE`，仅在为 `0` 时继续；失败时停止，不要把不完整输出当成成功归档。

完成后如需清理，先单独查看 `$HSE2Practice`，确认它仍指向刚才建立的随机临时目录；该目录里有练习明文、keyfile、归档和备份。确认不再需要后才删除。若不确定路径，先不要删除或继续任何会覆盖文件的命令。
