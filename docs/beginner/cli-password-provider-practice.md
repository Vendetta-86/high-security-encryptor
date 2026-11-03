# CLI 密码来源与自动化练习

本练习演示两件容易混淆的事：批量配置 JSON 如何引用密码来源，以及 HSE2 CLI 如何从重定向标准输入读取口令。练习只使用虚构密码和临时文件；不要把生产口令写进本练习脚本、命令行参数或 Git 仓库。

## 1. 先认清 JSON provider

**Provider（密码来源）**是 JSON 配置里的一条指示：程序运行时从哪里取得密码或解锁材料。配置通常保存来源描述，而非来源实际值：

```json
"metadata_password": {"type": "env", "name": "HSE_DEMO_METADATA_PASSWORD"},
"source_passwords": {
  "C:/practice/note.txt": {
    "type": "env",
    "name": "HSE_DEMO_FILE_PASSWORD"
  }
}
```

`metadata_password` 保护批次清单等辅助材料；`source_passwords` 按输入文件路径指定该文件的内容口令。程序读取环境变量后才执行任务。**配置检查不会执行加密，也不能证明运行时环境变量存在或值正确。**

| `type` | 程序怎样取值 | 主要限制 |
|---|---|---|
| `literal` | 从 JSON 的 `value` 读取明文 | 密码直接落在配置文件，不适合真实秘密。 |
| `env` | 从指定环境变量读取 | 变量值仍以明文存在于当前进程环境；这不是凭据保险库。 |
| `prompt` | 运行时隐藏提示 | 需要有人输入，不适合无人值守脚本。 |
| `file` | 读取 UTF-8 文本文件 | 通常是明文口令文件；保护文件权限、备份和生命周期。 |
| `command` | 启动明确的 `argv` 程序并读取其 stdout | 不调用 shell；只运行你审查过的命令。命令仍可能暴露秘密或执行其他操作。 |
| `keyfile` | 读取本地二进制 keyfile | keyfile 本身就是解锁材料；代码要求 16 字节至 1 MiB，并需单独备份。 |
| `dpapi` | 使用 Windows DPAPI 解开材料文件 | 谁能解密取决于 blob scope：`current_user` 通常绑定当前账户，`local_machine` 允许本机任何账户解密；两者都不是跨设备备份。见[scope 练习](dpapi-local-machine-practice.md)。 |

JSON provider 没有 `type: "stdin"`。HSE2 的 stdin 是各个 CLI 子命令提供的专用选项，输入行数和顺序由命令决定。

## 2. 用虚构环境变量创建一份练习密文

这段 PowerShell 会创建独立临时目录、源文本和 JSON 配置。变量值都是虚构练习密码，绝不能照搬成真实口令：

```powershell
$Practice = Join-Path $env:TEMP ("hse-provider-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Practice | Out-Null
$Source = Join-Path $Practice "note.txt"
$ConfigPath = Join-Path $Practice "encrypt.json"
$OutputDir = Join-Path $Practice "encrypted"
Set-Content -LiteralPath $Source -Value "Provider practice sample only" -Encoding utf8

$env:HSE_DEMO_FILE_PASSWORD = "FAKE-ONLY-file-password"
$env:HSE_DEMO_METADATA_PASSWORD = "FAKE-ONLY-metadata-password"
$Config = [ordered]@{
    sources = @($Source)
    source_passwords = @{ $Source = @{ type = "env"; name = "HSE_DEMO_FILE_PASSWORD" } }
    metadata_password = @{ type = "env"; name = "HSE_DEMO_METADATA_PASSWORD" }
    output_dir = $OutputDir
    batch_id = "beginner-provider-practice"
}
$Json = $Config | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($ConfigPath, $Json, [System.Text.UTF8Encoding]::new($false))
```

设置 `$HSE` 指向主 CLI：已安装的命令行程序可写 `$HSE = "high-security-encryptor"`；使用 Windows ZIP 时，在解压目录设为 `$HSE = (Resolve-Path .\high-security-encryptor.exe).Path`。

先检查配置。此命令只检查配置规则，不执行加密，也不会读取 `$env:HSE_DEMO_*` 的值：

```powershell
& $HSE validate-config --kind encrypt --config $ConfigPath
$Code = $LASTEXITCODE
if ($Code -ne 0) { throw "配置检查失败，退出码 $Code" }
```

然后才执行练习加密：

```powershell
$SummaryLines = & $HSE encrypt-batch --config $ConfigPath
$Code = $LASTEXITCODE
if ($Code -ne 0) { throw "加密练习失败，退出码 $Code" }
$Summary = ($SummaryLines -join "`n") | ConvertFrom-Json
if ($Summary.encrypted_files.Count -ne 1) { throw "结果文件数量不符合预期" }
if (-not (Test-Path -LiteralPath $Summary.encrypted_files[0])) { throw "加密结果不存在" }
"练习密文已生成：$($Summary.encrypted_files[0])"
```

成功时应有一项加密输出，文件存在；程序不会把这两条虚构口令作为摘要字段输出。完成后清除当前 PowerShell 会话中的虚构变量：

```powershell
Remove-Item Env:HSE_DEMO_FILE_PASSWORD, Env:HSE_DEMO_METADATA_PASSWORD -ErrorAction SilentlyContinue
```

## 3. 把配置报告交给脚本处理

`validate-config --report` 可生成结构化报告；`--output` 保存完整报告，`--summary-only` 只缩短终端摘要，不会缩短报告文件。报告可能含配置路径和问题详情，应按普通项目资料保护。

```powershell
$ReportPath = Join-Path $Practice "reports\validation.json"
& $HSE validate-config --kind encrypt --config $ConfigPath `
  --report --output $ReportPath --summary-only --exit-code-on-issues
$Code = $LASTEXITCODE
if ($Code -eq 2) { throw "报告发现阻断性问题，先读报告：$ReportPath" }
if ($Code -ne 0) { throw "检查命令无法完成，退出码 $Code" }
if (-not (Test-Path -LiteralPath $ReportPath)) { throw "报告文件没有生成" }
```

- `0`：没有被当前报告规则判定为阻断的问题。仍要查看报告中的 warning。
- `2`：启用 `--exit-code-on-issues` 后，配置无效或报告有 error；启用 `--warnings-as-errors` 时，warning 也会导致该结果。
- 其他非零值：命令无法完成，例如配置文件路径或 JSON 格式错误。不要把它当作“配置有问题但报告已完整生成”。

`--strict` 会增加配置检查规则；通过检查不代表真实输入文件、口令、权限、磁盘空间和完整任务都已验证。PowerShell 每次调用外部 CLI 后都要立即保存 `$LASTEXITCODE`；成功只检查最后那条命令。

## 4. HSE2 stdin：固定行数、固定顺序

HSE2 stdin 模式要求输入来自重定向管道或其他非终端输入。每行都必须非空，行数必须刚好匹配；终端交互仍应使用隐藏式密码提示。下面只列出当前支持的输入契约：

| 操作 | 选项 | 输入行顺序 |
|---|---|---|
| `v4-create`、`v5-create` | `--passwords-stdin` | Primary 密码、Primary 确认、Secondary 密码、Secondary 确认，共 4 行。 |
| `v4-open`、`v4-replace`、`v5-open`、`v5-verify`、`v5-preview`、`v5-replace` | `--password-stdin` | 当前所选视图密码，共 1 行。 |
| `v5-password-update` | `--passwords-stdin` | 当前密码、新密码、新密码确认，共 3 行。 |
| `v5-compact`、`v4-to-v5` | `--passwords-stdin` | Primary 密码、Secondary 密码，共 2 行。 |

以下是一个**只供练习**的 PowerShell 样例。先准备两个虚构文本文件 `$PrimaryFile`、`$SecondaryFile`，以及尚不存在的 `$Archive` 输出路径。值以 `FAKE-ONLY` 开头，不能替换为真实口令：

```powershell
$DemoLines = @(
    "FAKE-ONLY-primary"
    "FAKE-ONLY-primary"
    "FAKE-ONLY-secondary"
    "FAKE-ONLY-secondary"
)
$DemoLines | & $HSE hse2 v5-create --output $Archive `
  --primary-file "primary.txt=$PrimaryFile" `
  --secondary-file "secondary.txt=$SecondaryFile" `
  --passwords-stdin
$Code = $LASTEXITCODE
if ($Code -ne 0) { throw "v5 创建失败，退出码 $Code" }
```

成功条件：`$Archive` 已生成、退出码为 `0`，终端报告里没有上述口令。然后可以用 v5 双视图练习中的步骤分别验证两组视图。v5 仍是实验格式；stdin 只是输送口令的方式，不会改变它公开含有两个视图的事实，也不提供可否认性。

**真实自动化边界：**stdin 不会自动加密密码，也不会替你提供密钥保险库。生产脚本必须从已审核的凭据管理工具取得秘密并只传给本次进程；不要把口令写在 PowerShell 历史、脚本、环境共享日志、命令参数或 here-string 中。当前项目没有内置秘密管理器集成。

## 完成标准

- 能区分 JSON `env` provider 与 HSE2 命令的 `--password-stdin`；不会尝试配置不存在的 `type: "stdin"`。
- 知道 `validate-config` 是配置检查，不等于 provider 实际解析或加密成功。
- 能为所用子命令提供数量和顺序完全正确的非空 stdin 行，并在外部命令后立即检查 `$LASTEXITCODE`。
- 能解释验证报告文件可能包含什么信息、`0` 和 `2` 的区别，以及虚构练习口令不能用于真实数据。

相关概念见[术语索引](glossary.md)、[HSE2 CLI 工作流](../hse2_cli_workflows.md)和[v5 双视图练习](v5-practice.md)。
