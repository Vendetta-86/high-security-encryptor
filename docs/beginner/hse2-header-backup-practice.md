# 独立 HSE2 GUI：导出并演练 header backup

本练习先从一个完整的普通 HSE2 v2 归档导出 header backup，再只破坏该归档的临时副本头部，用 ZIP 内的 helper CLI 把备份头写入新副本。原归档和备份始终保留。

header backup 不是完整归档副本，也不包含口令、keyfile 或 DPAPI 解锁条件。它只适用于头部恢复；加密主体损坏或备份与主体不匹配时，校验会失败。备份包含可见的头部与恢复元数据，仍应妥善保管。

## 准备

1. 按[普通 HSE2 归档 GUI 练习](hse2-archive-practice.md)创建一个小型 v2 归档并确认它能完整校验。本练习继续使用同一个虚构样例和虚构口令。
2. 下载并解压 Windows ZIP。练习时使用可删除的桌面目录，例如 `HSE2-header-练习`。不要对唯一归档或真实资料执行下文的模拟损坏操作。

## 从 GUI 导出备份

1. 打开独立 HSE2 GUI，选择“导出 HSE2 header backup”。
2. “输入文件 / .hse2 容器”选择练习归档，例如 `练习.hse2`。
3. “输出文件”填写同一练习目录下的 `练习.hse2.header`。不要启用“允许覆盖输出文件”。
4. 运行并确认成功。将备份复制到练习目录之外的 `header-backup-副本` 目录。真实使用时应放在与归档分开的安全位置，并确认副本可读。

## 只损坏归档副本的头部

以下 PowerShell 命令只复制并修改临时副本的第一个字节，用来模拟头部标识损坏；它不会改动原归档：

```powershell
$base = Join-Path $HOME "Desktop\HSE2-header-练习"
Copy-Item (Join-Path $base "练习.hse2") (Join-Path $base "损坏副本.hse2")
$copyPath = Join-Path $base "损坏副本.hse2"
$bytes = [System.IO.File]::ReadAllBytes($copyPath)
$bytes[0] = $bytes[0] -bxor 1
[System.IO.File]::WriteAllBytes($copyPath, $bytes)
```

如果样例文件名或目录不同，请先调整命令中的名称。确认当前路径是桌面练习目录；不要对原归档运行这些命令。

## 用 ZIP 中的 helper CLI 恢复到新归档

1. 在资源管理器中打开解压后的 Windows ZIP 目录，在地址栏输入 `powershell` 并按 Enter，确保 PowerShell 当前目录就是 ZIP 解压目录。
2. 执行下面命令。`$base` 使用上节设置的路径；如果你另开了 PowerShell 窗口，请先重新设置 `$base`。

```powershell
$backupExe = ".\high-security-encryptor-hse2-header-backup.exe"
& $backupExe restore --input (Join-Path $base "损坏副本.hse2") --backup (Join-Path $base "练习.hse2.header") --output (Join-Path $base "恢复.hse2")
```

3. 成功结果应包含 `container_written: true`、`body_digest_verified: true`，且输出 `恢复.hse2`。不要添加 `--no-verify-body-digest`，也不要在入门演练中手动指定 `--body-offset`。
4. 回到独立 HSE2 GUI，选择“完整校验 HSE2 归档”，输入 `恢复.hse2` 和创建归档时的同一个虚构口令。通过后再恢复到一个新的空目录，并核对文件内容。
5. 确认原归档、损坏副本、header backup 和恢复归档都仍存在。恢复成功只说明本次头部恢复、主体摘要校验和口令认证通过。

## 失败时怎么判断

- **备份文件不存在或扩展名错误：**确认文件名以 `.hse2.header` 结尾，并选择正确的练习副本。
- **主体摘要不匹配：**停止。备份与这个归档的加密主体可能不对应，或主体已损坏；不要关闭摘要校验来强行继续。
- **header 恢复成功但完整校验失败：**恢复头部不等于凭据可用。确认所用口令/keyfile/DPAPI 条件与这份归档匹配；保留所有副本。
- **helper EXE 找不到：**确认 PowerShell 当前目录是解压 ZIP 根目录，且目录中有 `high-security-encryptor-hse2-header-backup.exe`。

本练习仅演示备份头与加密主体匹配时的特定恢复路径。它不能修复任意数据损坏，不能找回丢失凭据，也不构成备份策略或恢复保证。
