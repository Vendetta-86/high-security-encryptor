# BitLocker To Go 恢复信息预检改进

**状态：已实现并通过本地自动化验证；真实设备行为未验证。**

## 改动

- 加密前检查恢复信息目录可写，并拒绝将恢复信息目录放在目标盘符所在卷。
- 按 Microsoft 文档所述的常见顺序，先添加恢复密码保护器、以独占创建方式写出恢复文件并 flush，再调用 `Enable-BitLocker`。
- 恢复文件创建失败时，不启动加密；尽力清理本次创建的部分文件和恢复保护器，并把清理失败写入错误信息。
- 不覆盖已有恢复文件。若 BitLocker 启动命令报错，保留已写出的恢复文件，并在错误中给出路径及检查卷状态的提示，避免把可能已部分开始的加密误当作可直接重试。
- 更新入门教程中原有的“先启动加密、后保存恢复文本”描述。

## 验证

- Windows PowerShell AST 语法解析通过。
- `tests.test_removable_bitlocker` 与 `tests.test_gui`：33 项通过。
- 全量 `unittest discover -s tests`：786 项通过、6 项跳过。
- `git diff --check` 通过。

## 限制

自动化测试不触碰实体卷，只检查命令封装、脚本操作次序及 GUI 结果。BitLocker 的实际策略行为、设备移除/掉电中断和真实恢复流程仍须在可擦除测试设备上单独实测；这不构成对生产数据盘的加密建议。

实现依据：[Microsoft Enable-BitLocker 文档](https://learn.microsoft.com/en-us/powershell/module/bitlocker/enable-bitlocker?view=windowsserver2025-ps)说明常见做法是先添加恢复密码保护器并保存，再启用 BitLocker。
