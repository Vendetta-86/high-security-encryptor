# 独立 HSE2 GUI：临时体验 Windows DPAPI 解锁

本练习创建一个只由 Windows DPAPI 解锁的普通 HSE2 v2 归档，并在当前 Windows 用户下校验和恢复。DPAPI 使用 Windows 当前用户保护解锁材料；更换 Windows 用户、设备或重装系统后可能无法打开归档。

> 本练习只用于可删除的虚构样例，不适用于唯一副本或重要资料。练习中的 DPAPI-only 归档没有可移植的备用解锁方式。真实归档应另加并测试独立口令或 keyfile wrapper，再把副本放到另一位置。

## 1. 准备练习文件

在桌面创建 `HSE2-DPAPI-练习\待加密`，其中创建 `说明.txt` 并写入 `DPAPI current-user practice`。练习目录中再预留 `恢复结果` 名称，但暂时不要创建该目录。

## 2. 创建 DPAPI 归档

1. 打开独立 HSE2 GUI，选择“创建 HSE2 归档”。
2. “要加密的文件夹”选择 `HSE2-DPAPI-练习\待加密`；“输出文件”填写练习目录下的新文件 `练习.hse2`。
3. 保留“容器格式版本”`2` 和“归档密码安全等级”默认值。
4. 勾选“新建归档使用 Windows DPAPI”。本练习的“归档密码（可选）”“确认归档密码”、密码文件和 keyfile 都留空；这个创建操作不支持同时添加口令或 keyfile wrapper。
5. 保留“创建后校验归档（不写出明文）”，运行并确认成功。仔细阅读界面出现的 DPAPI 可移植性警告。

## 3. 在同一 Windows 用户下完整校验

1. 选择“完整校验 HSE2 归档”，输入 `练习.hse2`。
2. 勾选“允许 DPAPI 解锁 wrapper”，不填写密码或 keyfile，运行。
3. 成功表示这台 Windows 上当前用户可以认证这份归档；校验不会写出明文。

## 4. 在同一 Windows 用户下恢复

1. 选择“解密并打开 HSE2 归档”，输入同一 `练习.hse2`。
2. 输出目录填写尚不存在的 `HSE2-DPAPI-练习\恢复结果`，勾选“允许 DPAPI 解锁 wrapper”。
3. 保留“打开前完整校验归档”，不启用覆盖，然后运行。
4. 打开恢复结果中的 `待加密\说明.txt`，确认内容为 `DPAPI current-user practice`。原文和 `.hse2` 归档应仍存在。

## 理解范围与恢复限制

- DPAPI wrapper 把归档解锁能力绑定到 Windows 用户环境；仅仅复制 `.hse2` 文件不保证能在另一账户或设备上使用。
- “允许 DPAPI 解锁 wrapper”是告诉程序尝试调用本机 DPAPI，不会把当前凭据导出成可迁移密码。
- 这个演练没有模拟更换用户、重装 Windows 或更换设备，因为那会超出临时目录测试范围。不要通过在真实账户上更改 Windows 设置来验证迁移限制。
- 归档创建后，可以用 wrapper 管理操作增加独立口令或 keyfile 解锁方式；必须在归档副本上另行练习，并实际测试备用方式可用后，才考虑把 DPAPI-only 归档用于真实资料。
- DPAPI 保护 keyfile 的“Windows DPAPI 保护 keyfile”动作是另一个功能；其 blob/provider 流程见[DPAPI keyfile 练习](hse2-dpapi-keyfile-practice.md)，与本练习的归档 wrapper 不同。

完成后确认目录中无须保留的文件，再删除整个临时练习目录。
