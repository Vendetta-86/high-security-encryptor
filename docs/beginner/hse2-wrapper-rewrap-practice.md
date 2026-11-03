# 独立 HSE2 GUI：更换归档解锁方式

本练习把临时 v2 归档中的一个 keyfile wrapper 换成另一个 keyfile，并把结果写到新归档副本。旧 keyfile 会继续解锁原归档，但不应再解锁被替换 wrapper 的输出副本。

> 只用可删除的练习归档和虚构 keyfile。不要覆盖源归档。先备份并验证新 keyfile，再执行更换；新凭据校验和恢复成功前，保留源归档及旧 keyfile。

## 1. 准备并记录现有 wrapper

先完成[HSE2 keyfile GUI 练习](hse2-keyfile-practice.md)，保留 `practice.hse2`、`practice.key` 和 keyfile 的可读备份。在练习目录另外创建 `替换keyfile`、`替换keyfile备份`、`更换后归档` 三个文件夹，并预留 `更换后归档\practice-rewrapped.hse2` 这个新文件名。

1. 用独立 HSE2 GUI 的“列出 HSE2 wrapper”查看 `practice.hse2`。
2. 记下现有 wrapper 的准确 `id` 和数量。本练习沿用 keyfile 练习中只有一个 wrapper 的归档。
3. 选择“生成 keyfile”，把新文件保存到 `替换keyfile\replacement.key`，保留默认大小；再复制到 `替换keyfile备份\replacement.key`。
4. 确认两个新 keyfile 文件都存在且大小相同。不要把它们与 `.hse2` 归档放在同一文件夹。

## 2. 用新 keyfile 替换 wrapper

1. 选择“更换 HSE2 wrapper”。
2. 输入文件选择 `practice.hse2`；输出文件填写新路径 `更换后归档\practice-rewrapped.hse2`，输入与输出必须不同。
3. “要替换的现有 wrapper id”填写第 1 节记录的旧 `id`。
4. “新 wrapper id”填写唯一名称 `rotated-keyfile-1`；“keyfile”选择旧的 `practice.key`，用它验证并解锁输入归档。
5. “新 keyfile”选择 `替换keyfile\replacement.key`。不要勾选新 wrapper 使用 DPAPI，不要启用覆盖。
6. 阅读确认提示，确认保留源归档且输出路径是新文件后运行。

更换会用新 wrapper 取代指定 id；本练习的单 wrapper 归档在输出副本中仍有一条 wrapper。新 id 必须不与归档内未替换的其他 id 冲突。此操作和配置式单文件密文的[HSE2 keyfile 轮换练习](hse2-keyfile-rotation-practice.md)是不同功能。

## 3. 验证新归档和恢复材料

1. 用“列出 HSE2 wrapper”查看 `practice-rewrapped.hse2`。wrapper 数量应为 1，id 应为 `rotated-keyfile-1`，类型应为 keyfile。
2. 用“完整校验 HSE2 归档”分别选择 `替换keyfile\replacement.key` 和 `替换keyfile备份\replacement.key`。两次都应成功，且不会写出明文。
3. 用新 keyfile 打开输出副本到尚不存在的 `恢复结果` 文件夹，保留打开前完整校验。打开恢复出的 `待加密\练习.txt`，核对内容与原练习相同。
4. 用旧 `practice.key` 对 `practice-rewrapped.hse2` 完整校验，预期认证失败；再用它校验原始 `practice.hse2`，预期成功。这样可确认旧档未被改写，而新副本已使用替换后的 wrapper。

若新 keyfile 或其备份任一无法校验，停止并保留所有归档与 keyfile，不要覆盖、移除其他 wrapper 或删除旧材料。

## 术语和限制

- **wrapper rewrap（重新包装）**：用已有解锁方式验证归档后，为指定 wrapper 写入新的解锁材料，并输出新归档。它不会把整个归档原地改写；旧输入文件仍保留。
- **旧 wrapper id / 新 wrapper id**：前者指定要替换的记录，后者是输出副本中这条新记录的标识；留空时 GUI 默认沿用旧 id。
- 本练习只覆盖普通 HSE2 v2 归档的 keyfile-to-keyfile 更换。口令策略、DPAPI wrapper、移除其他解锁方式以及永久禁用访问另有条件和风险，不在此练习范围内。
