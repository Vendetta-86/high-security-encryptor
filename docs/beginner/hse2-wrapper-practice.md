# 独立 HSE2 GUI：查看、添加和移除解锁方式

本练习在一个可删除的 v2 样例归档上查看 wrapper、添加备用 keyfile，并在新副本上移除原 keyfile。每次修改都会写到新归档；原归档保留作回退。

> 只用临时样例和练习 keyfile。不要在唯一副本或重要归档上练习。添加备用方式后，必须先用新凭据成功校验和恢复，再考虑移除旧方式。不要运行“永久禁用 HSE2 访问”。

## 1. 准备

先完成[HSE2 keyfile GUI 练习](hse2-keyfile-practice.md)，保留其中的 `practice.hse2` 和 `practice.key`。在同一个练习目录新建 `新keyfile`、`新keyfile备份` 和 `修改后归档` 三个文件夹；在 `修改后归档` 中预留 `practice-with-backup.hse2` 和 `practice-backup-only.hse2` 两个新文件名。

在独立 HSE2 GUI 选择“生成 keyfile”，把输出写到 `新keyfile\backup.key`，保留默认大小。随后用文件资源管理器复制一份到 `新keyfile备份\backup.key`。不要把 keyfile 和归档放在同一个文件夹，也不要打开或编辑 keyfile 内容。

## 2. 查看当前解锁方式

1. 选择“列出 HSE2 wrapper”。
2. “输入文件 / .hse2 容器”选择 `practice.hse2`，运行。
3. 在结果中记下当前 wrapper 的 `id`、`type` 和 `label`。后续移除时必须使用准确的 `id`，不要凭记忆输入。

`wrapper` 是归档中描述一种解锁方式的记录，不是明文口令或 keyfile 内容。列表是归档元数据，仍可能暴露解锁方式、标签等信息；分享结果前检查并遮盖路径和敏感上下文。

## 3. 添加备用 keyfile

1. 选择“添加 HSE2 wrapper”。
2. 输入文件选择 `practice.hse2`；输出文件选择新的 `修改后归档\practice-with-backup.hse2`。输入和输出必须是不同文件。
3. “新 wrapper id”填写 `backup-keyfile-1`；“keyfile”选择原来的 `practice.key`。这个字段用于验证并解锁输入归档。
4. “新 keyfile”选择 `新keyfile\backup.key`。不要选择 DPAPI，也不要启用覆盖。
5. 阅读确认提示，确认输出是新文件后运行。成功时应生成归档副本。

这里的“现有 keyfile”和“新 keyfile”用途不同：前者证明你能解锁输入归档，后者会加入输出副本，供之后解锁。

## 4. 移除旧方式前先验证备用方式

1. 选择“列出 HSE2 wrapper”，输入 `practice-with-backup.hse2`。结果应包含原 `id` 和 `backup-keyfile-1`，wrapper 数量为 2。
2. 选择“完整校验 HSE2 归档”，输入 `practice-with-backup.hse2`，在“keyfile”选择 `新keyfile\backup.key` 并运行。目标是校验成功；此操作不写明文。
3. 再使用 `新keyfile备份\backup.key` 重做一次完整校验。只有备份副本也成功，才继续。

任一校验失败就停止；保留原归档、双 wrapper 归档和两个 keyfile，不要尝试移除 wrapper。

## 5. 在另一个副本中移除旧 wrapper

本步骤会让新输出副本不再接受旧 keyfile。原归档和双 wrapper 归档仍应保留。

1. 从“列出 HSE2 wrapper”的结果复制原 wrapper 的准确 `id`。
2. 选择“移除指定 HSE2 wrapper”。输入文件选择 `修改后归档\practice-with-backup.hse2`；输出文件选择新的 `修改后归档\practice-backup-only.hse2`。
3. “要移除的 wrapper id”填写刚才记录的原 `id`；“keyfile”选择已验证成功的 `新keyfile\backup.key`。
4. 不启用覆盖，阅读确认提示后运行。移除操作只写到新副本。

## 6. 验证结果

1. 用“列出 HSE2 wrapper”检查 `practice-backup-only.hse2`：应只剩 `backup-keyfile-1`。
2. 用 `新keyfile备份\backup.key` 对它执行“完整校验 HSE2 归档”，目标是成功。
3. 用 `新keyfile\backup.key` 打开归档到尚不存在的 `恢复结果` 文件夹，保留“打开前完整校验归档”。打开恢复出的 `待加密\练习.txt`，确认内容与前一练习一致。
4. 用旧的 `practice.key` 对 `practice-backup-only.hse2` 执行完整校验；预期认证失败。随后对原始 `practice.hse2` 使用同一个旧 keyfile 校验，预期成功。这说明移除只作用于新副本，原文件仍可用。

若结果与预期不同，停止并保留所有文件，不要覆盖任一归档。完成后确认没有需要保留的练习材料，再删除整个临时练习目录。

## 名词和范围

- **wrapper id**：标识归档内某条解锁记录的名称；移除时按列表中的准确值选择。
- **添加 wrapper**：验证一种现有解锁因子后，在输出归档副本中增加一种新的解锁方式。它不是 keyfile 备份操作；新 keyfile 仍须单独备份。
- **移除 wrapper**：验证仍可解锁归档后，在输出副本中删除指定解锁记录。若删掉最后一种可用方式，内容可能无法恢复；程序会拒绝移除最后一条 wrapper。
- 本练习只覆盖普通 HSE2 v2 归档上的 GUI list/add/remove。配置式单文件密文的 keyfile 轮换、DPAPI keyfile blob、[wrapper rewrap](hse2-wrapper-rewrap-practice.md) 和永久禁用访问是不同操作，不能互相替代。
