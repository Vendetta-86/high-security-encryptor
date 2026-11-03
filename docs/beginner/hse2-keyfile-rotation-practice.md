# 独立 HSE2 GUI：轮换单文件密文的 keyfile

本练习把一个 HSE2 配置式加密生成的单文件密文从旧 keyfile 重新包装到新 keyfile，并输出一个新文件。它不会覆盖原密文或删除 keyfile。

> **格式范围：**这里只能轮换通过 HSE2 GUI 的“加密配置”操作生成的 HSE2 单文件密文。不要把独立 GUI 的“创建 HSE2 归档”输出交给本轮换功能，即使它们都以 `.hse2` 结尾。

## 1. 准备隔离样例

在桌面创建 `HSE2-轮换练习`，其中放置 `keys` 和 `data` 两个文件夹。在 `data` 中创建 `原文.txt`，写入 `key rotation practice`。所有文件都使用临时虚构内容。

## 2. 生成两把练习 keyfile

1. 在独立 HSE2 GUI 选择“生成 keyfile”，分别保存到 `keys\old.key` 和 `keys\new.key`。
2. 每次都保留默认大小，确认不覆盖现有文件。
3. 将两把 keyfile 各复制一份到练习目录之外的 `keyfile-备份` 文件夹，并确认备份副本大小与对应原件相同。练习结束前保留全部 keyfile。

旧 keyfile 用于解锁原密文；新 keyfile 会用于新副本。不要把文件名改成相同，也不要用同一把 keyfile 代替新旧两把。

## 3. 用旧 keyfile 创建受支持的单文件密文

1. 使用应用提供的 HSE2 加密配置示例，复制一份为 `encrypt.json`。该练习配置的关键结构如下；请将三个 `C:/...` 路径替换为你桌面练习目录中的完整路径：

```json
{
  "input": "C:/.../HSE2-轮换练习/data/原文.txt",
  "output": "C:/.../HSE2-轮换练习/data/原密文.hse2",
  "wrapper": {
    "type": "keyfile",
    "path": "C:/.../HSE2-轮换练习/keys/old.key"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576
}
```

2. 打开独立 HSE2 GUI，选择“加密配置”，在“配置文件”中选择 `encrypt.json` 并运行。确认出现 `原密文.hse2`。
3. 记住：本练习的输入由“加密配置”生成；不要用“创建 HSE2 归档”来代替这一步。

## 4. 创建轮换配置并运行

在同一个练习目录创建 `rotate.json`，把以下路径都替换成桌面练习目录的完整路径：

```json
{
  "items": [
    {
      "input": "C:/.../HSE2-轮换练习/data/原密文.hse2",
      "output": "C:/.../HSE2-轮换练习/data/新密文.hse2"
    }
  ],
  "old_keyfile": "C:/.../HSE2-轮换练习/keys/old.key",
  "new_keyfile": "C:/.../HSE2-轮换练习/keys/new.key",
  "new_kdf_profile": "hardened",
  "continue_on_error": false
}
```

1. 再次检查 `input` 指向原密文，`output` 使用一个尚不存在的新名称。不要让两者相同，也不要打开覆盖选项。
2. 在独立 HSE2 GUI 选择“HSE2 keyfile 轮换”，选择 `rotate.json` 并运行。
3. 成功摘要应显示 `total: 1`、`succeeded: 1`、`failed: 0`，且生成 `新密文.hse2`。

## 5. 用新 keyfile 恢复并确认旧文件仍可用

1. 创建 `decrypt.json`，指向 `新密文.hse2`、新的恢复输出文件，以及 `keys\new.key`：

```json
{
  "input": "C:/.../HSE2-轮换练习/data/新密文.hse2",
  "output": "C:/.../HSE2-轮换练习/data/恢复.txt",
  "wrapper": {
    "type": "keyfile",
    "path": "C:/.../HSE2-轮换练习/keys/new.key"
  }
}
```

2. 在独立 HSE2 GUI 选择“解密配置”，选择 `decrypt.json` 并运行。
3. 对比 `恢复.txt` 与 `原文.txt`，确认内容完全相同。
4. 可再复制一份 `decrypt.json`，只把 wrapper 的 keyfile 路径改回 `old.key`，把输出改成新的空文件名，再运行。旧 keyfile 应能解锁未轮换的 `原密文.hse2`，不能作为新密文的解锁材料。
5. 确认原密文、新密文、两把 keyfile 和两份备份仍在。只有完成了新副本解锁验证之后，才可在真实工作流中考虑归档旧材料；本练习不删除任何文件。

## 错误处理

- **`HeaderError` 或格式错误：**先确认输入是“加密配置”生成的单文件 `.hse2`，而不是“创建 HSE2 归档”的容器。
- **`succeeded: 0` 或认证失败：**检查旧 keyfile 路径和原密文是否对应；不要删除或覆盖原文件。
- **输出已存在：**在 JSON 中换一个新输出名称，不要为练习启用覆盖。
- **新副本解不开：**保留所有输入和输出副本，重新检查新 keyfile 路径与轮换摘要；不要归档旧 keyfile。

完成后，可在确认目录内容无误的前提下删除整个临时练习目录。
