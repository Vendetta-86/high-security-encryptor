# 独立 HSE2 GUI：用 DPAPI 保护单文件解锁材料

本练习先生成普通 keyfile，再用 Windows DPAPI 把它保护为 `.dpapi` blob，最后让 HSE2 单文件配置通过 `dpapi` provider 加密和解密一个临时文本文件。它只适用于当前 Windows 用户，不等同于“创建 DPAPI 归档”。

> 只使用可删除的练习文件。DPAPI blob 不能当作跨用户、跨设备备份；不要用唯一 keyfile 或重要资料练习。练习会保留原 keyfile，以便说明 DPAPI 保护操作不会替你删除明文源文件。

## 1. 准备练习文件夹

在桌面创建 `HSE2-DPAPI-keyfile-练习`，并新建以下文件夹：

```text
HSE2-DPAPI-keyfile-练习/
├─ 明文/
├─ 原始keyfile/
├─ 原始keyfile备份/
├─ DPAPI保护blob/
├─ 密文/
├─ 配置/
└─ 恢复结果/
```

在 `明文` 中创建 `说明.txt`，写入 `DPAPI keyfile provider practice`。暂时不要在“恢复结果”中创建文件。

## 2. 生成 keyfile 并用 DPAPI 保护

1. 打开独立 HSE2 GUI，选择“生成 keyfile”，把输出保存为 `原始keyfile\practice.key`，保留默认大小，不启用覆盖。
2. 用文件资源管理器把 `practice.key` 复制到 `原始keyfile备份\practice.key`。练习中先保留原件和副本。
3. 在 GUI 选择“Windows DPAPI 保护 keyfile”。输入文件选择 `原始keyfile\practice.key`，输出文件填写新的 `DPAPI保护blob\practice.dpapi`。
4. “DPAPI scope”选择 `current_user`。不要选择 `local_machine`；本练习只验证当前 Windows 用户范围。
5. 阅读界面提示，确认目标是新的 `.dpapi` 文件且没有覆盖原始 keyfile，然后运行。出现警告时也检查范围和输出路径。

`.dpapi` 文件是由 Windows DPAPI 保护的数据 blob，不是另一份普通 keyfile。`dpapi-protect` 不会删除输入的 `.key` 文件。不要直接用 `keyfile` provider 指向 `.dpapi`；后面的配置要用 `type` 为 `dpapi` 的 provider。

## 3. 建立加密配置

本练习通过 JSON 配置调用 HSE2 单文件加密。配置使用绝对路径，避免 GUI 启动目录影响相对路径解析。

1. 在 `配置` 中新建 `encrypt.json`，复制下面模板。
2. 把 `C:/REPLACE/HSE2-DPAPI-keyfile-练习` 替换成练习目录的真实绝对路径。可从文件资源管理器地址栏复制目录路径，再把反斜杠改为 `/`；JSON 中的正斜杠无需转义。

```json
{
  "input": "C:/REPLACE/HSE2-DPAPI-keyfile-练习/明文/说明.txt",
  "output": "C:/REPLACE/HSE2-DPAPI-keyfile-练习/密文/说明.hse2",
  "wrapper": {
    "type": "dpapi",
    "path": "C:/REPLACE/HSE2-DPAPI-keyfile-练习/DPAPI保护blob/practice.dpapi"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576
}
```

确认 `input` 指向练习明文，`output` 指向尚不存在的密文，`path` 指向刚生成的 `.dpapi` 文件。JSON 文件里不要写口令或 keyfile 内容。

## 4. 加密并建立解密配置

1. 在独立 HSE2 GUI 选择“HSE2 加密配置”，配置文件选择 `配置\encrypt.json`，运行。成功后应出现 `密文\说明.hse2`。
2. 在 `配置` 中新建 `decrypt.json`，同样将根目录替换为练习目录的真实绝对路径：

```json
{
  "input": "C:/REPLACE/HSE2-DPAPI-keyfile-练习/密文/说明.hse2",
  "output": "C:/REPLACE/HSE2-DPAPI-keyfile-练习/恢复结果/说明.txt",
  "wrapper": {
    "type": "dpapi",
    "path": "C:/REPLACE/HSE2-DPAPI-keyfile-练习/DPAPI保护blob/practice.dpapi"
  }
}
```

3. 选择 GUI 的“HSE2 解密配置”，输入 `配置\decrypt.json` 并运行。
4. 打开 `恢复结果\说明.txt`，确认其内容与 `明文\说明.txt` 完全一致。原文、密文、`.dpapi` blob、原始 keyfile 和独立的原始 keyfile 备份都应仍存在。

## 5. 分清两种 DPAPI 用法

- **DPAPI keyfile blob**：先用“Windows DPAPI 保护 keyfile”产生 `.dpapi`，再由 JSON 中的 `{"type":"dpapi","path":"..."}` provider 解锁 HSE2 配置式单文件密文。
- **DPAPI archive wrapper**：在“创建 HSE2 归档”时勾选 DPAPI，或在归档副本上添加 DPAPI wrapper。它把归档访问方式与 Windows 环境绑定，不需要这里的 `.dpapi` keyfile blob。
- `current_user` 绑定当前 Windows 用户配置；更换用户、重装系统或换设备后可能无法解锁。另一份 `.dpapi` blob 不是可移植恢复副本。
- 真实使用时要自行决定如何保管原 keyfile 与 DPAPI blob。保护操作不做安全删除；普通删除也不保证从 SSD 或备份介质彻底擦除。
- 此练习采用 `current_user`，没有模拟其他 Windows 用户或设备；单独的[local-machine scope 练习](dpapi-local-machine-practice.md)说明同机账户共享边界。若加密或解密失败，保留全部练习材料并先核对 DPAPI scope、JSON 路径和文件是否存在。

完成后确认没有需要保留的练习材料，再删除整个临时练习目录。
