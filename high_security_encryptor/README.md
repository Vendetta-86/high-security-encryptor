# High Security Encryptor

独立的新项目，用于验证面向高价值数据场景的本地加密工具设计。

**当前能力**
- 已实现流式文件加密格式
- 已兼容旧版 `GCM1` 解密
- 已实现批次绑定、加密 sidecar 与批量/文件夹工作流
- 已实现混合批量解密、文件夹自动续解密与条目集合完整性校验
- 已实现 JSON 配置驱动的 CLI
- 已实现 provider 化密码来源：`literal`、`env`、`prompt`、`file`、`command`
- 已实现运行时模板密码计划，可在不保存密码表的情况下完成解密

**CLI**

```bash
python -m high_security_encryptor encrypt-batch --config path/to/encrypt.json
python -m high_security_encryptor decrypt-batch --config path/to/decrypt.json
python -m high_security_encryptor init-example --mode hardened --kind decrypt --output path/to/example.json
python -m high_security_encryptor init-example --mode compatible --kind encrypt --print
python -m high_security_encryptor validate-config --kind encrypt --config path/to/config.json
python -m high_security_encryptor validate-config --kind decrypt --config path/to/config.json --strict
python -m high_security_encryptor init-example --mode hardened --kind decrypt --print --set output_dir=D:/secure-out
```

CLI 采用配置文件驱动，是因为文件夹内部密码、运行时 provider、模板密码计划这类嵌套结构，用 JSON 表达比命令行长参数更稳定。

**密码来源**

密码字段支持以下几种形式：

```json
"metadata_password": "direct-password"
"metadata_password": {"type": "env", "name": "HSE_METADATA_PASSWORD"}
"metadata_password": {"type": "prompt", "prompt": "Metadata password: "}
"metadata_password": {"type": "file", "path": "C:/secrets/metadata.txt"}
"metadata_password": {"type": "command", "argv": ["python", "-c", "print('secret')"]}
```

`command` provider 只接受显式 `argv` 数组，不经过 shell，这样更容易控制安全边界。

**不落盘密码表**

顶层批量解密现在可以只依赖：
- `manifest`
- `template`
- 运行时 provider

而不必长期保存顶层密码表。

这个模式也已经延伸到文件夹内部续解密：如果外层包里有独立 `.hse` 文件，内部密码表也可以不保存，只保留内部模板，再通过运行时 provider 注入密码。

**生成端开关**

加密时可以关闭密码表 sidecar：

- `write_password_table: false`
  含义：不生成顶层 `batch_password_table.hsm`
- `write_internal_password_tables: false`
  含义：不生成文件夹内部 `batch_password_table.hsm`

这样可以运行在“只生成 manifest + template”的模式下。

**命名安全模式**

目前支持三种命名安全模式：

- `compatible`
  含义：生成顶层密码表和内部密码表，兼容性最高
- `hardened`
  含义：不生成顶层密码表，但保留文件夹内部密码表
- `no-password-tables`
  含义：顶层和文件夹内部都不生成密码表，完全依赖运行时 provider

如果配置里同时显式给了 `write_password_table` 或 `write_internal_password_tables`，显式值会覆盖安全模式默认值。

对于解密配置，还要注意这条约束：

- `hardened`
- `no-password-tables`

这两种模式下不应再提供顶层 `password_table_path`，而应通过模板和运行时 provider 提供顶层密码。

**示例配置**

项目根目录的 [examples](D:/PycharmProjects/PythonProject1/high_security_encryptor/examples) 提供了 3 套官方示例：

- `compatible_*`
  含义：完全兼容模式，加密和解密都使用顶层密码表
- `hardened_*`
  含义：顶层不保存密码表，解密时通过模板与 provider 提供顶层密码
- `no_password_tables_*`
  含义：顶层与文件夹内部都不保存密码表，解密完全依赖模板与 provider

如果你不想手工复制 `examples/` 里的文件，可以直接用 `init-example` 命令生成对应模板。

**当前状态**

- 项目与旧工具完全分离
- 已有较完整的端到端测试覆盖
- 当前测试总数已达到 `72`
