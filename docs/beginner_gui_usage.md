# 新手图形界面使用说明

这份说明面向第一次使用 High Security Encryptor 图形界面的用户。

## 推荐新手流程

### 只加密一个文件或文件夹

1. 打开 `high-security-encryptor-gui.exe`。
2. 使用“一键加密”。
3. 选择文件或文件夹。
4. 输入主加密密码。
5. 点击开始。

这种方式不需要手写 JSON 配置。

### 需要批量或高级配置

1. 打开 `examples/beginner_encrypt_config.json`。
2. 复制一份到自己的工作目录。
3. 修改里面的文件路径、输出目录和密码。
4. 回到 GUI，先用“检查配置”。
5. 检查通过后，在“文件加密”里选择这个 JSON 配置开始加密。

## 加密 JSON 示例

随包附带两个新手示例：

- `examples/beginner_encrypt_config.json`：单文件加密配置示例。
- `examples/beginner_multi_file_encrypt_config.json`：多文件加密配置示例。

示例里的路径和密码都必须改成自己的实际内容。

## 密码来源示例

图形界面不支持 `prompt` 密码来源。不要在 GUI 的批量任务里使用这种写法：

```json
{"type": "prompt", "prompt": "Password: "}
```

GUI 支持下面几种密码来源。

### 直接填写

适合新手测试和临时使用。密码会直接写在 JSON 文件里，请不要把这种配置文件发给别人。

```json
{
  "type": "literal",
  "value": "change-this-password"
}
```

### 环境变量

适合日常使用。JSON 里只保存环境变量名称，真正密码放在系统环境变量里。

```json
{
  "type": "env",
  "name": "HSE_FILE_PASSWORD"
}
```

PowerShell 示例：

```powershell
$env:HSE_FILE_PASSWORD = "your-real-password"
```

### 本地文件

适合脚本或批量任务。密码放在本地文本文件中，JSON 里只保存文件路径。

```json
{
  "type": "file",
  "path": "C:/Users/your-name/secrets/file_password.txt"
}
```

注意保护这个密码文件，不要和加密文件一起公开备份。

### 命令输出

适合高级用户。程序会运行命令，并把命令标准输出作为密码。

```json
{
  "type": "command",
  "argv": ["python", "C:/Users/your-name/scripts/get_password.py"]
}
```

命令 provider 不会调用 shell，但被调用的程序本身必须可信。

## 密码表/清单密码是什么

GUI 中的“密码表/清单密码”对应配置里的 `metadata_password`。

它不是单个文件的加密密码，而是用来保护批量任务产生的元数据文件，例如：

- `batch_password_table.hsm`
- `batch_manifest.hsm`
- `batch_template.hsm`

区别如下：

| 名称 | 作用 |
| --- | --- |
| 文件密码 | 保护具体文件内容 |
| 密码表/清单密码 | 保护批量任务的清单、模板和密码表 |

新手可以先让两者不同但都记住。高价值资料建议使用更强的密码，并避免长期保存明文密码。

## 密码表如何创建

如果使用 `compatible` 模式，程序会在加密时自动生成加密后的密码表文件。

示例配置：

```json
{
  "security_mode": "compatible",
  "metadata_password": {
    "type": "literal",
    "value": "change-this-metadata-password"
  },
  "password_table_path": "C:/Users/your-name/Documents/encrypted-output/batch_password_table.hsm",
  "manifest_path": "C:/Users/your-name/Documents/encrypted-output/batch_manifest.hsm",
  "template_path": "C:/Users/your-name/Documents/encrypted-output/batch_template.hsm"
}
```

加密完成后，`batch_password_table.hsm`、`batch_manifest.hsm` 和 `batch_template.hsm` 会由程序生成。解密时需要使用同一批次的这些文件。

## 文件夹内子文件单独加密示例

GUI 的多文件配置里，如果需要给某个文件夹内的子文件单独设置密码，使用格式：

```text
文件夹路径|子文件相对路径|密码
```

示例：

```text
D:/资料包|合同/合同正文.docx|contract-password
D:/资料包|身份证/正面.png|id-card-password
D:/资料包|财务/2026.xlsx|finance-password
```

含义：

- 左边：要打包的文件夹路径。
- 中间：这个文件夹内部的子文件相对路径。
- 右边：这个子文件单独使用的密码。

没有单独写出的子文件，会使用主加密密码。

## 不知道选哪个安全模式

| 目标 | 推荐模式 |
| --- | --- |
| 第一次学习流程 | `compatible` |
| 想减少长期保存的密码材料 | `hardened` |
| 高价值资料长期保存 | `no-password-tables` |

`compatible` 最容易上手，但会生成加密密码表。密码表仍然是敏感文件。

`no-password-tables` 更适合高价值资料，但要求你自己保存好密码来源、manifest 和 template。
