# 独立 .hse 文件批次：检查配置、加密和批量解密

- **预计时间：**约 30 分钟
- **适用对象：**想分别得到多个 .hse 文件，并通过主 GUI 批量恢复的用户
- **需要准备：**主 GUI、两个可删除的文本文件、文本编辑器、临时练习目录
- **练习数据：**虚构内容和口令；不要使用真实敏感资料

本教程处理的是多个独立加密文件和它们配套的 manifest、加密密码表、template。它和[多文件打包练习](batch-practice.md)创建的单个 .zip.hse 归档是不同流程。

## 1. 准备文件并复制配置示例

1. 创建 HSE-独立批次练习 文件夹，并在其中创建 输入、密文、恢复 三个子文件夹。
2. 在 输入 中创建 a.txt 和 b.txt，分别写入不同的虚构内容。
3. 从发布包的 examples 文件夹复制 beginner_multi_file_encrypt_config.json 到练习文件夹，重命名为 encrypt.json。
4. 用文本编辑器打开 encrypt.json，按下面的表格改路径和密码；JSON 的引号、逗号和括号必须保留。

| 配置字段 | 填写内容 |
|---|---|
| sources | 输入\a.txt 与 输入\b.txt 的完整路径，各占一个数组项 |
| source_passwords | 两个完整源文件路径分别对应一个虚构文件口令 |
| metadata_password | 填另一个虚构口令，用于保护辅助文件 |
| output_dir | 密文 子文件夹 |
| manifest_output_path | 密文\batch_manifest.hsm |
| password_table_output_path | 密文\batch_password_table.hsm |
| template_output_path | 密文\batch_template.hsm |

本练习的示例显式设为 package_as_bundle=false，因此预期输出为两个单独的 .hse 文件，而不是一个 .zip.hse 包；write_password_table=true 会生成批量解密要用的密码表。

> 示例中使用 literal 明文口令，只能填虚构练习口令。真实任务请改用环境变量或受保护的本地密码文件，并保护配置文件。

## 2. 检查加密配置

1. 打开 high-security-encryptor-gui.exe，进入“检查配置”页签。
2. 将“配置用途”设为“加密配置”，选择刚编辑的 encrypt.json。
3. 点击“检查配置”。确认结果为有效；有错误时按报告提示修正 JSON、路径和安全模式。
4. 配置检查只验证设置是否符合规则，不会读取并加密文件。

## 3. 生成两个独立加密文件

1. 进入“文件加密”页签，在“运行已有配置”区域选择 encrypt.json。
2. 点击“开始加密”，等待日志报告完成。
3. 在“密文”目录确认生成 a.txt.hse、b.txt.hse 和三份指定的 .hsm 辅助文件。
4. 记录 manifest、密码表和 template 的路径。三个文件必须来自本次同一轮加密。

## 4. 创建并运行批量解密配置

1. 进入“文件解密”页签，再进入“多文件解密配置”。
2. 在“要解密的 .hse 文件”中点击“添加文件”，选择 a.txt.hse 和 b.txt.hse。
3. 分别选择本批次的 batch_manifest.hsm、batch_password_table.hsm 和 batch_template.hsm。
4. 在“密码表/清单密码”填写 encrypt.json 中 metadata_password 对应的练习口令。此处不需要重新输入 a.txt、b.txt 各自的文件口令；程序会从受保护的密码表中读取对应关系。
5. 将“输出目录”设为新的空目录 HSE-独立批次练习\恢复，将“密码表保存方式”设为“简单兼容：保存完整密码表”。
6. 在“配置保存到”选择 HSE-独立批次练习\decrypt.json，然后点击“生成并开始解密”。
7. GUI 会将刚输入的密码暂时放入当前进程环境并立即运行。decrypt.json 只记录环境变量名称；如果以后关闭程序再单独运行此 JSON，需要自行设置该变量。

**预期结果：**恢复目录生成 a.txt 和 b.txt。分别打开并与输入目录的原文件逐字核对。

## 常见错误

| 现象 | 含义和处理 |
|---|---|
| 配置检查提示 sources 或 source_passwords 缺失 | 示例文件与当前字段不匹配，或编辑时删改了字段；从随包更新版重新复制再填写。 |
| 密文目录只有一个 .zip.hse | package_as_bundle 被改为 true；本教程要求 false，单包流程见[打包练习](batch-practice.md)。 |
| manifest、密码表或 template 绑定检查失败 | 误用了其他批次的辅助文件；重新选择密文目录中同次加密产生的文件。 |
| 找不到对应文件密码 | 输入的 metadata_password 不匹配，或密码表不是同一批次；确认口令和配套关系。 |
| 恢复目录已有文件 | 选择一个全新的空目录，不要为继续练习而覆盖未知文件。 |

## 术语与操作区别

- **单独的 .hse 文件：**每个输入文件分别加密，批次辅助文件记录它们的清单、模板和口令对应关系。
- **metadata_password：**保护 manifest、template 和密码表；不是 a.txt、b.txt 的文件口令。
- **密码表：**解密批次时把每个密文文件映射到对应文件口令，因此恢复时需要同批次的密码表和 metadata_password。
- **检查配置：**只检查设置，不读写加密内容；配置通过后仍要执行加密。

更多安全模式和密码来源见[图形界面使用说明](../beginner_gui_usage.md)和[术语索引](glossary.md)。
