新手必看

第一次使用 High Security Encryptor：

1. 单个文件或文件夹加密：
   双击 high-security-encryptor-gui.exe，使用“一键加密”。
   这种方式不需要手写 JSON 配置。

2. 批量或高级加密：
   打开 examples 文件夹，复制 beginner_encrypt_config.json 或 beginner_multi_file_encrypt_config.json。
   把示例里的路径、输出目录和密码改成自己的实际内容。

3. 修改 JSON 后不要直接加密。
   先在图形界面里使用“检查配置”。
   检查通过后，再到“文件加密”里选择这个 JSON 开始加密。

4. 图形界面不支持 prompt 密码来源。
   请使用 literal、env、file 或 command 密码来源。
   具体示例见 docs/beginner_gui_usage.md。

5. 多文件加密时，“密码表/清单密码”就是 metadata_password。
   它用于保护 batch_password_table.hsm、batch_manifest.hsm、batch_template.hsm 等批量任务元数据。
   密码表会在 compatible 模式加密时由程序自动创建。

6. 文件夹内子文件单独加密格式：
   文件夹路径|子文件相对路径|密码

   示例：
   D:/资料包|合同/合同正文.docx|contract-password

更多说明见：docs/beginner_gui_usage.md
