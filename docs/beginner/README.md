# 零基础使用指南

这组指南按“先完成一次安全的本地练习，再逐项学习功能”的顺序编写。你不需要先懂密码学或命令行。每次操作前先看清输入、输出、密码和覆盖提示；练习只使用临时样例文件与虚构密码。

## 从这里开始

1. [第一次使用：加密、解密并核对一个练习文件](first-run.md)（约 10 分钟；需要 Windows 图形界面和一个可删除的文本文件）。
2. [术语索引](glossary.md)：按屏幕和文档中出现的词查含义、用途、程序的大致处理方式和限制。
3. [文件夹加密与恢复](folder-practice.md)：用快速使用将目录加密为 `.zip.hse`，再恢复到新目录。
4. [v5 双视图入门练习](v5-practice.md)：创建归档、分别完整校验两个视图、预览并恢复。
5. [批量加密与解密练习](batch-practice.md)：用 GUI 创建一个兼容模式批次并按配套材料恢复。
6. [单独文件口令与文件夹内口令练习](password-practice.md)：给指定文件和文件夹内文件设置不同口令，再恢复并核对。
7. [独立 .hse 批次练习](independent-batch.md)：检查 JSON、生成多个独立密文并通过批量配置恢复。
8. [生成并检查配置](config-practice.md)：生成 JSON 模板、认识字段，再用 GUI 检查且不执行任务。
9. [HSE2 归档 GUI 练习](hse2-archive-practice.md)：创建普通 v2 归档、完整校验、检查元数据并恢复核对。
10. [HSE2 keyfile GUI 练习](hse2-keyfile-practice.md)：生成 keyfile、用它创建归档、校验并恢复。
11. [HSE2 header backup 演练](hse2-header-backup-practice.md)：导出备份、模拟副本头部损坏并恢复到新归档。
12. [HSE2 keyfile 轮换练习](hse2-keyfile-rotation-practice.md)：为配置式加密单文件密文更换 keyfile 并验证新副本。
13. [HSE2 DPAPI 练习](hse2-dpapi-practice.md)：在当前 Windows 用户下创建、校验并恢复临时归档。
14. [HSE2 DPAPI keyfile 练习](hse2-dpapi-keyfile-practice.md)：保护单文件解锁材料，并通过 DPAPI provider 加密和解密。
15. [HSE2 wrapper 管理练习](hse2-wrapper-practice.md)：查看、添加备用 keyfile，并在新副本上移除旧 wrapper。
16. [HSE2 wrapper 更换练习](hse2-wrapper-rewrap-practice.md)：用新 keyfile 替换归档副本中的旧解锁方式。
17. [HSE2 永久禁用访问练习](hse2-access-destroy-practice.md)：只对可丢弃的 v2 样例生成禁用访问的新副本，并验证源档仍可用。
18. [HSE2 命令行练习](hse2-cli-practice.md)：在 Windows ZIP 或源码环境中创建、完整校验并恢复临时归档。
19. [图形界面使用说明](../beginner_gui_usage.md)：多文件配置、密码来源与安全模式。
20. [Windows ZIP 说明](../windows_exe.md)：下载、解压、运行及发布包内容。
21. [BitLocker To Go 可移动存储练习](bitlocker-removable-practice.md)：识别目标设备、理解恢复材料，并学习 GUI 的加密、解锁和上锁流程；实体设备操作需自行确认。
22. [CLI 密码来源与自动化练习](cli-password-provider-practice.md)：配置 JSON provider，练习报告和退出码，并学习 HSE2 stdin 的固定行协议。

## 功能教程地图

功能清单记录主 GUI、独立 HSE2 GUI、命令行和 Windows ZIP 的全部用户入口。教程正在按该清单逐项补齐；“已有深入说明”不等于已完成零基础跟练。

| 学习主题 | 当前入口 | 教程进度 |
|---|---|---|
| 主 GUI：单文件/文件夹加解密 | [第一次使用](first-run.md)、[文件夹练习](folder-practice.md)、[GUI 说明](../beginner_gui_usage.md) | 单文件与文件夹加解密及样例人工核对已提供；一般错误恢复仍待扩展 |
| 主 GUI：批量任务、配置检查、配置生成 | [批量练习](batch-practice.md)、[单独口令练习](password-practice.md)、[独立 .hse 批次练习](independent-batch.md)、[生成并检查配置](config-practice.md)、[GUI 说明](../beginner_gui_usage.md)、[功能清单](../progress/20261103-hse2-roadmap-3.0-phase3-feature-inventory.md) | 打包/独立批次、单独文件口令和文件夹内单独加密已有跟练；错误分支待补 |
| 主 GUI：BitLocker 可移动存储 | [BitLocker To Go 入门练习](bitlocker-removable-practice.md)、[功能清单](../progress/20261103-hse2-roadmap-3.0-phase3-feature-inventory.md) | 已写明设备辨认、加密选项、恢复文件、解锁/上锁和常见故障；未对真实设备启用 BitLocker |
| 独立 HSE2 GUI：归档创建、打开、校验、检查 | [HSE2 归档 GUI 练习](hse2-archive-practice.md)、[功能清单](../progress/20261103-hse2-roadmap-3.0-phase3-feature-inventory.md)、[HSE2 CLI 工作流](../hse2_cli_workflows.md) | 普通 v2 归档的创建、完整校验、元数据检查和恢复已提供独立样例跟练；其他授权方式和错误恢复仍待补 |
| 独立 HSE2 GUI：keyfile、DPAPI、wrapper、header backup | [HSE2 keyfile GUI 练习](hse2-keyfile-practice.md)、[HSE2 keyfile 轮换练习](hse2-keyfile-rotation-practice.md)、[HSE2 DPAPI 练习](hse2-dpapi-practice.md)、[DPAPI keyfile 练习](hse2-dpapi-keyfile-practice.md)、[HSE2 wrapper 管理练习](hse2-wrapper-practice.md)、[HSE2 wrapper 更换练习](hse2-wrapper-rewrap-practice.md)、[HSE2 永久禁用访问练习](hse2-access-destroy-practice.md)、[HSE2 header backup 演练](hse2-header-backup-practice.md)、[术语索引](glossary.md)、[功能清单](../progress/20261103-hse2-roadmap-3.0-phase3-feature-inventory.md) | keyfile 基础/轮换、DPAPI-only 归档、current-user DPAPI keyfile blob、wrapper list/add/remove/rewrap、隔离副本禁用访问和 header backup 导出/特定恢复已有练习；本次禁用访问已做 CLI 临时样例端到端验证，GUI 字段/动作通过自动化测试，未做桌面手动走查 |
| HSE2 v5 创建、完整校验、预览和恢复 | [v5 双视图练习](v5-practice.md) | 已提供隔离样例跟练；口令更新、替换、compact 和迁移待补 |
| HSE2 v4/v5 其他实验操作 | [术语索引](glossary.md)、[HSE2 CLI 工作流](../hse2_cli_workflows.md) | 待补隔离样例演练；v5 不承诺可否认性 |
| CLI、自动化、密码 provider | [HSE2 命令行练习](hse2-cli-practice.md)、[CLI 密码来源与自动化练习](cli-password-provider-practice.md)、[DPAPI keyfile 练习](hse2-dpapi-keyfile-practice.md)、[CLI 工作流](../hse2_cli_workflows.md) | 已覆盖 JSON 环境变量 provider、配置报告/退出码及 HSE2 固定行 stdin 协议；一般错误恢复仍待补 |

所有面向用户的功能入口及逐项教程状态见[阶段 3 功能清单](../progress/20261103-hse2-roadmap-3.0-phase3-feature-inventory.md)。该清单中的“待补”会在对应跟练教程实际完成并核对后更新，不以计划文字代替教程。

## 练习安全规则

- 使用临时目录和可删除的虚构资料，不要拿唯一副本或真实敏感资料练习。
- 练习口令必须是虚构口令，不要复用真实账户密码。
- 先确认解密目标目录和输出文件名。程序提示覆盖、替换、永久禁用访问或删除时，先停止并查阅对应教程。
- 本地校验结果只说明该次操作达到了对应检查条件，不构成独立密码学审计、认证或安全保证。
