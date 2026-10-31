# HSE2 离线抗暴力破解升级计划书

- **项目**：`Vendetta-86/high-security-encryptor`
- **计划生成时间**：2026-06-07 22:01 Asia/Taipei
- **文档命名时间戳**：`20260607-2201`
- **当前状态**：P11 Windows EXE 本地验收完成；P12 第一段、第二段已合并；`v0.6.0-alpha.3` 发布准备进行中。
- **进度标记规则**：
  - `[x]` = 已完成 / 仓库中已有明确实现或文档基础
  - `[~]` = 进行中 / 已有部分基础，但仍需补齐正式流程
  - `[ ]` = 未开始
  - `[!]` = 高风险功能，默认不启用或延后

---

## 0. 总体目标

本次升级目标不是把项目改造成 VeraCrypt 替代品，而是把 `high-security-encryptor` 发展为：

> **文件级高安全加密容器 + 多 wrapper 密钥管理 + 强 KDF + keyfile / DPAPI + 显式密钥销毁 + 可验证恢复流程。**

重点解决实际使用中的问题：

1. 攻击者复制 `.hse/.hse2` 文件后进行离线暴力破解。
2. 用户密码过弱导致 Argon2id 也只能拖慢、不能阻止攻击。
3. 单一密码或单一密钥材料丢失后无法恢复。
4. sidecar、manifest、文件名、目录结构等元数据泄露。
5. nuke / duress 类功能容易误触，需要安全边界清晰。

---

## 1. 不做项

这些功能本轮不做，避免项目复杂度失控。

| 状态 | 功能 | 处理方式 | 原因 |
|---|---|---|---|
| [x] | 不做虚拟磁盘挂载 | 保留为非目标 | 会进入 VeraCrypt / 文件系统驱动复杂度 |
| [x] | 不做 Windows 文件系统驱动 | 保留为非目标 | 安全审计和维护成本过高 |
| [x] | 不做系统盘加密 | 交给 BitLocker / VeraCrypt | 项目定位是文件级加密 |
| [x] | 不承诺真隐藏卷 | 只做元数据最小化 | 文件加密器天然泄露文件数量、大小、时间戳等信息 |
| [x] | 不做默认 nuke 密码 | 改为显式 `access destroy` | 自动误触风险高 |
| [x] | 不承诺彻底安全删除明文 | 只做风险提示和临时目录控制 | SSD、缓存、影子副本、日志都可能保留痕迹 |

---

## 2. 当前已具备基础能力盘点

| 状态 | 能力 | 说明 |
|---|---|---|
| [x] | Python 项目基础 | 已有项目结构，可继续扩展 HSE2 模块 |
| [x] | CLI / GUI 基础 | 已有命令行、Tkinter GUI、HSE2 standalone GUI |
| [x] | 文件加密基础 | HSE1/HSE2 文件级加密路线已存在 |
| [x] | 文件夹加密基础 | HSE2 archive create/open 已覆盖文件夹归档闭环 |
| [x] | 批量处理基础 | 已有 batch / sidecar 工作流方向 |
| [x] | Argon2id KDF 路线 | 已有 compatible / hardened / paranoid profiles |
| [x] | HSE2 实验基础 | HSE2 create/open/header backup/wrapper/access/GUI 已形成 alpha 闭环 |
| [~] | DPAPI wrapper | create 阶段已有 DPAPI wrapper，仍需 add/remove 与风险提示正式化 |
| [x] | Keyfile 操作 | HSE2 create/open 支持 keyfile wrapper，GUI 有 keyfile 字段 |
| [~] | no-password-table 工作流 | keyfile-only 已可用，paranoid 策略仍需强制化 |
| [~] | brute-force guard | 本地尝试限制不等于离线抗破解；仍需文档化边界 |
| [~] | 文档基础 | CLI/GUI 文档已更新；正式 `docs/hse2_format.md` 仍缺 |

---

## 3. 里程碑总览

| 阶段 | 状态 | 名称 | 当前判断 |
|---|---|---|---|
| Phase 0 | [x] | 升级计划建立 | 本进度文档已建立 |
| Phase 1 | [~] | HSE2 格式冻结 | magic/version/header codec 已实现；正式格式文档未合并 |
| Phase 2 | [~] | DEK + Wrapper 架构 | DEK/MEK 与 wrapper 架构已实现；rewrap/正式文档仍需补齐 |
| Phase 3 | [x] | KDF Profiles 正式化 | 三档 profile 可由 CLI 选择；GUI 的 wrapper add/rewrap 流程提供中文档位及 paranoid 性能提示 |
| Phase 4 | [x] | Keyfile 双因子 | inspect、paranoid 双因子策略、丢失与同目录风险提示均已实现并验收 |
| Phase 5 | [x] | Header Backup | create 成功后推荐导出；GUI 常驻提示备份不能替代解锁因子；CLI/GUI 文案与恢复回归通过 |
| Phase 6 | [x] | Destroy Access | header backup 可在 v2/v3 wrapper 区域被 access destroy 清除后恢复旧 header，并重新解密原 payload |
| Phase 7 | [x] | DPAPI 正式化 | create/add/remove、current-user/local-machine 风险提示、独立恢复 wrapper 要求与可移植性文档均已覆盖并验收 |
| Phase 8 | [!] | Decoy / Duress | 继续延后 |
| Phase 9 | [x] | 元数据最小化 | 文件名仅存在于加密 manifest；v2/v3 可选末块 padding 与精确恢复通过验证 |
| Phase 10 | [~] | GUI / CLI 完整闭环 | 统一 inspect、validate、wrapper 管理与 access destroy 已接入；完整向导仍需补齐 |
| Phase 11 | [~] | 测试与发布 | v0.6.0-alpha.3 release-prep 已建立，待 CI/本地验收与发布 |

---

## 4. Phase 1：HSE2 格式冻结

### 待完成清单

- [x] `docs/hse2_format.md` 定义 v2/v3 格式及流式兼容边界
- [x] 明确 HSE2 magic：`HSE2`
- [x] 明确格式版本：`format_version = 2`
- [x] 明确 header 编码格式：canonical JSON
- [x] 明确 header 认证方式：`header_auth` / `header_auth_tag`
- [x] 明确 payload 加密方式：AES-256-GCM streaming chunks
- [x] 明确 manifest 默认加密策略
- [x] 明确 wrappers 数组结构
- [x] 明确向后兼容策略：HSE1 显式迁移到新 HSE2 输出；不原地转换既有容器

### 完成标准

- [x] `docs/hse2_format.md` 和 `docs/hse2_framing_reference.md` 已覆盖 v2/v3 framing；工作区改动仍待用户决定是否提交
- [x] HSE2 header schema 有模型和 codec 实现
- [x] 测试能读取 HSE2 header / container fixture
- [x] 旧 HSE1 路径未被破坏

---

## 5. Phase 2：DEK + Wrapper 架构

### 待完成清单

- [x] 每次加密随机生成 32-byte `DEK`
- [x] 每次加密随机生成 32-byte `MEK`
- [x] 每次加密生成 payload nonce / chunk index 派生材料
- [x] 每个 wrapper 独立生成 salt 和 nonce
- [x] wrapper 只保存加密后的 `DEK` / `MEK`
- [x] 支持同一容器多个 wrapper（测试中可追加并移除 wrapper）
- [x] 支持原子 rewrap：更换密码或 keyfile 时只替换 wrapper，不重加密 payload

### 完成标准

- [x] 密码 wrapper 能解开 DEK / MEK
- [x] 不同 wrapper 能解开同一组 DEK / MEK
- [x] 修改密码只改 wrapper，不重写 payload；v2/v3 body 字节保持不变
- [x] 篡改 wrapper / header 会认证失败

---

## 6. Phase 3：KDF Profiles 正式化

### 推荐参数

| 状态 | Profile | Argon2id 内存 | time_cost | parallelism | 用途 |
|---|---|---:|---:|---:|---|
| [x] | `compatible` | 64 MiB | 3 | 4 | 老机器兼容 |
| [x] | `hardened` | 256 MiB | 3 | 4 | 默认推荐 |
| [x] | `paranoid` | 1 GiB | 4 | 4 | 高价值、低频归档 |

### 待完成清单

- [x] 新增 KDF profile 模块
- [x] 新增 KDF profile 常量
- [x] 新增 profile 参数校验
- [x] 加密时把实际 KDF 参数写入 wrapper/header
- [x] 解密时以 header 参数为准，不依赖当前软件默认值
- [x] GUI 的 wrapper add/rewrap 使用中文安全等级，不直接暴露底层参数

### 完成标准

- [x] 三档 profile 均有实现
- [x] 参数被篡改会导致认证失败
- [x] wrapper add/rewrap 选择 `paranoid` 且设置新密码文件时显示明显 GUI 性能提示

---

## 7. Phase 4：Keyfile 双因子正式化

### 待完成清单

- [x] 新增 keyfile 生成命令 / GUI action
- [x] 新增 keyfile inspect 命令（定向 helper/CLI 测试 4/4 通过）
- [x] 支持 password + keyfile 联合派生 KEK
- [x] 支持 keyfile-only wrapper，但 GUI 默认不推荐
- [x] `paranoid` 模式强制要求 keyfile 或等价外部 wrapper（定向 policy/workflow/dry-run 测试 5/5 通过）
- [x] keyfile 丢失风险提示（威胁模型、GUI 常驻提示与 wrapper 确认已补；GUI tab 测试 25/25 通过并完成界面目视检查）
- [x] keyfile 与 `.hse2` 同目录时给出警告（create/open/wrapper CLI 与 GUI 提示已补；全量测试通过）

### 完成标准

- [x] 缺少 keyfile 时无法离线验证密码 / 解锁失败
- [x] 错 keyfile 明确失败
- [x] keyfile 生成使用安全随机数
- [x] GUI 完成 keyfile 生成 / 选择 / 风险提示闭环（现有生成/选择操作配合离线备份警告；GUI tab 25/25 通过并完成目视检查）

---

## 8. Phase 5：Header Backup

### 待完成清单

- [x] 新增 header export 命令
- [x] 新增 header restore 命令
- [x] 加密完成后提示导出 header backup（stderr 给出可复制命令，JSON 提供推荐路径与 argv；dry-run 不提示）
- [x] header backup 不包含明文 DEK / MEK
- [x] header backup 不包含用户密码
- [x] header backup 不包含 keyfile 内容
- [x] restore 后能重新解密原 payload

### 完成标准

- [x] header backup 可导出
- [x] header backup 可恢复
- [x] 恢复后 payload auth 仍正常
- [x] GUI 有强提示：header backup 不能替代 keyfile / 密码 / DPAPI 解锁条件

---

## 9. Phase 6：Destroy Access

### 待完成清单

- [x] 新增 wrapper list 命令
- [x] 新增 wrapper remove 命令
- [x] 新增 access destroy 命令
- [x] `access destroy` 删除所有 wrappers
- [x] `access destroy` 保留 payload 密文
- [x] `access destroy` 写入 destroyed 标记
- [x] `access destroy` 要求完整确认短语
- [x] GUI 中不使用误导性词汇“安全删除数据”

### 完成标准

- [x] 删除单个 wrapper 后，其他 wrapper 仍可解密
- [x] 删除全部 wrapper 后不可解密
- [x] 有 header backup 时可恢复 wrapper 区域（v2/v3 access destroy 后以匹配 body digest 恢复并解密）
- [x] 无 header backup 时明确不可恢复

---

## 10. Phase 7：DPAPI 正式化

### 待完成清单

- [x] 新增 `dpapi` wrapper 类型
- [x] 支持 current-user scope / Windows DPAPI 可用性检查
- [x] 支持 local-machine scope 时给出风险提示（CLI 与 GUI 明确同机任意用户可解密）
- [x] 支持添加 DPAPI wrapper（wrapper add / rewrap CLI 与 GUI）
- [x] 支持移除 DPAPI wrapper（通用 wrapper remove；Windows 集成测试验证保留的密码 wrapper）
- [x] DPAPI 不作为唯一恢复方式（create/add/rewrap CLI 与 GUI 强提示独立密码或 keyfile wrapper）
- [x] GUI 强制提示：重装系统 / 换用户 / 换电脑可能失效

### 完成标准

- [x] 当前 Windows 用户可通过 DPAPI wrapper 解锁（create/open 路径支持）
- [x] DPAPI wrapper 不可移植风险已文档化（Windows 通常绑定同一用户和计算机；另有 roaming profile 例外）
- [x] password + keyfile 仍可作为跨机器恢复方式

---

## 11. Phase 8：Decoy / Duress 胁迫诱饵模式

### 状态

`[!]` 高风险功能，建议延后到 HSE2 核心稳定后再做。

### 不做项

- [x] 不做输入胁迫密码后自动删除真实数据
- [x] 不做输入胁迫密码后自动删除真实 wrapper
- [x] 不承诺法律、取证或现实胁迫场景下的绝对可否认性

### 待完成清单

- [ ] 新增 decoy manifest
- [ ] 新增 decoy payload 区
- [ ] 新增 duress wrapper 类型
- [ ] 胁迫密码只解开 decoy MEK / DEK
- [ ] GUI 明确标注“这不是完整可否认性保证”

---

## 12. Phase 9：元数据最小化

### 待完成清单

- [x] 默认加密 manifest
- [x] 文件名仅存在于加密 manifest；payload 记录不含明文文件名，因此随机别名不增加静态隐私
- [x] 支持不保存绝对路径
- [x] 支持不保存 Windows 用户名 / 盘符
- [x] 支持相对路径恢复
- [x] 文件夹通过 HSE2 create 输出为单个 `.hse2` 容器
- [x] 可选文件大小 padding（`--pad-last-chunk`，默认关闭）

### 完成标准

- [x] `.hse2` 外部无法直接看到原文件名（v2/v3 原始容器字节检查通过）
- [x] manifest 篡改会认证失败
- [x] 解密后能恢复相对目录结构
- [x] 创建默认启用 manifest 加密与 encrypted filename policy；随机别名不适用，因为文件名从未以明文写入 payload
- [x] padding 保持显式可选；它会隐藏更精确的文件大小，但增加最多每个非空文件一个 chunk 的空间

---

## 13. Phase 10：CLI 命令体系

### 已完成 / 进行中命令

- [x] `high-security-encryptor-hse2-create`
- [x] `high-security-encryptor-hse2-open`
- [x] `high-security-encryptor-hse2-header-backup export`
- [x] `high-security-encryptor-hse2-header-backup restore`
- [x] `high-security-encryptor-hse2-wrapper list`
- [x] `high-security-encryptor-hse2-wrapper remove`
- [x] `high-security-encryptor-hse2-access destroy`
- [x] `high-security-encryptor-hse2-gui`
- [x] `high-security-encryptor hse2 inspect`（复用现有安全元数据 inspect handler）
- [x] `high-security-encryptor hse2 keyfile inspect`（定向 helper/CLI 测试 4/4 通过）
- [x] `high-security-encryptor hse2 wrapper add-password`
- [x] `high-security-encryptor hse2 wrapper add-keyfile`
- [x] `high-security-encryptor hse2 wrapper add-dpapi`
- [x] `high-security-encryptor hse2 wrapper list/remove/rewrap`
- [x] `high-security-encryptor hse2 access destroy`（精确确认短语，写入独立副本）
- [x] `high-security-encryptor hse2 validate`

### 完成标准

- [x] 发布用 HSE2 helper EXE 均包含 `--help` smoke；本轮 archive-validate helper 已完成本机 PyInstaller onefile 构建及 `--help` 验收
- [x] 错误 exit code 稳定为非零并有 stderr 前缀
- [x] 密码可通过 password-file 进入，不要求进 shell history
- [x] 默认不打印敏感路径以外的密钥材料，不打印 keyfile/DPAPI/wrapper bytes

---

## 14. Phase 11：GUI 升级

### 待完成清单

- [~] 新增“高安全 HSE2 加密向导”（standalone HSE2 GUI 已有，完整向导仍需补齐）
- [x] 文件 / 文件夹选择
- [x] 输出位置选择
- [x] 安全等级选择：wrapper add/rewrap 和新建归档支持标准兼容 / 推荐高安全 / 极高安全；paranoid 密码 wrapper 强制要求 keyfile
- [x] 密码输入与确认：创建归档可用掩码输入框直接输入并二次确认；打开/校验可单次输入，密码与 argv、日志、临时文件隔离
- [x] keyfile 生成 / 选择
- [x] DPAPI 本机绑定选项
- [x] header backup 导出提示和 GUI 导出入口（创建后提醒；备份与容器分开保存）
- [x] 新建归档默认执行创建后认证校验，可在 GUI 关闭；失败会明确报告且不写出明文
- [x] GUI 可单独完整校验现有归档，打开前可选完整校验；打开前会执行只读 inspect 预览并要求确认
- [x] wrapper 管理界面
- [x] destroy-access 独立危险操作界面
- [x] wrapper/access JSON 结果可读摘要

### 完成标准

- [~] 新手可通过 GUI 选择目录并创建 v2/v3 password-file 或直接输入密码归档；创建到预览、确认、恢复的统一引导仍可继续收敛
- [x] GUI 可用 password-file/keyfile/DPAPI 打开并恢复 v2/v3 归档；可选的整包预校验失败时不创建输出目录
- [x] GUI 不诱导用户只依赖 DPAPI：创建与 wrapper 管理均提示 DPAPI 本机绑定/可移植性风险及独立恢复方式
- [x] GUI 对 destroy-access 有强确认和单独入口


---

## 15. Phase 12：测试计划

### 已有重点测试文件

- [x] `tests/test_hse2_models.py`
- [x] `tests/test_kdf_profiles.py`
- [x] `tests/test_hse2_header_backup_cli.py`
- [x] `tests/test_hse2_access_management_cli.py`
- [x] `tests/test_hse2_gui_actions.py`
- [x] `tests/test_hse2_gui_launcher.py`
- [x] `tests/test_hse2_wrapper_provider_examples.py`
- [ ] `tests/test_hse2_format.py`（原计划文件名，尚未单独建立）
- [ ] `tests/test_hse2_keyfile.py`
- [ ] `tests/test_hse2_dpapi.py`
- [ ] `tests/test_hse2_manifest_metadata.py`

### 必测场景

- [x] password wrapper 解密成功
- [x] keyfile wrapper 解密成功
- [x] password + keyfile 解密成功
- [x] 错密码失败
- [x] 错 keyfile失败
- [x] 缺 keyfile 失败
- [x] header backup 导出成功
- [x] header backup 恢复成功
- [x] 删除 DPAPI wrapper / 任意 wrapper 后其他 wrapper 仍可用（通用 wrapper remove 路径）
- [x] 删除全部 wrapper 后不可解密
- [x] manifest 被篡改后认证失败
- [x] payload 被篡改后认证失败
- [x] KDF 参数被篡改后认证失败
- [x] 大文件 streaming 内存增长受限：Windows benchmark 对比 8 MiB/128 MiB create/open，Python heap 增长均为 0 MiB，working-set 增长分别为 -0.17/-0.13 MiB，均低于 32 MiB 预算
- [x] 文件夹加密不落地未加密中间归档：create 从源文件分块加密并直接写 HSE2 容器；创建/恢复集成回归通过
- [ ] 解密临时目录可通过环境变量指定

### 常规测试命令

```powershell
python -m compileall -q src tests
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

---

## 16. 推荐版本规划

| 版本 | 状态 | 内容 |
|---|---|---|
| `v0.6.0-alpha.1` | [x] | HSE2 create/open 与基础 GUI/EXE 验收 |
| `v0.6.0-alpha.2` | [x] | HSE2 helper CLI EXE 打包与 8 个 EXE 验收 |
| `v0.6.0-alpha.3` | [~] | P12 GUI wrapper/access 与结果摘要后的下一条 alpha 线，release-prep 已建立 |
| `v0.6.0` | [~] | HSE2 格式冻结、DEK + wrappers、KDF profiles |
| `v0.6.1` | [~] | keyfile 双因子、header backup |
| `v0.6.2` | [~] | wrapper 管理、destroy-access |
| `v0.6.3` | [ ] | DPAPI 正式化、GUI 加密向导 |
| `v0.6.4` | [ ] | 元数据最小化、manifest 加密默认化 |
| `v0.7.0` | [!] | decoy / duress 诱饵模式，默认关闭 |

---

## 17. 推荐开发顺序

1. [x] 建立本进度计划文档
2. [ ] 写 `docs/hse2_format.md`
3. [x] 新建 `hse2/` 模块骨架
4. [x] 实现 header 读写和认证
5. [x] 实现 DEK / MEK 生成
6. [x] 实现 password wrapper
7. [x] 实现 encrypt / decrypt 最小闭环
8. [x] 实现 KDF profiles
9. [x] 实现 keyfile wrapper
10. [x] 实现 password + keyfile 双因子
11. [x] 实现 header backup / restore
12. [x] 实现 wrapper list / remove
13. [x] 实现 access destroy
14. [~] 实现 DPAPI wrapper 正式接入
15. [~] 实现 manifest 加密和元数据最小化
16. [~] 补齐 CLI help 和错误码
17. [~] 补齐 GUI 向导
18. [~] 补齐测试
19. [ ] 写迁移文档
20. [~] 打包 release
21. [!] 评估 decoy / duress 是否进入下一版本

---

## 18. 每次开发完成后的标记规范

以后每完成一步，都在本文件中做三件事：

1. 把对应任务从 `[ ]` 改成 `[x]`。
2. 在下面“开发日志”追加一条记录。
3. 如果有提交 SHA，写入提交 SHA。

---

## 19. 开发日志

- 2026-06-07 22:01 Asia/Taipei：创建 HSE2 离线抗暴力破解升级计划文档。Commit: `8dd66e7f5bc6bf8da01b3bcbfa01e3359d38eee4`
- 2026-06-07：发布并本地验收 `v0.6.0-alpha.1`。Commit: `78ab648a5f5e829dca62ef31f319648e7db5b016`
- 2026-06-07：发布并本地验收 `v0.6.0-alpha.2`，确认 8 个 Windows EXE。Commit: `808d91362138dc060e84c5fbc816b5777e425c46`
- 2026-06-07：P12 第一段合并，HSE2 GUI 接入 wrapper/access 管理。Merge commit: `c7b3f8f56a7c3eb6cb5206eaafa83a8fd5ffbf1b`
- 2026-06-07：P12 第二段合并，HSE2 GUI wrapper/access JSON 日志新增可读结果摘要。Merge commit: `fab8c6b1e74fbe057430728071ea5cdd700564b9`
- 2026-06-07：根据当前 HSE2 alpha 进度更新本计划勾选状态。Commit: `918c4cdd17b245924bef7627b9312cf095de294a`
- 2026-06-07：准备 `v0.6.0-alpha.3` release-prep，更新版本号和发布验收清单。Commit: 本 PR
- 2026-10-31：扩展正式格式文档和 framing reference，描述 v2 JSON body 与 v3 MNF3/CHK3 流式布局、限制、自动分派及 HSE1 显式迁移边界。验证：M1 定向回归与 589 项全量测试通过（6 项跳过）；独立 v3 版本互操作仍未验证。Commit: 未提交
- 2026-10-31：新增 HSE2 wrapper 原子 rewrap API/CLI，可替换最后一个 wrapper 或保留其他 wrapper，一次写出新认证 header 并流式复制 v2/v3 body；新增旧/新因子和失败回滚测试并更新 CLI 文档。HSE2 定向 154/154、全量 593 项通过（6 项跳过）。Commit: 未提交
- 2026-10-31：HSE2 实验 GUI 新增 wrapper rewrap 操作、原/新因子输入、标签和 DPAPI 选项；密码 wrapper 提供兼容旧设备/推荐高安全/极高安全中文档位，极高安全在新密码文件已设置时展示耗时与内存提示，并在执行前确认。GUI 定向 42 项、全量 597 项通过（6 项跳过）；Windows 界面已目视检查，未使用真实容器执行 rewrap。Commit: 未提交
- 2026-10-31：HSE2 实验 GUI 新增 wrapper add 流程，复用现有容器验证因子并单独采集新 wrapper 因子，支持中文 KDF 档位、密码+keyfile 与 DPAPI；增加执行前确认并更新 README、GUI 集成和 CLI 工作流文档。GUI 定向 44 项、全量 599 项通过（6 项跳过），Windows GUI 中 add/rewrap 表单已目视检查。Commit: 未提交
- 2026-10-31：完成 Phase 4 keyfile inspect：新增 `high-security-encryptor hse2 keyfile inspect`、128 KiB 有界 SHA-256 读取、HSE2 32-byte 适配状态与文档；`tests.test_hse2_keyfile_inspect` 4/4 通过。Commit: `17c467d2264afd196528294ffa63ffe82417ca70`
- 2026-10-31：完成 paranoid wrapper 因子策略：password-backed paranoid create 需要 keyfile；workflow 与 dry-run 共用策略校验，keyfile-only/独立 DPAPI 仍可用。定向测试 `tests.test_hse2_paranoid_wrapper_policy` 5/5 通过。Commit: `17c467d2264afd196528294ffa63ffe82417ca70`
- 2026-10-31：完成 keyfile 丢失风险提示：威胁模型说明不可从归档或密码恢复 keyfile，要求独立离线备份并验证可读；GUI 在生成 keyfile 与 wrapper 管理/移除/销毁相关操作显示提示并增强确认文案。`tests.test_hse2_gui_tab` 25/25 通过，Windows GUI 中生成和 wrapper-add 表单提示目视确认。Commit: `17c467d2264afd196528294ffa63ffe82417ca70`
- 2026-10-31：完成 keyfile 同目录风险提示：create/open/wrapper CLI 检查 keyfile 与归档目录共址并将警告写入 stderr，GUI 提示明确避免共址；路径/CLI 定向测试 5/5 通过，全量测试 615 项通过、6 项跳过。`git diff --check` 通过。Commit: `17c467d2264afd196528294ffa63ffe82417ca70`
- 2026-10-31：完成 Phase 5 header backup 提示：create 成功后在 stderr 输出可复制的 export 命令，JSON 附推荐 `.hse2.header` 路径和 argv；GUI 顶部增加常驻醒目提示，说明 header backup 不能恢复或替代密码、keyfile、DPAPI 解锁条件。测试会实际执行建议 argv 并确认备份文件生成；HSE2 定向 397 项通过、2 项跳过；全量 616 项通过、6 项跳过。Commit: `9c19ced`
- 2026-10-31：完成 Phase 6 header backup wrapper 恢复场景：修复 restore 在 header 长度变化后仍使用备份旧 offset 的问题；有效当前 header 用于定位现有 body，恢复后继续校验备份 frame offset、body 长度及 SHA-256，损坏 header 仍回退备份 offset。新增 v2/v3 测试：备份、access destroy、恢复旧 wrapper、验证 body 完全一致并以原 keyfile 解密。HSE2 定向 398 项通过、2 项跳过；全量 617 项通过、6 项跳过。Commit: `00054a6`
- 2026-10-31：完成 Phase 7 DPAPI 风险正式化：create/add/rewrap CLI 明示 DPAPI wrapper 的账户/设备可移植性限制并建议保留独立密码或 keyfile；GUI 对新 DPAPI wrapper 显示醒目提示并在确认框重申，对 `local_machine` scope 显示同机其他用户可解密的风险。补充微软官方行为说明和 roaming-profile 例外。Windows 本机实测 DPAPI create/open、wrapper add、DPAPI 解锁、保留密码 fallback 后移除 DPAPI、local_machine blob 保护/解保护；Tk 界面动态警示可见性通过。全量 620 项通过、6 项跳过。Commit: `2b0e525`
- 2026-10-31：完成 Phase 9 元数据最小化：确认 v2/v3 文件名与相对路径只存在于加密 manifest，payload record 无明文路径，原始容器检查中 secret 文件名不可见；为 v2/v3 create/open 增加显式 `--pad-last-chunk`，以随机填充将每个非空文件末块加密到 chunk_size，manifest 保留原大小，解密只写回原始字节，padding mode 纳入认证 header 且使用独立 AAD。新增 CLI dry-run 与 v2/v3 create/open 集成回归，定向 9 项通过，全量 622 项通过（6 项跳过），`git diff --check` 通过。随机别名无额外 at-rest 隐私，故不引入冗余格式复杂度；padding 默认关闭。Commit: 待提交
- 2026-10-31：Phase 10 CLI 整合第一步：在统一 `high-security-encryptor hse2` 命令树下接入容器 `inspect`，保留原 `hse2-inspect` 兼容入口，并更新 CLI 文档；新增 unified route 回归。定向测试通过，`high-security-encryptor hse2 --help` 显示 `inspect` 与 `keyfile`，全量 622 项通过（6 项跳过），`git diff --check` 通过。Commit: `02268b1`
- 2026-10-31：Phase 10 CLI 整合第二步：统一 `hse2 wrapper add-password/add-keyfile/add-dpapi` 三条路径，复用现有 wrapper add 校验和写入实现；新入口支持现有解锁因子、密码档位、组合 password+keyfile、覆盖控制、keyfile 共址提示及 DPAPI 恢复警告，并在 paranoid 密码 wrapper 缺少 keyfile 时拒绝写入。三条 `--help`、密码/keyfile/Windows DPAPI 路由集成回归及 compileall 均通过；全量 625 项通过（6 项跳过），`git diff --check` 通过。Commit: `22ebc2b`
- 2026-10-31：Phase 10 CLI 整合第三步：统一 `hse2 wrapper list/remove/rewrap` 命令，保留专用 helper；安全元数据列表、header 鉴权后 wrapper 移除、body 原样保留的 rewrap 均复用现有实现。集成回归验证 list、rewrap、remove 后保留 keyfile 可重新解密；全量 626 项通过（6 项跳过），help、compileall 与 `git diff --check` 通过。Commit: `04c22f6`
- 2026-10-31：Phase 10 CLI 整合第四步：接入统一 `hse2 access destroy`，保留专用 helper；要求完全匹配的破坏性确认短语，授权因子通过后写入新容器并清除全部 wrappers。集成测试验证输出 `access_destroyed=true` 且 wrappers 为空；help、compileall 与 `git diff --check` 通过，全量 627 项通过（6 项跳过）。Commit: `8d4000f`
- 2026-10-31：Phase 10 CLI 整合第五步：在统一命令树下接入 `hse2 validate`，复用原 validation handler，并保持报告文件、summary-only 和失败退出码选项一致；同一有效/无效混合样本对比 unified 与 helper 两个入口的总数、成功数和失败数相同。定向回归、help 和 `git diff --check` 通过；全量 627 项通过（6 项跳过）。Commit: `bccde7a`
- 2026-10-31：Phase 11 GUI header-backup 第一步：新增 header backup 导出动作、输入/输出/覆盖控件及专用 CLI helper 调度；常驻提示要求创建后导出并与归档分开保存。58 项 GUI 定向测试通过，实建 v2 容器并从 GUI dispatcher 导出备份成功；Tk 实例确认 input/output/overwrite 控件实际可见；全量 630 项通过（6 项跳过），`compileall` 与 `git diff --check` 通过。Commit: `507837f`
- 2026-10-31：Phase 11 GUI 归档创建向导第一步：新增目录归档 GUI action，复用 `hse2-create`，可选择 password-file/keyfile/DPAPI、KDF profile、v2/v3、chunk size、末块 padding 与覆盖确认；密码不进入 argv，paranoid 密码策略要求 keyfile。为端到端路径补齐 v3 流式 inspect（仅读 framing/metadata，分块跳过密文，不解锁、不验证 AEAD）。修正 GUI 密码文件变更后 paranoid 提示不刷新的问题及旧的“GUI 不应展示 archive-create”断言。定向 77 项通过；Tk 控件及 paranoid/DPAPI 条件警告检查通过；全量 637 项通过（6 项跳过），compileall 与 `git diff --check` 通过。Commit: `742ed92`
- 2026-10-31：Phase 11 GUI 归档打开向导：新增 `archive-open` action 及 GUI helper 调度，可选择容器、恢复目录、password-file/keyfile/DPAPI 与覆盖；DPAPI 使用时出现可移植性提示。集成测试通过 GUI dispatcher 创建并恢复 v3 归档，逐字节比对解密输出；Tk 控件与 DPAPI 条件警告检查通过。定向 77 项通过，全量 641 项通过（6 项跳过），compileall 与 `git diff --check` 通过。另在 Windows 主 GUI 中点击“打开 HSE2 实验工具”，确认 HSE2 窗口显示。Commit: `1949411`
- 2026-10-31：Phase 11 创建后归档认证校验：新增 v2/v3 `validate_hse2_archive`，验证 header HMAC、manifest AEAD、完整 payload AEAD 与布局，不写出明文；v3 按 chunk 流式验证。GUI 创建向导默认勾选，可关闭；CLI 失败会返回独立非零状态并明确说明归档已写出。验证涵盖 v2/v3 padding、空文件、错误 key 与损坏末块 tag；GUI dispatcher 检查报告成功及 `plaintext_written=false`。定向 90 项通过；全量 643 项通过（6 项跳过），Tk 默认选项检查、compileall 与 `git diff --check` 通过。Commit: `f7661a3`
- 2026-10-31：Phase 11 打开前认证校验：`hse2-open --validate-before-open` 和 GUI 可选项会先认证 header、manifest 和全部 payload tags，再执行恢复；失败时输出目录不会创建，GUI 默认关闭以避免重复读大文件。损坏 tag/无输出目录回归、GUI dispatcher v3 create/validate/open、定向 74 项及全量 643 项（6 项跳过）通过；Tk 选项显隐、compileall 与 `git diff --check` 通过。Commit: `dc073bb`
- 2026-10-31：Phase 11 单独归档校验入口：新增 unified `hse2 validate-archive`、focused `high-security-encryptor-hse2-archive-validate` 和 GUI action，报告 header/manifest/payload 全部认证且未写明文。v3 unified CLI 与 GUI dispatcher 集成通过；定向 84 项、全量 648 项通过（6 项跳过），Tk 输入控件检查、compileall 与 `git diff --check` 通过。Commit: `69953c0`
- 2026-10-31：Phase 11 GUI 密码输入确认：新建归档可在两个掩码输入框内输入并确认密码；CLI builder 校验匹配、互斥的 password-file/DPAPI 方式及 paranoid+keyfile 策略。密码只在内存命令计划中携带（repr 隐藏），不进 argv、日志或临时文件，提交后 GUI 清空输入框；GUI dispatcher 端到端创建并恢复比对成功。GUI 定向 78 项通过；全量 654 项通过（6 项跳过），`compileall` 与 `git diff --check` 通过。Commit: `0098582`
- 2026-10-31：Phase 11 打开前 inspect 预览确认：GUI 恢复动作先运行只读 inspect，展示输入容器、恢复目标、格式、容器大小、wrapper 类型、payload 块数及访问禁用标记；预览检查失败或用户取消都会阻止恢复。界面明确该预览不代表认证通过且不显示加密文件名，打开仍按原流程认证。定向 GUI 80 项、全量 656 项通过（6 项跳过），`compileall` 与 `git diff --check` 通过。Commit: `1b76e27`
- 2026-10-31：Phase 11 创建后直接密码打开/校验：归档创建、解密恢复和完整校验均支持掩码密码输入并直接传入原 CLI helper；创建必须确认两次，打开/校验单次输入。端到端 GUI dispatcher 创建后直接以输入密码恢复并完整认证，argv/stdout/stderr 均不含密码；Tk 检查确认三个动作字段均掩码且确认框只在创建时出现。定向 88 项通过；全量 658 项通过（6 项跳过），`compileall` 与 `git diff --check` 通过。Commit: `ba4e25a`
- 2026-10-31：Phase 12 Windows 流式内存基准：运行 `build_tools/benchmark_hse2_v3_memory.py --small-mib 8 --large-mib 128 --max-growth-mib 32`。create Python heap 7.67→7.67 MiB、working set 41.66→41.49 MiB；open heap 7.67→7.67 MiB、working set 41.59→41.46 MiB；增长预算通过。该结论仅适用于本机和本次 8/128 MiB 样本。Commit: 待提交
- 2026-10-31：Phase 12 检查目录归档未落地明文中间归档：create 根据 manifest 分块读取源文件并立即加密，v3 将加密 payload 流直接交给容器 writer；现有 v2/v3 create/open 与 GUI dispatcher 往返集成覆盖此路径。`workflows.py` 未创建明文 staging archive。Commit: 待提交
- 2026-10-31：Windows 发布补齐 archive-validate helper：新增 PyInstaller entry script；workflow build、文件存在检查、`--help` smoke 和 release ZIP copy 均加入 helper；Windows EXE 文档及 workflow contract test 同步。隔离 venv 安装 `.[build]` 后实际构建 onefile EXE 并运行 `--help` 成功；契约测试通过，全量 659 项通过（6 项跳过），compileall 和 `git diff --check` 通过。Commit: 待提交

