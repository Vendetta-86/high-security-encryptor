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
| Phase 3 | [~] | KDF Profiles 正式化 | 三档 profile 已实现并可由 CLI 选择；GUI 映射仍需完善 |
| Phase 4 | [~] | Keyfile 双因子 | keyfile 与 password+keyfile wrapper 已实现；inspect/强风险提示未完成 |
| Phase 5 | [~] | Header Backup | export/restore CLI 与测试已实现；GUI 提示未完成 |
| Phase 6 | [~] | Destroy Access | wrapper list/remove/access destroy CLI+GUI 已完成；backup 恢复场景仍需补测 |
| Phase 7 | [~] | DPAPI 正式化 | create 阶段已有 DPAPI wrapper；add/remove/跨机风险文档仍需补齐 |
| Phase 8 | [!] | Decoy / Duress | 继续延后 |
| Phase 9 | [~] | 元数据最小化 | encrypted manifest/store_original_paths=false 已落地；随机名/padding 仍需补齐 |
| Phase 10 | [~] | GUI / CLI 完整闭环 | helper CLI 与 HSE2 GUI 可用；统一子命令树和完整向导仍需补齐 |
| Phase 11 | [~] | 测试与发布 | v0.6.0-alpha.3 release-prep 已建立，待 CI/本地验收与发布 |

---

## 4. Phase 1：HSE2 格式冻结

### 待完成清单

- [ ] 新增 `docs/hse2_format.md`
- [x] 明确 HSE2 magic：`HSE2`
- [x] 明确格式版本：`format_version = 2`
- [x] 明确 header 编码格式：canonical JSON
- [x] 明确 header 认证方式：`header_auth` / `header_auth_tag`
- [x] 明确 payload 加密方式：AES-256-GCM streaming chunks
- [x] 明确 manifest 默认加密策略
- [x] 明确 wrappers 数组结构
- [ ] 明确向后兼容策略：HSE1 只读迁移，不强行原地升级

### 完成标准

- [ ] `docs/hse2_format.md` 已合并
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
- [ ] 支持 rewrap：更换密码或 keyfile 不重加密 payload

### 完成标准

- [x] 密码 wrapper 能解开 DEK / MEK
- [x] 不同 wrapper 能解开同一组 DEK / MEK
- [~] 修改密码只改 wrapper，不重写 payload（remove 已有，完整 rewrap 未完成）
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
- [ ] GUI 使用中文安全等级，不直接暴露底层参数

### 完成标准

- [x] 三档 profile 均有实现
- [x] 参数被篡改会导致认证失败
- [ ] `paranoid` 模式有明显 GUI 性能提示

---

## 7. Phase 4：Keyfile 双因子正式化

### 待完成清单

- [x] 新增 keyfile 生成命令 / GUI action
- [ ] 新增 keyfile inspect 命令
- [x] 支持 password + keyfile 联合派生 KEK
- [x] 支持 keyfile-only wrapper，但 GUI 默认不推荐
- [ ] `paranoid` 模式强制要求 keyfile 或等价外部 wrapper
- [~] keyfile 丢失风险提示（文档与 GUI 仍需强化）
- [ ] keyfile 与 `.hse2` 同目录时给出警告

### 完成标准

- [x] 缺少 keyfile 时无法离线验证密码 / 解锁失败
- [x] 错 keyfile 明确失败
- [x] keyfile 生成使用安全随机数
- [~] GUI 完成 keyfile 生成 / 选择 / 风险提示闭环

---

## 8. Phase 5：Header Backup

### 待完成清单

- [x] 新增 header export 命令
- [x] 新增 header restore 命令
- [ ] 加密完成后提示导出 header backup
- [x] header backup 不包含明文 DEK / MEK
- [x] header backup 不包含用户密码
- [x] header backup 不包含 keyfile 内容
- [x] restore 后能重新解密原 payload

### 完成标准

- [x] header backup 可导出
- [x] header backup 可恢复
- [x] 恢复后 payload auth 仍正常
- [ ] GUI 有强提示：header backup 不能替代 keyfile / 密码

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
- [ ] 有 header backup 时可恢复 wrapper 区域（需独立场景补测）
- [x] 无 header backup 时明确不可恢复

---

## 10. Phase 7：DPAPI 正式化

### 待完成清单

- [x] 新增 `dpapi` wrapper 类型
- [x] 支持 current-user scope / Windows DPAPI 可用性检查
- [~] 支持 local-machine scope 时给出风险提示
- [ ] 支持添加 DPAPI wrapper
- [~] 支持移除 DPAPI wrapper（可通过通用 wrapper remove 移除，缺 add-dpapi 正式流）
- [~] DPAPI 不作为唯一恢复方式（需 GUI/文档强提示）
- [ ] GUI 强制提示：重装系统 / 换用户 / 换电脑可能失效

### 完成标准

- [x] 当前 Windows 用户可通过 DPAPI wrapper 解锁（create/open 路径支持）
- [ ] 移动到其他机器后 DPAPI wrapper 不可用（需测试或文档化）
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
- [~] 支持随机化内部文件名（当前策略为 encrypted，仍需确认随机命名策略）
- [x] 支持不保存绝对路径
- [x] 支持不保存 Windows 用户名 / 盘符
- [x] 支持相对路径恢复
- [~] 支持 bundle-folder 单容器输出（HSE2 archive 已可输出单容器，仍需正式命令名）
- [ ] 可选文件大小 padding

### 完成标准

- [~] `.hse2` 外部无法直接看到原文件名（manifest 加密已完成，内部命名策略需复核）
- [x] manifest 篡改会认证失败
- [x] 解密后能恢复相对目录结构
- [ ] paranoid 模式默认启用 manifest 加密和随机化名称

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
- [ ] `high-security-encryptor hse2 inspect`
- [ ] `high-security-encryptor hse2 keyfile inspect`
- [ ] `high-security-encryptor hse2 wrapper add-password`
- [ ] `high-security-encryptor hse2 wrapper add-keyfile`
- [ ] `high-security-encryptor hse2 wrapper add-dpapi`

### 完成标准

- [~] 所有已发布 helper 命令有 `--help`（v0.6.0-alpha.2 Windows EXE 已本地验收）
- [x] 错误 exit code 稳定为非零并有 stderr 前缀
- [x] 密码可通过 password-file 进入，不要求进 shell history
- [x] 默认不打印敏感路径以外的密钥材料，不打印 keyfile/DPAPI/wrapper bytes

---

## 14. Phase 11：GUI 升级

### 待完成清单

- [~] 新增“高安全 HSE2 加密向导”（standalone HSE2 GUI 已有，完整向导仍需补齐）
- [x] 文件 / 文件夹选择
- [x] 输出位置选择
- [ ] 安全等级选择：标准兼容 / 推荐高安全 / 极高安全
- [~] 密码输入与确认（当前偏 CLI/file boundary，需正式 GUI 控件）
- [x] keyfile 生成 / 选择
- [x] DPAPI 本机绑定选项
- [ ] header backup 导出提示
- [~] 加密后 validate 选项
- [~] 解密前 inspect / validate 选项
- [x] wrapper 管理界面
- [x] destroy-access 独立危险操作界面
- [x] wrapper/access JSON 结果可读摘要

### 完成标准

- [~] 新手可通过 GUI 完成 password + keyfile 加密
- [~] 新手可通过 GUI 完成解密
- [~] GUI 不诱导用户只依赖 DPAPI
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
- [~] 大文件 streaming 不爆内存（streaming chunk 实现已有，需更大 fixture）
- [~] 文件夹加密不落地未加密中间归档
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
