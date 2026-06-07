# HSE2 离线抗暴力破解升级计划书

- **项目**：`Vendetta-86/high-security-encryptor`
- **计划生成时间**：2026-06-07 22:01 Asia/Taipei
- **文档命名时间戳**：`20260607-2201`
- **当前状态**：计划已建立，基础能力盘点已完成，后续每完成一步在本文件中把对应状态改为 `[x]`
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
5. nuke / duress 类功能容易误删，需要安全边界清晰。

---

## 1. 不做项

这些功能本轮不做，避免项目复杂度失控。

| 状态 | 功能 | 处理方式 | 原因 |
|---|---|---|---|
| [x] | 不做虚拟磁盘挂载 | 保留为非目标 | 会进入 VeraCrypt / 文件系统驱动复杂度 |
| [x] | 不做 Windows 文件系统驱动 | 保留为非目标 | 安全审计和维护成本过高 |
| [x] | 不做系统盘加密 | 交给 BitLocker / VeraCrypt | 项目定位是文件级加密 |
| [x] | 不承诺真隐藏卷 | 只做元数据最小化 | 文件加密器天然泄露文件数量、大小、时间戳等信息 |
| [x] | 不做默认 nuke 密码 | 改为显式 `destroy-access` | 自动销毁误触风险高 |
| [x] | 不承诺彻底安全删除明文 | 只做风险提示和临时目录控制 | SSD、缓存、影子副本、日志都可能保留痕迹 |

---

## 2. 当前已具备基础能力盘点

以下项目根据当前仓库规划和已有功能方向先标记为已具备或部分具备，后续实现时可继续细化。

| 状态 | 能力 | 说明 |
|---|---|---|
| [x] | Python 项目基础 | 已有项目结构，可继续扩展 HSE2 模块 |
| [x] | CLI / GUI 基础 | 已有命令行和图形界面方向 |
| [x] | 文件加密基础 | 已有文件级加密路线 |
| [x] | 文件夹加密基础 | 已有文件夹打包 / 加密方向 |
| [x] | 批量处理基础 | 已有 batch / sidecar 工作流方向 |
| [x] | Argon2id KDF 路线 | 已有 Argon2id / KDF profiles 规划基础 |
| [~] | HSE2 实验基础 | 已有 HSE2 方向，但需格式冻结和正式化 |
| [~] | DPAPI wrapper | 已有 Windows DPAPI wrapper 方向，需纳入正式 HSE2 wrapper 架构 |
| [~] | Keyfile 操作 | 已有 keyfile 方向，需强化为离线抗破解主路径 |
| [~] | no-password-table 工作流 | 已有方向，需在 paranoid 模式中强制化 |
| [~] | brute-force guard | 已有本地尝试限制，但不能防复制后的离线攻击 |
| [~] | 文档基础 | 已有安全模型方向，需新增进度计划和 HSE2 格式文档 |

---

## 3. 里程碑总览

| 阶段 | 状态 | 名称 | 目标 |
|---|---|---|---|
| Phase 0 | [x] | 升级计划建立 | 新增本进度文档，统一后续开发标记 |
| Phase 1 | [ ] | HSE2 格式冻结 | 定义正式 `.hse2` 容器结构 |
| Phase 2 | [ ] | DEK + Wrapper 架构 | 文件内容密钥随机生成，密码/keyfile/DPAPI 只包装密钥 |
| Phase 3 | [ ] | KDF Profiles 正式化 | compatible / hardened / paranoid 三档参数落地 |
| Phase 4 | [ ] | Keyfile 双因子 | 将 keyfile 变成离线抗破解主路径 |
| Phase 5 | [ ] | Header Backup | 防止 header 或 wrapper 损坏导致永久丢失 |
| Phase 6 | [ ] | Destroy Access | 借鉴 nuke 思路，做显式销毁解锁能力 |
| Phase 7 | [ ] | DPAPI 正式化 | 本机绑定 wrapper 纳入 HSE2 格式 |
| Phase 8 | [!] | Decoy / Duress | 胁迫密码只打开诱饵，不自动销毁真实数据 |
| Phase 9 | [ ] | 元数据最小化 | 加密 manifest、随机文件名、隐藏源路径 |
| Phase 10 | [ ] | GUI / CLI 完整闭环 | 命令和界面可供普通用户直接使用 |
| Phase 11 | [ ] | 测试与发布 | 单元测试、手动测试、迁移文档、Release |

---

## 4. Phase 1：HSE2 格式冻结

### 目标

将 HSE2 从实验方向推进成正式容器格式。

### 待完成清单

- [ ] 新增 `docs/hse2_format.md`
- [ ] 明确 HSE2 magic，例如 `HSE2`
- [ ] 明确格式版本，例如 `format_version = 2`
- [ ] 明确 header 编码格式：建议第一版使用 canonical JSON
- [ ] 明确 header 认证方式：HMAC-SHA256 或 AEAD AAD 认证
- [ ] 明确 payload 加密方式：AES-256-GCM streaming chunks
- [ ] 明确 manifest 是否默认加密
- [ ] 明确 wrappers 数组结构
- [ ] 明确向后兼容策略：HSE1 只读迁移，不强行原地升级

### 推荐目录结构

```text
src/high_security_encryptor/hse2/
├── __init__.py
├── constants.py
├── format.py
├── header.py
├── container.py
├── keys.py
├── kdf.py
├── wrappers.py
├── manifest.py
└── errors.py
```

### 完成标准

- [ ] `docs/hse2_format.md` 已合并
- [ ] HSE2 header schema 有样例
- [ ] 测试能读取一个最小 HSE2 header fixture
- [ ] 旧 HSE1 路径未被破坏

---

## 5. Phase 2：DEK + Wrapper 架构

### 目标

改变密钥模型：用户密码不直接加密文件内容，而是派生 KEK，用 KEK 包装随机 DEK / MEK。

### 密钥定义

```text
DEK = Data Encryption Key，用于加密 payload
MEK = Manifest Encryption Key，用于加密 manifest
KEK = Key Encryption Key，由密码 / keyfile / DPAPI provider 派生或获得
```

### 待完成清单

- [ ] 每次加密随机生成 32-byte `DEK`
- [ ] 每次加密随机生成 32-byte `MEK`
- [ ] 每次加密随机生成 payload nonce seed
- [ ] 每个 wrapper 独立生成 salt 和 nonce
- [ ] wrapper 只保存加密后的 `DEK` / `MEK`
- [ ] 支持同一容器多个 wrapper
- [ ] 支持 rewrap：更换密码或 keyfile 不重加密 payload

### Wrapper 逻辑结构

```json
{
  "id": "password-1",
  "type": "password",
  "kdf": {
    "algorithm": "argon2id",
    "profile": "hardened",
    "salt": "base64...",
    "memory_cost_kib": 262144,
    "time_cost": 3,
    "parallelism": 4
  },
  "wrap_cipher": "AES-256-GCM",
  "nonce": "base64...",
  "wrapped_keys": {
    "dek": "base64...",
    "mek": "base64..."
  },
  "created_utc": "2026-06-07T22:01:00+08:00",
  "label": "main password"
}
```

### 完成标准

- [ ] 密码 wrapper 能解开 DEK / MEK
- [ ] 不同 wrapper 能解开同一组 DEK / MEK
- [ ] 修改密码只改 wrapper，不重写 payload
- [ ] 篡改 wrapper 会认证失败

---

## 6. Phase 3：KDF Profiles 正式化

### 目标

将 KDF 参数变成 HSE2 header 中的自描述字段，并提供固定安全档位。

### 推荐参数

| 状态 | Profile | Argon2id 内存 | time_cost | parallelism | 用途 |
|---|---|---:|---:|---:|---|
| [ ] | `compatible` | 64 MiB | 3 | 4 | 老机器兼容 |
| [ ] | `hardened` | 256 MiB | 3 | 4 | 默认推荐 |
| [ ] | `paranoid` | 1 GiB | 4 | 4 | 高价值、低频归档 |

### 待完成清单

- [ ] 新增 `src/high_security_encryptor/hse2/kdf.py`
- [ ] 新增 KDF profile 常量
- [ ] 新增 profile 参数校验
- [ ] 加密时把实际 KDF 参数写入 header
- [ ] 解密时以 header 参数为准，不依赖当前软件默认值
- [ ] GUI 使用中文安全等级，不直接暴露底层参数

### GUI 映射

| GUI 名称 | 实际 profile |
|---|---|
| 标准兼容 | `compatible` |
| 推荐高安全 | `hardened` |
| 极高安全/慢速 | `paranoid` |

### 完成标准

- [ ] 三档 profile 均可加密/解密
- [ ] 参数被篡改会导致认证失败
- [ ] `paranoid` 模式有明显性能提示

---

## 7. Phase 4：Keyfile 双因子正式化

### 目标

把 keyfile 从附加能力升级为离线抗暴力破解的主路径。

### 待完成清单

- [ ] 新增 keyfile 生成命令
- [ ] 新增 keyfile inspect 命令
- [ ] 支持 password + keyfile 联合派生 KEK
- [ ] 支持 keyfile-only wrapper，但 GUI 默认不推荐
- [ ] `paranoid` 模式强制要求 keyfile 或等价外部 wrapper
- [ ] keyfile 丢失风险提示
- [ ] keyfile 与 `.hse2` 同目录时给出警告

### 推荐命令

```powershell
high-security-encryptor hse2 keyfile generate --out E:\hse_keys\archive.key
```

```powershell
high-security-encryptor hse2 encrypt `
  --input D:\Secrets `
  --output D:\Encrypted\Secrets.hse2 `
  --profile hardened `
  --password-prompt `
  --keyfile E:\hse_keys\secrets.key `
  --encrypt-manifest `
  --randomize-names
```

### 完成标准

- [ ] 缺少 keyfile 时无法离线验证密码
- [ ] 错 keyfile 明确失败
- [ ] keyfile 生成使用安全随机数
- [ ] GUI 完成 keyfile 生成 / 选择 / 风险提示闭环

---

## 8. Phase 5：Header Backup

### 目标

降低 header 损坏、wrapper 误删、迁移失败导致永久丢数据的风险。

### 待完成清单

- [ ] 新增 header export 命令
- [ ] 新增 header restore 命令
- [ ] 加密完成后提示导出 header backup
- [ ] header backup 不包含明文 DEK / MEK
- [ ] header backup 不包含用户密码
- [ ] header backup 不包含 keyfile 内容
- [ ] restore 后能重新解密原 payload

### 推荐命令

```powershell
high-security-encryptor hse2 header export `
  --input D:\Encrypted\Secrets.hse2 `
  --out D:\Backup\Secrets.hse2.header.backup
```

```powershell
high-security-encryptor hse2 header restore `
  --input D:\Encrypted\Secrets.hse2 `
  --header D:\Backup\Secrets.hse2.header.backup `
  --out D:\Encrypted\Secrets.restored.hse2
```

### 完成标准

- [ ] header backup 可导出
- [ ] header backup 可恢复
- [ ] 恢复后 payload auth 仍正常
- [ ] GUI 有强提示：header backup 不能替代 keyfile / 密码

---

## 9. Phase 6：Destroy Access

### 目标

借鉴 nuke / LUKS keyslot erase 思路，但只做显式销毁解锁能力，不做默认 nuke 密码。

### 待完成清单

- [ ] 新增 wrapper list 命令
- [ ] 新增 wrapper remove 命令
- [ ] 新增 access destroy 命令
- [ ] `access destroy` 删除所有 wrappers
- [ ] `access destroy` 保留 payload 密文
- [ ] `access destroy` 写入 destroyed 标记
- [ ] `access destroy` 要求完整确认短语
- [ ] GUI 中不使用误导性词汇“安全删除数据”

### 推荐命令

```powershell
high-security-encryptor hse2 wrapper list --input D:\Encrypted\Secrets.hse2
```

```powershell
high-security-encryptor hse2 wrapper remove `
  --input D:\Encrypted\Secrets.hse2 `
  --wrapper-id dpapi-1 `
  --out D:\Encrypted\Secrets.no-dpapi.hse2
```

```powershell
high-security-encryptor hse2 access destroy `
  --input D:\Encrypted\Secrets.hse2 `
  --out D:\Encrypted\Secrets.destroyed.hse2
```

### 强制确认短语

```text
我确认这会永久销毁解锁能力，且没有备份时无法恢复
```

### 完成标准

- [ ] 删除单个 wrapper 后，其他 wrapper 仍可解密
- [ ] 删除全部 wrapper 后不可解密
- [ ] 有 header backup 时可恢复 wrapper 区域
- [ ] 无 header backup 时明确不可恢复

---

## 10. Phase 7：DPAPI 正式化

### 目标

把 Windows DPAPI 从辅助能力纳入正式 HSE2 wrapper 架构，用于本机绑定便利解锁。

### 待完成清单

- [ ] 新增 `dpapi` wrapper 类型
- [ ] 支持 current-user scope
- [ ] 支持 local-machine scope 时给出风险提示
- [ ] 支持添加 DPAPI wrapper
- [ ] 支持移除 DPAPI wrapper
- [ ] DPAPI 不作为唯一恢复方式
- [ ] GUI 强制提示：重装系统 / 换用户 / 换电脑可能失效

### 推荐命令

```powershell
high-security-encryptor hse2 wrapper add-dpapi `
  --input D:\Encrypted\Secrets.hse2 `
  --out D:\Encrypted\Secrets.with-dpapi.hse2 `
  --password-prompt `
  --keyfile E:\hse_keys\secrets.key
```

### 完成标准

- [ ] 当前 Windows 用户可通过 DPAPI wrapper 解锁
- [ ] 移动到其他机器后 DPAPI wrapper 不可用
- [ ] password + keyfile 仍可作为跨机器恢复方式

---

## 11. Phase 8：Decoy / Duress 胁迫诱饵模式

### 状态

`[!]` 高风险功能，建议延后到 HSE2 核心稳定后再做。

### 目标

提供胁迫密码，但它只打开诱饵内容，不自动销毁真实数据。

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

### 完成标准

- [ ] 正常密码打开真实内容
- [ ] 胁迫密码打开诱饵内容
- [ ] 胁迫密码不修改真实数据
- [ ] 胁迫密码不触发自动销毁

---

## 12. Phase 9：元数据最小化

### 目标

不承诺隐藏卷，但降低文件名、路径、manifest、批量结构泄露。

### 待完成清单

- [ ] 默认加密 manifest
- [ ] 支持随机化内部文件名
- [ ] 支持不保存绝对路径
- [ ] 支持不保存 Windows 用户名 / 盘符
- [ ] 支持相对路径恢复
- [ ] 支持 bundle-folder 单容器输出
- [ ] 可选文件大小 padding

### 推荐选项

```powershell
--encrypt-manifest
--randomize-names
--hide-source-paths
--pad-file-size
--bundle-folder
```

### 完成标准

- [ ] `.hse2` 外部无法直接看到原文件名
- [ ] manifest 篡改会认证失败
- [ ] 解密后能恢复相对目录结构
- [ ] paranoid 模式默认启用 manifest 加密和随机化名称

---

## 13. Phase 10：CLI 命令体系

### 目标

形成稳定、可文档化的命令结构。

### 待完成命令

- [ ] `high-security-encryptor hse2 encrypt`
- [ ] `high-security-encryptor hse2 decrypt`
- [ ] `high-security-encryptor hse2 inspect`
- [ ] `high-security-encryptor hse2 validate`
- [ ] `high-security-encryptor hse2 keyfile generate`
- [ ] `high-security-encryptor hse2 keyfile inspect`
- [ ] `high-security-encryptor hse2 wrapper list`
- [ ] `high-security-encryptor hse2 wrapper add-password`
- [ ] `high-security-encryptor hse2 wrapper add-keyfile`
- [ ] `high-security-encryptor hse2 wrapper add-dpapi`
- [ ] `high-security-encryptor hse2 wrapper remove`
- [ ] `high-security-encryptor hse2 header export`
- [ ] `high-security-encryptor hse2 header restore`
- [ ] `high-security-encryptor hse2 access destroy`

### 完成标准

- [ ] 所有命令有 `--help`
- [ ] 错误 exit code 稳定
- [ ] 密码不进入 shell history
- [ ] 默认不打印敏感路径和密钥材料

---

## 14. Phase 11：GUI 升级

### 目标

把 HSE2 高安全流程做成普通用户可操作的图形向导。

### 待完成清单

- [ ] 新增“高安全 HSE2 加密向导”
- [ ] 文件 / 文件夹选择
- [ ] 输出位置选择
- [ ] 安全等级选择：标准兼容 / 推荐高安全 / 极高安全
- [ ] 密码输入与确认
- [ ] keyfile 生成 / 选择
- [ ] DPAPI 本机绑定选项
- [ ] header backup 导出提示
- [ ] 加密后 validate 选项
- [ ] 解密前 inspect / validate 选项
- [ ] wrapper 管理界面
- [ ] destroy-access 独立危险操作界面

### GUI 警告文案

```text
请不要把 keyfile 和 .hse2 文件放在同一个云盘目录。
建议 .hse2 放云盘或移动硬盘，keyfile 放另一只 U 盘或离线设备。
```

```text
DPAPI 解锁只适合当前 Windows 用户。
系统重装、用户配置损坏、换电脑后可能无法使用。
请至少保留一种 password + keyfile 解锁方式。
```

### 完成标准

- [ ] 新手可通过 GUI 完成 password + keyfile 加密
- [ ] 新手可通过 GUI 完成解密
- [ ] GUI 不诱导用户只依赖 DPAPI
- [ ] GUI 对 destroy-access 有强确认和单独入口

---

## 15. Phase 12：测试计划

### 单元测试文件

- [ ] `tests/test_hse2_format.py`
- [ ] `tests/test_hse2_kdf_profiles.py`
- [ ] `tests/test_hse2_wrappers.py`
- [ ] `tests/test_hse2_keyfile.py`
- [ ] `tests/test_hse2_dpapi.py`
- [ ] `tests/test_hse2_header_backup.py`
- [ ] `tests/test_hse2_destroy_access.py`
- [ ] `tests/test_hse2_cli.py`
- [ ] `tests/test_hse2_manifest_metadata.py`

### 必测场景

- [ ] password wrapper 解密成功
- [ ] keyfile wrapper 解密成功
- [ ] password + keyfile 解密成功
- [ ] 错密码失败
- [ ] 错 keyfile 失败
- [ ] 缺 keyfile 失败
- [ ] header backup 导出成功
- [ ] header backup 恢复成功
- [ ] 删除 DPAPI wrapper 后其他 wrapper 仍可用
- [ ] 删除全部 wrapper 后不可解密
- [ ] manifest 被篡改后认证失败
- [ ] payload 被篡改后认证失败
- [ ] KDF 参数被篡改后认证失败
- [ ] 大文件 streaming 不爆内存
- [ ] 文件夹加密不落地未加密中间归档
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
| `v0.6.0` | [ ] | HSE2 格式冻结、DEK + wrappers、KDF profiles |
| `v0.6.1` | [ ] | keyfile 双因子、header backup |
| `v0.6.2` | [ ] | wrapper 管理、destroy-access |
| `v0.6.3` | [ ] | DPAPI 正式化、GUI 加密向导 |
| `v0.6.4` | [ ] | 元数据最小化、manifest 加密默认化 |
| `v0.7.0` | [!] | decoy / duress 诱饵模式，默认关闭 |

---

## 17. 推荐开发顺序

严格按下面顺序推进，避免先做 GUI 或高风险功能导致返工。

1. [x] 建立本进度计划文档
2. [ ] 写 `docs/hse2_format.md`
3. [ ] 新建 `hse2/` 模块骨架
4. [ ] 实现 header 读写和认证
5. [ ] 实现 DEK / MEK 生成
6. [ ] 实现 password wrapper
7. [ ] 实现 encrypt / decrypt 最小闭环
8. [ ] 实现 KDF profiles
9. [ ] 实现 keyfile wrapper
10. [ ] 实现 password + keyfile 双因子
11. [ ] 实现 header backup / restore
12. [ ] 实现 wrapper list / remove
13. [ ] 实现 destroy-access
14. [ ] 实现 DPAPI wrapper 正式接入
15. [ ] 实现 manifest 加密和元数据最小化
16. [ ] 补齐 CLI help 和错误码
17. [ ] 补齐 GUI 向导
18. [ ] 补齐测试
19. [ ] 写迁移文档
20. [ ] 打包 release
21. [!] 评估 decoy / duress 是否进入下一版本

---

## 18. 每次开发完成后的标记规范

以后每完成一步，都在本文件中做三件事：

1. 把对应任务从 `[ ]` 改成 `[x]`。
2. 在下面“开发日志”追加一条记录。
3. 如果有提交 SHA，写入提交 SHA。

### 开发日志格式

```text
- 2026-06-07 22:01 Asia/Taipei：创建 HSE2 离线抗暴力破解升级计划文档。Commit: <sha>
```

---

## 19. 开发日志

- 2026-06-07 22:01 Asia/Taipei：创建 HSE2 离线抗暴力破解升级计划文档。Commit: 待写入
