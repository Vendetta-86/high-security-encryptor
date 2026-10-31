# M0 功能基线矩阵

检查日期：2026-10-17
检查基线：`master` / `fdb7cb55f6458736f69a43b83710fa0780bc7e94`
方法：静态检查源码、测试、README、打包 workflow 和已发布 CI/Release 元数据。本次没有运行测试、构建或 EXE。

## 总结

README 中“streaming file encryption”对 HSE1 文件格式成立；项目另有独立的实验性 HSE2 单文件流辅助实现。但这不代表 `.hse2` archive 的 `hse2-create/open` 已具备有界内存的端到端流式 I/O。

当前 HSE2 archive 路径逐 chunk 读取源文件，却把全部密文 chunk 放入 tuple，再构造成 JSON body 和完整 `bytes` 容器写盘。打开容器时，程序读取全部 archive bytes、解析整个 JSON 并建立全部 chunk 对象。其内存需求随 archive 总体积增长；逐文件恢复还会在内存中聚合该文件的完整明文。

因此路线图 M1 的主目标仍未完成：**HSE2 archive 容器的真正流式读写、按 chunk 验证/恢复及大文件内存证据。** 当前格式/CLI 功能较齐全，但 HSE2 仍应明确标为 experimental。

## README 声明映射

| README 声明 | 实现位置 | 现有测试证据 | 当前判断 / 缺口 |
|---|---|---|---|
| Streaming file encryption | HSE1: `streaming_format.py`；实验性 HSE2 单文件 helper: `hse2_streaming.py` | `test_phase1_scaffold.py`、`test_aes_gcm_security.py`、`test_hse2_streaming.py` | 单文件流式实现存在；README 应区分 HSE1、实验性 HSE2 helper 与 HSE2 archive workflow。 |
| HSE2 chunked archive create/open | `hse2/workflows.py`、`hse2/archive_payload.py` | `test_hse2_create_cli.py`、`test_hse2_open_cli.py`、`test_hse2_archive_payload.py` | 源文件按 chunk 读取，但密文 chunks 全量留在内存中；archive 不是有界内存流式格式。 |
| HSE2 container read/write | `hse2/container_bytes.py`、`hse2/file_io.py` | `test_hse2_container_bytes.py`、`test_hse2_file_io.py` | body 以 JSON 一次性序列化/解析；整个文件使用 `read_bytes()`；写入端先构造完整 `bytes`。峰值内存是总体积的倍数，实际倍率尚未测量。 |
| Per-file restored output | `hse2/workflows.py` | `test_hse2_open_cli.py` | 每个文件先在内存中解密为完整 `bytes`，然后写临时文件并 `os.replace`；单文件替换原子，整个输出目录没有事务性提交。较大的单个文件仍会占用相应明文内存。 |
| HSE2 header backup / restore | `hse2/header_backup.py`、相关 CLI | `test_hse2_header_backup.py`、`test_hse2_header_backup_cli.py` | 功能和篡改/恢复边界有测试；未见超大容器内存和恢复失败注入基准。 |
| Password/keyfile/DPAPI wrappers | HSE2 wrapper、provider、DPAPI 模块 | `test_hse2_wrapping.py`、`test_hse2_wrapper_provider_examples.py`、`test_windows_dpapi.py` | 现有功能覆盖较完整；DPAPI portability 边界在 threat model 中已有说明。 |
| HSE2 GUI delegates to CLI | HSE2 GUI tab/launcher 与 CLI command builders | `test_hse2_gui_tab.py`、`test_hse2_gui_actions.py`、`test_hse2_gui_launcher.py` | 符合“GUI 不是独立加密实现”的设计；GUI 测试主要验证命令构建与动作呈现，不等同于 Windows EXE 实机全流程验收。 |
| Windows EXE release | `.github/workflows/windows-exe.yml`、PyInstaller entrypoints | Workflow 构建/文件存在/help/GUI smoke；远端 alpha.7 Windows workflow 成功 | Release ZIP 已包含 CLI、主 GUI、HSE2 GUI 与 create/open/header-backup/inspect/wrapper/access helper。该 workflow 没有 HSE2 大文件 RSS 测量或 `.hse2` EXE round trip。 |

## HSE2 archive 流程证据

- `hse2/workflows.py:103-142` 收集 `payload_chunks` 后再调用 `write_hse2_container`。
- `hse2/workflows.py:215-229` 逐 chunk 读取源文件，但将每个加密 chunk append 到 list 并返回完整 tuple。
- `hse2/container_bytes.py:31-43` 将全部 chunks 转为 JSON list，并一次性 canonical-JSON 编码成完整容器 bytes。
- `hse2/file_io.py:46-75` 用 `Path.read_bytes()` 读整个容器，再整体 decode；写之前先拿到完整编码结果。底层写文件用 sibling temp、flush/fsync 和 `os.replace`，保护的是最终文件替换，不改变内存复杂度。
- `hse2/workflows.py:170-185` 在解密前调用完整容器读取/解码，再开始恢复。
- `hse2/workflows.py:374-380` 每个目标文件的完整明文先由 `_decrypt_file_range` 返回，再写入临时文件并原子替换。
- `hse2_streaming.py:44-106,109-180` 有单文件 chunk 读写和 trailer 验证实现；它独立于 archive `workflows.py`。`docs/hse2_streaming.md` 仍称其为 draft，并列出 CLI/GUI 选择和 streaming output adapters 为未完成工作。

## 现有测试覆盖与缺口

静态检查找到 HSE2 archive chunk 构造测试使用 6–7 字节样本和 2 字节 chunk；HSE2 单文件 helper 测试覆盖 round trip、错误密码、header/chunk/trailer 篡改及空文件。create/open 测试覆盖正常恢复、错误 keyfile、覆盖保护与缺少凭据。

对 `tests/` 静态搜索未发现 `tracemalloc`、RSS/`getrusage`、GB 级 payload、峰值内存或内存上限测试。也未发现 HSE2 archive 级别的逐 chunk 中断恢复或整目录原子提交测试。**以上是静态检索结果，不是对测试套件运行结果的陈述。**

## 打包与远端发布核对

- `pyproject.toml:47-53` 暴露 HSE2 create/open/header-backup/plan/inspect/wrapper/access Python 命令。
- `.github/workflows/windows-exe.yml:105-155` 构建并对六个 HSE2 helper EXE 运行 `--help`，同时检查 GUI 与主程序 smoke。
- `.github/workflows/windows-exe.yml:157-197` 显式挑选 EXE 和文档组成 ZIP，并上传到 GitHub Release。
- 远端 `v0.6.0-alpha.7` 的 Windows ZIP asset 存在；对应 Windows workflow 和 master CI 最近一次均成功（2026-07-26）。这证明当时发布流水线成功，不是本地对 ZIP 内容或实机行为的重新复验。

## M0 结论与下一步

1. 更新 README：把通用 streaming 声明明确归属到 HSE1/单文件 helper，不暗示 HSE2 archive create/open 已是有界内存实现。
2. 在 M1 开发前记录 HSE2 archive 格式的读写约束和兼容策略。基于当前代码，格式/容器 I/O 是主要重构面；不能只替换 chunk builder 而宣称完成流式化。
3. 为 M1 设立可重复的大文件 RSS 基准、按 chunk 认证、截断/缺块/重排故障样本、原子失败语义与旧版兼容 fixture。
4. 明确输出目录级失败策略：当前单文件临时替换不会自动回滚已经恢复的其他文件。

下一项按路线图顺序：审阅 HSE2 `create/open` 的实现与接口，形成 M1 格式/数据流设计和可验收的 issue 切片；本次不跳到公钥共享、Vault 或传输功能。
