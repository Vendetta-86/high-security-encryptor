# M1: HSE2 归档有界内存设计与实施切片

日期：2026-10-17
状态：M1.1–M1.7 已实施并完成当前本地验收（2026-10-31）；第三方 v3 实现互操作及稳定格式冻结审查仍未完成
依据：本地代码审阅及 `docs/progress/m0-feature-matrix-2026-10.md`

## 当前状态（2026-10-31）

本文件后续章节保留各 M1 切片的历史设计与验证记录；其中最初的“M1.1 规格收敛”状态已过时。当前仓库已完成 v3 有界 framing、流式 create/open、wrapper/header-backup 流式操作、CLI/GUI 接入、v2 基线 fixture、畸形 framing 回归、仓库内独立参考实现的双向互操作以及 Windows 8 MiB/128 MiB 内存基准。后续 alpha.8 本地验收进一步完成 Windows EXE v3 往返、打包 GUI 元数据检查和 666 项全量测试（6 项跳过）；见 [`20261031-alpha8-prep-status.md`](20261031-alpha8-prep-status.md)。

剩余边界：仓库内独立参考实现不是第三方实现，因此不能据此承诺与外部 v3 实现兼容；单机内存基准也不构成任意 manifest 大小、内存压力和平台上的绝对上限证明。进入稳定格式冻结或作出对外兼容承诺前，需要外部 v3 实现的双向互操作证据及独立格式/密码学审查。Phase 8 decoy/duress 仍按主路线图维持 no-go。

## 1. 目标与当前问题

M1 要让 HSE2 归档创建、恢复、wrapper 重包和 header 备份检查都不因归档总大小而占用等量内存，同时保持旧 HSE2 归档可读取。

当前创建流程虽按 `chunk_size` 读取源文件，但 `_build_payload_chunks` 会把全部加密块收集到 tuple；`container_bytes` 再将这些块序列化进单个 JSON body。文件 I/O 层最终接收完整 `bytes`，恢复也先读取/解码整个容器，并把每个恢复文件完整解密为一个 bytes 对象。wrapper 变更虽然不重新加密 payload，但会完整载入归档对象，再重写整个 JSON 容器。

项目还有独立的 `hse2_streaming.py` 单文件实验格式。它不能直接视作归档格式：其 header、chunk/trailer framing 和归档的 `HSE2Header`、manifest、wrapper 管理属于不同路径。

## 2. 已核实的格式与认证事实

- 归档 preamble 使用 `HSE2` magic、固定 preamble version 2、canonical JSON header encoding 标记和 header 长度。版本 2 当前只接受该 preamble 版本。
- preamble 后面是可变长度 canonical JSON header；其后正文为 `HSE2BODY\n` 标识和一个 JSON 对象，内含加密 manifest 与全部 payload chunk 的 JSON 表示。
- header HMAC-SHA256 覆盖带上下文前缀的 canonical header（去除 auth tag 字段），因此任何纳入 header 的布局字段都受认证保护。
- payload 通过 DEK-backed AES-GCM 分块保护；实施前必须将现有 payload AAD/nonce 派生代码作为协议基线逐字段冻结。M1 不应擅自改变算法或 AAD。
- header backup 元数据记录 `body_offset`、`body_size`、`container_size` 和 body SHA-256。body 偏移依赖当前 header frame 长度；任何新格式都要明确“body”范围和偏移算法，并按固定块流式计算摘要。
- wrapper add/remove 会验证 header tag、更新 header 并重写容器；当前读取接口因此把 manifest 与 payload chunks 一并载入内存。

## 3. M1.1 协议决议

### 3.1 格式版本与兼容

保留现有 v2 读取器，禁止原地重新解释 v2 JSON body。归档 v3 将外层 preamble version 和 authenticated header `format_version` 均设为 3，并通过外层 preamble 显式 dispatch。v2 preamble 仍只允许 `header.format_version == 2`；v3 只允许等于 3。单文件实验 helper 是独立格式，不参与此 dispatch。

v3 成为新建 archive 的默认格式；open/list/backup/rewrap 依输入版本 dispatch。旧版本程序无法读取 v3，CLI/GUI 在创建前必须清楚显示输出格式和兼容性。不得静默将既有 v2 归档迁移或改写为 v3。

### 3.2 v3 字节布局

v3 布局定为：

```text
固定 preamble(v3, header_length)
canonical JSON authenticated header
manifest record: "MNF3" | ciphertext_length:u64be | nonce:12 | ciphertext:N | tag:16
chunk record × payload_layout.chunk_count:
  "CHK3" | index:u64be | ciphertext_length:u32be | nonce:12 | ciphertext:N | tag:16
EOF (no trailer and no trailing bytes)
```

`u64be`/`u32be` 为无符号 big-endian。manifest record 正好一个且必须先于 chunk records。v3 binary record 使用当前 `EncryptedManifest`/`EncryptedPayloadChunk` 对应的原始 nonce、ciphertext、tag 字节，不使用 Base64；不改变 AES-GCM 算法、随机 nonce 长度或 tag 长度。chunk index 必须从 0 连续递增，且最终数量等于经 header HMAC 认证的 `payload_layout.chunk_count`。所有记录读完后必须精确 EOF。文件中间 EOF、record magic 错误、重复/跳号、额外数据一律拒绝。

为了保持密文 chunk 的 AEAD 定义稳定，v3 沿用现有归档 payload AAD `HSE2:payload-chunk:v1:<global-index>`；record 中的 index 必须与下一个期望 index 相等。GCM tag 认证密文，manifest GCM tag 认证文件/路径/范围元数据，header HMAC 认证总 chunk 数和 cipher/header fields。总数、范围总和及精确 EOF 三者共同检测缺块、重复、重排和尾随内容，因此不另加自定义 trailer MAC 或 stream digest。header backup 的 SHA-256 只用于识别 body 是否与备份时相同，不参与解密可信判断。

v3 的 `payload_layout.payload_offset` 与 `footer_offset` 固定写 0，定义为保留字段；解析器不得据此 seek。这样可避免可变 header 长度和 rewrap 改变 header 长度时产生自指偏移。实际数据通过顺序 framing 定位。

### 3.3 资源上限

实现采用以下 v3 硬上限，超限必须在分配相应缓冲前拒绝：header JSON 1 MiB；加密 manifest 64 MiB；单块密文 16 MiB；归档 entry 数 1,000,000；UTF-8 相对路径 4,096 bytes。`chunk_size` 必须为 1 byte 至 16 MiB，块密文长度必须为 1 至 header 声明的 `chunk_size`。manifest 上限限制其 AEAD 解密和 JSON parse 峰值；内存验收预算需包含 JSON 对象展开开销。

### 3.4 创建与恢复事务语义

创建流程先构建 assembly plan 并校验源文件元数据，再加密 manifest 和 header，逐文件读源、逐块加密并写同目录临时归档。每个源文件处理时检查实际字节数与计划大小相符，防止计划后源文件变化导致块数错配。写完所有记录后 flush/fsync，再以当前 overwrite 规则替换目标；失败删除临时归档，既有目标保持不变。

解密先读取有界 header、解锁 wrapper、验证 header HMAC，再读取和验证有界 manifest，检查条目/路径/范围/总 chunk 数和目标路径安全性；以上步骤均在创建恢复文件之前完成。随后逐块认证、解密到当前文件的同目录临时文件。完成文件范围后校验实际写入长度与 manifest 文件大小，再原子提交该文件。认证失败时删除当前临时文件；已经提交的完整文件保留，且命令失败并指出 archive 未完整恢复。首版不承诺整棵目录 all-or-nothing，也不做断点续传。existing `--overwrite` 行为继续逐文件适用。

达到 O(chunk_size + bounded header + bounded manifest + fixed buffers) 内存上界；RSS 实测还需考虑 manifest JSON 对象展开。

### 3.5 Wrapper 重包与 header backup

wrapper 操作只解析 header、解锁 MEK、验证旧 header tag、生成新 tag，然后在同目录临时文件中写新 header，并以固定缓冲从旧归档 body 流式复制到新归档。这样不重新加密 payload，也不把 body 载入内存。变长 header 会改变 body_offset；重包必须按新 frame 长度重新计算备份元数据，不能复用旧 offset。

header backup 仍作为恢复 header 的载体。body 定义为 header frame 最后一个字节之后至容器 EOF 的全部字节，即从 manifest record magic 开始；创建备份和恢复时以固定缓冲扫描并计算 SHA-256、body size 和 container size。restore 必须验证 metadata format、offset、size、container size 和 digest 一致。v3 使用新的 metadata format 标记，旧格式继续服务 v2。body 摘要仅检查 body 是否与备份时相同，不代替 header HMAC 或 payload AEAD。

### 3.6 错误与兼容行为

- v2 继续可读、可做现有操作；不承诺其大归档有界内存。
- v3 reader 不接受缺失/截断/超长 frame，不接受错误顺序和尾随数据。
- 密码错误、header tag 失败应在写出任何恢复数据之前失败；块认证失败则删除当前 staging 临时文件。
- 创建/重包输出在完整成功前不替换目标；overwrite 规则与既有 CLI 行为一致。
- 暂不做随机访问、断点续传、并行加密、原位 wrapper 重包或 v2 自动迁移。

## 4. 实施顺序与验收切片

以下是本地 issue 草案，不代表已在 GitHub 创建。

### M1.1 — 冻结 HSE2 v2 兼容契约与 v3 framing ADR

交付：已在本节记录字节布局、字段宽度、上限、版本 dispatch、失败语义、header backup v3 metadata 和现有 payload AAD 兼容选择。

验收：协议文档可逐字节重建 v3 格式；格式设计不增加新的密码原语；实现中的 v2 reader 仍保持原路径。v2 fixture dispatch 与 v3 malformed-frame 互操作属于 M1.2/M1.7 测试门槛。

### M1.2 — 有界 v3 frame reader/writer 与原子文件输出

交付：二进制读写原语、短读/EOF/溢出保护、record 顺序检查、流式复制和临时文件原子提交。

验收：不调用 `Path.read_bytes()` 或构造全容器 bytes；固定缓冲可注入；损坏 frame 在越界分配前拒绝；失败时既有目标保持不变。

### M1.3 — HSE2 archive 创建改为流式写入

交付：从 assembly plan 生成 manifest，逐输入文件和逐块加密并写 v3；文件以 header 中认证的 chunk count 和精确 EOF 结束。

验收：空文件、空目录、多文件、分块边界和大文件语义稳定；任一输入/写盘失败不会留下可被误认完整的目标归档；峰值内存不随 payload 总量线性增长。

### M1.4 — v3 archive 流式验证与恢复

交付：v2/v3 分派恢复、逐块解密、单文件 staging 与完整性检查。

验收：错误密码在目标写入前失败；块篡改、截断、顺序错乱和尾随数据均失败；失败文件不出现在正式路径；既有 overwrite 规则有显式回归覆盖。

### M1.5 — Wrapper 操作和 header backup 流式化

交付：list 仅读 header；add/remove/destroy 以流式 body copy 重包；backup digest/restore validation 流式扫描。

验收：重包前后加密 body 字节逐字节相同；只变化 header 时新 body offset 与摘要正确；大文件操作不将 body 装入内存；旧 v2 backup 仍能恢复 v2。

### M1.6 — CLI/GUI 接入与兼容说明

交付：格式选择/自动识别、进度与取消、错误呈现、文档将“单文件流式”和“HSE2 归档流式”区分。

验收：新旧归档行为在 CLI/GUI 一致；取消后临时文件清理；用户不会把 v2 内存特性误解为 v3；EXE 清单包含实际调用模块。

### M1.7 — 安全、兼容与资源验收

交付：固定 v2/v3 fixtures、畸形 frame 与密码学篡改用例、有界内存基准，以及 Windows 原子替换验收记录。

验收：所有 v2 fixtures 仍可解密；v3 跨版本 fixture 可交换；大文件峰值内存有明确预算并与总 payload 大小解耦；运行测试与基准前后记录提交、命令、结果。

## 5. 进度与下一步门槛

M1.1 规格已收敛。M1.2 已完成 v3 header frame、manifest/chunk body record、精确 chunk count/EOF 读取原语和路径级流式读写 adapter。header callback 在读取 manifest 前完成认证；写入按同目录临时文件原子提交。2026-10-28 在 Python 3.13 独立虚拟环境验证：v3 stream 23 tests、v3 file I/O 10 tests、v2 codec/model/header/auth 31 tests、v2 file I/O/header backup 11 tests 均通过。

M1.2 路径级 adapter 已实现并通过针对性测试。未运行全量测试套件。

已运行命令：

```powershell
work\hse2-test-venv\Scripts\python.exe -m unittest discover -s tests -p "test_hse2_v3_container_stream.py" -v
work\hse2-test-venv\Scripts\python.exe -m unittest discover -s tests -p "test_hse2_v3_file_io.py" -v
work\hse2-test-venv\Scripts\python.exe -m unittest tests.test_hse2_container_codec tests.test_hse2_models tests.test_hse2_header tests.test_hse2_header_auth -v
work\hse2-test-venv\Scripts\python.exe -m unittest tests.test_hse2_file_io tests.test_hse2_header_backup -v
```

结果：M1.2 上述 4 组共 75 次测试通过。M1.3 已新增 v3 创建内部 workflow：基于 assembly plan 逐块加密并懒惰消费，校验创建期间源文件大小未变化，写入同目录临时文件并原子替换。`container_format_version` 默认仍为 2，因此 CLI 沿用既有安全行为；v3 暂只通过 workflow 参数调用，待 M1.4 reader 完成后再接入用户入口。

M1.3 验证：新增测试覆盖空文件、多文件 chunk range、连续索引、密文解密内容、v3 chunk 上限、计划后源文件增长时保留旧目标并清理临时文件、默认 v2 可读。专门测试禁止 v3 路径调用 `_build_payload_chunks`，用于验证不构造全量密文 tuple。新测试 4/4 通过；既有 create CLI、空文件 CLI、archive assembly plan 与 payload 回归 24/24 通过。未运行全量测试套件。

已运行命令：

```powershell
work\\hse2-test-venv\\Scripts\\python.exe -m unittest discover -s tests -p "test_hse2_archive_v3_create.py" -v
work\\hse2-test-venv\\Scripts\\python.exe -m unittest tests.test_hse2_create_cli tests.test_hse2_create_cli_empty_file tests.test_hse2_archive_assembly_plan tests.test_hse2_archive_payload -v
```

M1.4 已完成 v2/v3 自动分派。v3 恢复先校验 header HMAC、解密并预校验 manifest 的路径、条目、chunk 范围和目标冲突，再逐块解密到当前文件的同目录 staging 文件，验证文件长度和归档 EOF 后原子提交。chunk 认证或格式错误会丢弃当前 staging 文件；此前已提交的完整文件可能保留，符合设计中的逐文件提交语义。CLI 复用既有 `open_hse2_archive`，因此可读取 v3，不需要单独的格式开关。

M1.4 验证：新增 `tests/test_hse2_archive_v3_open.py` 9/9 通过，覆盖空文件/多文件/分块边界恢复、错误密钥和错误 header HMAC 在输出前失败、穿越路径与错误 chunk range 在输出前拒绝、chunk 篡改、截断、尾随数据、覆盖策略及 v2 恢复。另与 v3 stream/file I/O、CLI、v2 file I/O/header backup 回归共 57/57 通过。未运行全量测试套件。

已运行命令：

```powershell
work\\hse2-test-venv\\Scripts\\python.exe -m unittest discover -s tests -p "test_hse2_archive_v3_open.py" -v
work\\hse2-test-venv\\Scripts\\python.exe -m unittest tests.test_hse2_v3_container_stream tests.test_hse2_v3_file_io tests.test_hse2_archive_v3_open tests.test_hse2_open_cli tests.test_hse2_file_io tests.test_hse2_header_backup -v
```

M1.5 已完成。wrapper list 现在仅读 v2/v3 header；新增内部 add wrapper workflow，add/remove/destroy 均以固定 128 KiB 缓冲复制 body，并通过同目录临时文件原子提交。v3 access destroy 需要 unlock material，以便移除所有 wrapper 后仍为 header 写入有效 HMAC。header backup path API 现在流式扫描 body digest，并支持 v3 专用 metadata format；restore 流式验证 offset/size/container size/digest 后才提交输出，v2 v1 metadata 兼容保留。header 变化时按新 header frame 长度自然形成新 body offset。

M1.5 验证：新增 `tests/test_hse2_v3_streaming_ops.py` 7/7 通过；与 v3 frame/file I/O、M1.3/M1.4 workflow、既有 wrapper CLI、header backup CLI 和 v2 file I/O 回归合计 78/78 通过。覆盖 wrapper add/remove/destroy 及 body 逐字节一致、更新后 header 认证、新 wrapper 密码可解锁、header-only list、失败重包保留旧目标并清理 staging、v3 backup/restore 对损坏 header 的恢复、body digest 篡改拒绝、v2 backup 格式兼容。未运行全量测试套件。

已运行命令：

```powershell
work\\hse2-test-venv\\Scripts\\python.exe -m unittest discover -s tests -p "test_hse2_v3_streaming_ops.py" -v
work\\hse2-test-venv\\Scripts\\python.exe -m unittest tests.test_hse2_v3_container_stream tests.test_hse2_v3_file_io tests.test_hse2_archive_v3_create tests.test_hse2_archive_v3_open tests.test_hse2_v3_streaming_ops tests.test_hse2_access_management_cli tests.test_hse2_header_backup tests.test_hse2_header_backup_cli tests.test_hse2_open_cli tests.test_hse2_file_io -v
```

M1.6 已完成 CLI/GUI 可用边界内的接入：create CLI 新增 `--format-version 2|3` 且默认 v2；open 自动识别；wrapper CLI 支持 add/list/remove；v3 access destroy CLI 支持密码、keyfile 或 DPAPI 解锁材料；GUI access destroy 显示并传递这些材料。创建结果与 wrapper list/add JSON 都报告格式版本。README 明确说明 v2 默认、v3 选择、自动识别及 GUI 当前未提供 archive create/open、wrapper add、header backup。`pyproject.toml` 现有 console entrypoints 和 setuptools 自动发现规则覆盖这些模块，仓库内未发现单独的 PyInstaller spec/hidden-import 清单。

M1.6 定向验证：新建 `tests/test_hse2_v3_cli_integration.py` 5/5 通过；与 create/open/access/header-backup CLI 和 GUI action/tab 回归合计 67/67 通过；`git diff --check` 通过。测试覆盖默认 v2 与显式 v3 创建、open 自动分派、wrapper add/list/remove、新密码解锁、v3 access destroy header 认证标记、header backup v3 导出/恢复、入口脚本存在以及 GUI 不暴露未实现归档控制。尚未覆盖 GUI 归档创建/恢复、进度/取消、可执行文件打包运行和 Windows 原子替换；它们不在当前 GUI/本仓库打包清单中，不能记为通过。未运行全量套件。

已运行命令：

```powershell
work\\hse2-test-venv\\Scripts\\python.exe -m unittest tests.test_hse2_v3_cli_integration tests.test_hse2_create_cli tests.test_hse2_open_cli tests.test_hse2_access_management_cli tests.test_hse2_header_backup_cli tests.test_hse2_gui_actions tests.test_hse2_gui_tab -v
git diff --check
```

M1.7 本机验收已完成。新增固定归档样本：v2 fixture 由基线提交 `fdb7cb5`（2026-07-26，v3 实现前）生成，v3 fixture 由当前 v3 writer 生成；测试固定 SHA-256 并分别验证 header format version 与解档明文。基线 v2 fixture 的 hash 为 `44be3d3405f3b0bd4b0df01bd0493181440575505dc010ea91e13dbe1875f9b2`，v3 fixture 的 hash 为 `8676572a59a12cfc513dc4dd9a7a9c63fe867d4241dfc8ba3ff4fdc1a0b4c163`。现有回归还覆盖 record magic/长度/索引、字段边界截断、精确 EOF、header HMAC 与 chunk AEAD 篡改、错误密钥、manifest 路径和范围校验，以及原子写入失败保留旧目标并清理临时文件。

双向独立代码路径对照已通过：测试参考实现 `tests/interop_reference/hse2_v3_reference.py` 不导入项目包；独立 writer 生成的容器由项目 reader 解档，项目 writer 创建的容器由独立 reader 解档。两个方向都覆盖 3 个文件（空文件、嵌套路径和多 chunk），并核对恢复路径、长度和 SHA-256。测试命令为 `work\hse2-test-venv\Scripts\python.exe -m unittest tests.test_hse2_v3_independent_interop -v`，结果 2/2 通过。参考实现 identity 为本仓库测试目录内的本地参考代码（当前工作区版本，尚未提交），不是第三方发行版；不将其描述为外部供应商认证。

M1.7 验证运行环境：Windows 11 专业工作站版 build 26300、Python 3.13.15；执行时 Git HEAD 为 `fdb7cb55f6458736f69a43b83710fa0780bc7e94`，工作区包含本路线图实现的未提交变更。M1 定向回归 146/146 通过；2026-10-31 后续增加 wrapper rewrap 和格式文档更新后，全量测试套件为 593 项通过、6 项跳过。Windows 原子替换两个用例在该 Windows 环境中实际运行并通过。

资源基准脚本 `build_tools/benchmark_hse2_v3_memory.py` 以独立 Python worker 分别测 create/open 的 tracemalloc heap 峰值和 Windows 进程峰值 working set。8 MiB 对比 128 MiB、允许增长 32 MiB 时：create heap 7.68→7.68 MiB、working set 41.35→41.68 MiB；open heap 7.67→7.68 MiB、working set 41.40→41.12 MiB。两项路径均通过增长预算。该结果是单机性能证据，不构成所有 manifest 尺寸/内存压力下的上限证明。

已运行命令：

```powershell
work\hse2-test-venv\Scripts\python.exe -m unittest tests.test_hse2_v3_fixtures tests.test_hse2_v3_container_stream tests.test_hse2_v3_file_io tests.test_hse2_archive_v3_create tests.test_hse2_archive_v3_open tests.test_hse2_v3_streaming_ops tests.test_hse2_v3_cli_integration tests.test_hse2_create_cli tests.test_hse2_open_cli tests.test_hse2_access_management_cli tests.test_hse2_header_backup_cli tests.test_hse2_gui_actions tests.test_hse2_gui_tab tests.test_hse2_container_codec tests.test_hse2_header_auth tests.test_hse2_file_io tests.test_hse2_header_backup -v
work\hse2-test-venv\Scripts\python.exe -m unittest discover -s tests -q
work\hse2-test-venv\Scripts\python.exe build_tools\benchmark_hse2_v3_memory.py --small-mib 8 --large-mib 128 --max-growth-mib 32
git diff --check
```

外部实现互操作尚未验证：仓库内参考实现提供了独立编码/解码路径的双向证据，但不是第三方实现；此前检查的远端旧分支和 release tag 均不支持 v3。若需要对外部版本兼容性作保证，仍需找到并记录另一个 v3-capable 发行版的准确版本，再做双向读写和明文哈希核验。

2026-10-31 对远端候选分支 `feature/hse2-streaming-helpers`（`f3e537a3514abe8497858979bdb3624902241983`）做只读检查。该分支包含早期 streaming helper，但在其 `src`、`docs`、`tests` 中没有 `MNF3`、`CHK3` 或 v3 format-version 声明，因此不能作为 M1.7 的 v3 互操作端。本轮远端 refs 名称筛查未发现其他明显的 v3/streaming 候选；没有逐一审查所有 release tag。远端 `master` 与本地当前提交 `e489ed8` 一致。

继续检查最新 release tag `v0.6.0-alpha.7`（提交 `37a99c78cc43a289cf53a76c771c8010cc1a3a77`）：该版本没有 `container_stream.py`、v3 测试模块、`MNF3`、`CHK3` 或 format version 3 声明，不能作为第二个 v3-capable 版本。
2026-10-31 GUI wrapper 端到端验收：在隔离临时目录中以 GUI 将 `recovery-gui` 替换为 `recovery-gui-v2`。GUI 日志报告原 wrapper 数量 2、结果数量 2、替换 ID 正确且退出码 0；wrapper list 显示原 `password-1` 与新 `recovery-gui-v2`，旧 recovery ID 不存在。新密码与原始密码均成功解档并匹配载荷；旧 recovery 密码无法解锁。比较 rewrap 前后的 header 后数据体，604 字节逐字节相同，SHA-256 为 `91d17d13cd412f743697a2fb9a8417faf19f744cef5480e1521811badfe34c80`。GUI wrapper add 测试也已通过，旧/新增密码均可解档。所有凭据和容器均为一次性测试样本，保留在 `%LOCALAPPDATA%\Temp\hse2-wrapper-gui-2807583301e34c37a9999ebdae829bbf`，未自动删除。

此前最终回归：`work\hse2-test-venv\Scripts\python.exe -m unittest discover -s tests`，599 项通过、6 项跳过。之后新增的独立参考互操作定向测试 2/2 通过；`git diff --check` 通过。外部发行版互操作仍需另一个外部 v3-capable 实现。
