# pftrim 开发计划

> 工具名：工程/包名 `pftrim`，exe 与 UI 标题 `Perfetto Trim`。
> 用途：在普通 Windows 电脑上，以有限内存对 GB 级 Android perfetto trace 按时间线裁剪/切割，输出仍为标准 `.perfetto-trace`，窗口内信息不丢失。

## 1. 目标与范围

**第一版范围**

- 数据：Android 端 trace —— ftrace/atrace、进程信息、logcat、frame timeline、电源/电池计数器、sys_stats、heapprofd/traced_perf 等。
- 功能：`info` 概况、按时间段截取（cut）、按大小/份数/时长切割（split）、按关键字定位截取（find）。
- 形态：本地网页 UI + 命令行，打包为单个 exe。

**第一版不做**

- 按进程、按数据类型过滤（会破坏完整性；以后作为"导航用轻量版"单独做）。
- Chrome / App SDK 的 track_event 精细裁剪（这类数据按规则整包正确保留，但不精细裁剪）。
- 修改或新增 trace 中的事件内容。

## 2. 工程与环境

| 项 | 方案 |
|---|---|
| 目录 | `D:\codes\sagereal\pftrim\` |
| 版本管理 | git，主分支 `main`，按里程碑提交并打 tag（`v0.1.0` …） |
| Python | `py -3.13 -m venv .venv`，依赖只装在 `.venv`，不影响全局 |
| 运行时依赖 | **仅 Python 标准库**；自实现最小 protobuf wire 编解码 |
| 开发依赖（固定版本，`requirements-dev.txt`） | `pytest`；`perfetto==0.58.2`（测试用 trace_processor + 生成字段编号表）；`pyinstaller==6.17.0` |
| trace_processor | 测试中用于等价性对比；通过环境变量 `PFTRIM_TP_BIN` 固定版本，默认用本机已缓存的二进制 |
| 测试数据 | 大 trace 不进 git，放 `testdata/`（ignored）；提交 `testdata/MANIFEST.json` 记录文件名、sha256、来源、用途 |
| 文档 | `AGENTS.md`（构建/测试/打包命令）；`README.md`（中文，面向团队使用者） |

**目录结构**

```
pftrim/
  pyproject.toml  requirements-dev.txt  .gitignore  README.md  AGENTS.md
  docs/PLAN.md
  src/pftrim/
    wire.py        protobuf wire 编解码（memoryview，尽量零拷贝）
    fields.py      字段编号常量（scripts/gen_fields.py 从 perfetto 格式定义生成，结果提交）
    reader.py      流式读取 packet；支持 .gz 与 compressed_packets；进度回调
    writer.py      流式写出，支持同时写多个输出
    clock.py       clock_snapshot 处理，统一换算到 BOOTTIME
    classify.py    packet 分类（元数据 / 快照 / 普通带时间戳 / 多事件包 / 增量状态）
    ftrace.py      ftrace bundle 逐条过滤、compact_sched 解码与重新编码
    state.py       边界状态跟踪 + 重排序缓冲区
    scan.py        第一遍扫描：时间范围、密度直方图、数据源大小、关键标记
    index.py       扫描结果 sidecar 缓存
    engine.py      单次读取、多窗口同时写出
    ops/           info / cut / split / find（CLI 与 UI 共用）
    cli.py  __main__.py
    web/           server.py + static/（原生 HTML/JS/canvas，无需 npm 构建）
  scripts/         gen_fields.py、make_big_trace.py、build_exe.ps1
  tests/           unit/  equivalence/  synthetic/  perf/
  testdata/        （不进 git）
```

## 3. 核心设计

### 3.1 流式处理

- 内存占用与 trace 大小无关：只保留当前 packet、边界状态和重排序缓冲区。
- 两遍处理（按需）：
  - 第一遍 scan：时间范围、密度直方图、数据源大小、关键标记，写入 sidecar 索引缓存。
  - 第二遍 engine：按时间窗口写出。
  - 用绝对时间戳 cut 时可跳过第一遍；相对时间 / split / find 需要扫描结果（有缓存则复用）。
- split 成 N 份时原文件只读一遍，同时写出 N 个文件。

### 3.2 packet 处理规则

| 类别 | Android 上的例子 | 规则 |
|---|---|---|
| 元数据 | trace_config、system_info、clock_snapshot、packages_list、trace_stats、ftrace_stats、service_event | 每个输出都整包保留 |
| 快照 | process_tree、process_stats、sys_stats | 保留窗口内全部 + 窗口开始前最后一份 |
| 普通带时间戳 | frame_timeline、电源/电池计数器、perf_sample | 按 packet 时间戳归入窗口 |
| 多事件包 | **ftrace_events**（含 compact_sched）、android_log | 拆开逐条过滤并重新编码；完全在窗口内的包原样拷贝；修正 `previous_bundle_end_timestamp` |
| 增量状态序列 | heapprofd、traced_perf（interned_data） | 带 interned_data / 增量状态重置标志的 packet 必须保留；同一次 dump 的多个 packet 整组归入同一份 |
| 未知类型 | 新版 Android 新增数据源 | **默认整包保留**，原始字节透传 |

### 3.3 边界状态延续

- 每个 CPU：窗口开始前最后一次 sched_switch、cpu_frequency、cpu_idle。
- 每个线程：未结束的 atrace B（同步）与 S（异步）slice；atrace 计数器（C）最后一个值。
- 跨窗口的 binder 收发配对。
- 重排序缓冲区：默认 2 秒（可配置），线程级状态先按时间排序再计算；按 CPU 的状态天然有序无需缓冲。乱序超出缓冲区时记录警告并写入输出报告。
- 带入状态的时间戳默认改到窗口起点（避免 UI 前段空白）；`--keep-original-ts` 保留原始时间戳。
- 生成跨切点 slice 清单 `*.boundary.csv`（真实开始、结束、时长）。

### 3.4 时间语义

- 内部统一纳秒级 BOOTTIME；非 BOOTTIME 时钟的 packet 借助 clock_snapshot 换算。
- 输入：相对时间 `3.5s` / `1200ms` / `800us`；绝对时间为纯整数（ns）；`--last 10s` 从结尾倒数。
- trace 起点按 Perfetto UI 规则计算，以 trace_processor 的 `trace_bounds` 做对照测试，必须一致。
- 输出文件名带原始绝对时间范围：`<原名>__<start_ns>-<end_ns>.perfetto-trace`。
- 每次运行生成报告（JSON + 一句中文摘要）：起点、实际窗口、各份大小、警告。

### 3.5 split 切点计算

- 第一遍扫描按 10ms 一格统计数据量；ftrace bundle 的字节按其中事件分摊到各时间格。
- 按累计数据量找切点，可加 overlap。
- 不可拆分的数据组（如一次 heap dump）导致某份超出目标大小时给出提示。

### 3.6 find

- 匹配来源：atrace slice 名（B/S/C）、logcat tag/内容；支持子串与正则。
- 列出全部匹配，可截取第 N 个或全部匹配（每个匹配前后各截一段，输出多个文件）。

## 4. 网页 UI

- `ThreadingHTTPServer` 仅监听 `127.0.0.1` 随机端口，启动后自动打开浏览器；每次启动生成随机 token，API 请求必须携带。
- 文件选择：不通过浏览器上传（GB 级不可行），由本地服务弹出 Windows 原生文件选择框（tkinter），只传路径；同时提供路径输入框和最近打开列表。
- 界面：时间轴密度柱状图 + 关键标记（应用启动、卡顿帧、logcat 匹配），可缩放；鼠标框选区间并实时显示预计输出大小；split 模式预览切点；find 结果列表点击即设置区间。
- 执行：后台任务 + 进度条（前端轮询）；完成后可打开输出目录。
- 可选：通过 ui.perfetto.dev 的 postMessage 方式直接打开小文件。

## 5. 打包

- PyInstaller 单文件 `pftrim.exe`，内含网页静态资源；窗口/界面标题 "Perfetto Trim"。
- 无参数双击 → UI 模式（保留控制台窗口显示日志与"关闭此窗口即退出"）；带参数 → 命令行模式。
- 打包脚本 `scripts/build_exe.ps1`；exe 写入版本信息；目标 Windows 10+。
- 测试中文路径、长路径、杀毒软件环境；如单文件 exe 被误报，改为目录形式发布。

## 6. 测试策略

| 层级 | 内容 |
|---|---|
| 单元测试 | wire 编解码往返；compact_sched 解码再编码与原字节**完全一致**；时间/大小参数解析；状态跟踪器 |
| 透传测试 | 不裁剪只读写一遍，输出与原文件**字节完全一致**（含 gz、compressed_packets） |
| 等价性测试（核心） | trace_processor 分别加载原 trace 与裁剪结果，同一组 SQL 对比窗口内 slice、sched、thread_state、counter、android_logs、frame timeline 等；边界项按 3.3 规则单独断言 |
| 完整性测试 | split 后各份事件合并（去掉 overlap）与原 trace 完全一致，无遗漏无重复 |
| 合成 trace | 自写小型 trace 构造器生成边界用例：乱序、窗口前开始的嵌套 slice、异步 slice、计数器、跨窗口 binder、压缩包、未知 packet 类型 |
| 性能测试 | 真实 trace 平移时间戳后拼接成 1/3/5 GB，测峰值内存与耗时 |

## 7. 里程碑

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M0 工程搭建** | git、venv、pyproject、依赖、.gitignore、AGENTS.md、gen_fields.py、testdata 清单、trace_processor 测试工具 | `pytest` 跑通空用例；能用 trace_processor 加载样本 trace |
| **M1 流式读写** | wire / reader / writer / clock，支持 gz 与 compressed_packets | 透传字节完全一致；内存不随文件变大 |
| **M2 scan 与 info** | 第一遍扫描、索引缓存、`pftrim info` | 起点/终点与 `trace_bounds` 完全一致；直方图与数据源统计正确 |
| **M3 cut（数据层面）** | ftrace bundle 过滤、compact_sched、3.2 分类规则、按 CPU 的状态延续 | 样本 trace 多个窗口（开头、中间、结尾、极短窗口）通过等价性测试 |
| **M4 边界状态** | 线程级 slice 栈、异步 slice、计数器、binder、重排序缓冲区、时间戳调整、跨切点清单 | 合成用例全部通过；UI 中裁剪结果开头无空白、无不配对 slice |
| **M5 split** | 按份数/时长/大小切割、overlap、单次读取多份写出 | 完整性测试通过；各份大小与目标偏差可接受 |
| **M6 find** | atrace 与 logcat 匹配，截取指定/全部匹配 | 带 logcat 的 trace 验证（需样本） |
| **M7 性能** | 大文件测试，定位并优化瓶颈 | 初步目标：3GB trace cut ≤ 10 分钟，峰值内存 < 500MB（以实测再调整） |
| **M8 网页 UI** | 第 4 节全部功能 | 样本 trace 手动走通完整流程；无 token 的 API 请求被拒绝 |
| **M9 打包发布** | exe 打包、中文 README、`v1.0.0` | 在无 Python 的电脑上双击即可使用 |

每个里程碑结束：测试全部通过 → 提交 → 打 tag → 汇报结果与示例输出。

## 8. 风险与待确认事项

1. trace 起点计算规则须与 Perfetto UI 一致 —— M2 用测试确认。
2. 纯 Python 速度 —— M7 未达标时，备选为热点路径专项优化或 Cython/Rust 扩展，依据实测数据再决定。
3. ring buffer 模式 trace 开头部分 CPU 数据可能已被覆盖 —— 确认裁剪不会使其更难理解。
4. 测试样本待提供：带 logcat 的 trace（M6）、真实 GB 级大 trace（M7）、带 frame timeline / heapprofd 的 trace；缺失时先用合成数据。
5. Perfetto 新版格式变化 —— 未知字段/类型整包透传不会出错；新的多事件包类型需补充适配。

## 9. 现有样本

- `trace_TECNO_TECNOKN8_20261105_113857.perfetto-trace`（约 32MB，约 10.95s）：99.6% 为 ftrace bundle（1098 个，约 73 万条事件，其中 1095 个含 compact_sched）；atrace print 约 44 万条；无 interned_data / track_event。
