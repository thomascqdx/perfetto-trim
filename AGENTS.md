# perfetto-trim 开发说明

## 命名约定

- 对外名称（exe / 命令 / pyproject / 文档 / HTTP 头）一律 `perfetto-trim`；
  Python 包名保持 `pftrim`（有意为之，类似 Pillow/PIL）——不要改
  `src/pftrim/`、import 或 `scripts/pftrim_entry.py`。
- 环境变量统一走 `pftrim.env.getenv`：新名 `PERFETTO_TRIM_*` 优先，
  兼容旧名 `PFTRIM_*`。
- golden 默认临时目录名保持 `pftrim_golden*`（黄金输出的位置，见「性能 / 并行」节的回归门禁）。

## 环境

- Windows + Python 3.13（`py -3.13`），虚拟环境在项目内 `.venv`。
- 首次搭建：

  ```powershell
  py -3.13 -m venv .venv
  .venv\Scripts\python -m pip install -e . -r requirements-dev.txt
  ```

- **运行时只用 Python 标准库**（`src/pftrim/` 不得 import 第三方包；
  protobuf wire 编解码在 `src/pftrim/wire.py` 自实现）。第三方包
  （perfetto/protobuf/pytest/pyinstaller）只允许出现在 `tests/` 和
  `scripts/`。

## 测试

```powershell
.venv\Scripts\python -m pytest            # 默认跳过 perf 标记的慢测试
.venv\Scripts\python -m pytest -m perf    # 只跑性能测试
```

- 标记：`tp`（需要 trace_processor 二进制）、`sample`（需要
  `testdata/` 里的样本 trace）、`perf`（慢速性能测试）。
- trace_processor 二进制：环境变量 `PERFETTO_TRIM_TP_BIN` 指定；默认用
  `~/.local/share/perfetto/prebuilts/trace_processor_shell-100334b6091596fb.exe`
  （v57.2，与 perfetto 0.58.2 对应）。
- 样本 trace 不进 git；`testdata/MANIFEST.json` 记录文件名、sha256、
  来源、用途，测试通过它定位文件，缺失时 `sample` 标记的测试自动 skip。
  第三个样本 `trace_TECNO_KN8_20261106_114131.perfetto-trace`（新版 KN8：
  ftrace 包在 ftrace_events 之后带 interned_data，track_event 跑在
  seq 8 的 sequence-scoped incremental clock 上）由
  `kn8_interned_trace` fixture 按文件名定位。
- `classify.classify_packet` 返回的 `data_fno` 是**决定类别的字段**
  （ftrace_events 之后跟 interned_data 的包仍返回 FTRACE_EVENTS）；
  只有纯 METADATA 包返回最后一个数据字段（engine 用它判断
  SERVICE_EVENT）。

## 性能 / 并行（M7）

- ftrace bundle 的逐事件解码在工作进程中并行（`src/pftrim/ftpar.py`
  的 `OrderedPool`），有序状态（ReorderBuffer / BoundaryTracker / 输出）
  只在主进程按文件顺序处理，**任何 jobs 值的输出都必须逐字节一致**。
  - `scan.scan_bundle` / `engine.engine_bundle` 是纯函数（worker 与
    jobs=1 共用同一实现）；需要主进程时钟状态的 bundle（ftrace_clock
    非默认）返回 None，由主进程按原位置重算。
  - 默认 jobs = min(CPU-1, 3)；CLI `-j N`，环境变量 `PERFETTO_TRIM_JOBS`。
    文件 < 64MB 不开进程池（`PERFETTO_TRIM_PAR_MIN_BYTES` 可覆盖，测试设 0）。
  - 乱序窗口是自适应的：scan 测量 `ftrace_max_lag_ns`（每个 bundle 最早
    事件落后已见最大事件 ts 的距离），ops 解析为
    clamp(lag + 250ms, 2s, 30s)；`Options.reorder_window_ns=None` 表示自动，
    run() 直接调用且无 scan 时回落 2s。
- 回归门禁：`scripts/golden_check.py` 对比黄金输出
  （`%TEMP%\pftrim_golden_out`），要求逐字节一致；多进程路径：
  `$env:PERFETTO_TRIM_PAR_MIN_BYTES=0; $env:PERFETTO_TRIM_JOBS=4` 后再跑一次。
  黄金输出由 `%TEMP%\pftrim_golden` worktree（detached，当前在 `v1.3.0`）
  的源码生成，6 个用例共 48 个输出文件。有意改变输出的修复发版后，把
  worktree `git checkout --detach vX.Y.Z` 并跑 `golden_check.py --regen`
  更新基准（需用户同意）。
- 基准：`scripts/bench.py <trace> --ops info,cut,split,find [--jobs N]`，
  报告 wall / 主进程峰值 / 进程树峰值（peak_tree_mb）。
- 大 trace TP 校验（慢，需 1.5GB 文件）：
  `.venv\Scripts\python -m pytest -m perf tests\equivalence\test_big_trace_tp.py`

## 网页 UI（M8）

- `perfetto-trim ui [--port N] [--no-browser]`；无参数运行 = UI 模式。
- 后端 `src/pftrim/web/server.py`（标准库 ThreadingHTTPServer，只听
  127.0.0.1）：`/api/*` 必须带 `X-Perfetto-Trim-Token`（每次启动随机，经 URL
  fragment `#t=` 交给页面）且 Host 为 127.0.0.1/localhost，否则 403。
  长操作是后台任务：`/api/jobs/<id>` 轮询、`/api/jobs/<id>/cancel`。
- 前端 `src/pftrim/web/static/`（原生 HTML/CSS/JS，无构建）。页面内时间
  一律用“相对 trace 起点的 ns”（JS number 精确），发给后端的绝对 ns
  用 BigInt 拼成字符串。
- 测试：`tests/unit/test_web.py`（token/Host 拒绝、路径穿越、全流程）。
  截图自查可用全局 Python 的 playwright（不是项目依赖）。

## 打包（M9）

```powershell
build.bat                # 一键：建/补 .venv -> pytest -> 打包 -> exe --version 自检
build.bat --skip-tests   # 跳过 pytest；--no-pause 结束时不等按键（脚本/CI 调用时加）
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1   # 只打包 -> dist\perfetto-trim.exe
```

- `build.bat` 检测到是被 `cmd /c` 启动（双击、或从 PowerShell 调用）时
  结尾会 `pause`；自动化调用务必加 `--no-pause`。失败返回非 0。
- PyInstaller 单文件、控制台程序；入口 `scripts/pftrim_entry.py`，静态
  页面以 `--add-data` 打进 `pftrim\web\static`，版本信息由脚本按
  `pftrim.__version__` 生成。
- `cli.main()` 第一行调用 `multiprocessing.freeze_support()`，冻结后的
  worker 进程才能正常启动——不要移动。
- 验收：exe 与源码运行的输出逐字节一致（含 `-j 3` 多进程、中文/带空格
  路径、PATH 中无 Python），`ui --no-browser` 可访问且无 token 返回 403。

## 重新生成字段编号表

`src/pftrim/fields.py` 是生成文件（头有 do-not-edit 注释），由
perfetto_trace_pb2 的 descriptor 生成：

调试工具：`scripts/diag_thread_stacks.py` 在样本上模拟 TP 的
per-incarnation（utid）线程身份模型 + 统一 slice 栈，与 TP 的
open-slice 状态做一致性对比（写报告/调试 BoundaryTracker 时用）。

```powershell
.venv\Scripts\python scripts\gen_fields.py
```

注意：perfetto 0.58.2 自带的 pb2 缺 `FrameTimelineEvent`（上游
v57.0 在 `frame_timeline_event.proto`，TracePacket field 76），
`gen_fields.py` 里 `EXTRA_MESSAGES` / `EXTRA_TRACE_PACKET_FIELDS`
手工补齐了这部分常量，升级 perfetto 包后请核对。

## 联网失败时

本机代理 `http://127.0.0.1:7890`：pip 加 `--proxy`，其他命令用
`$env:HTTPS_PROXY='http://127.0.0.1:7890'` 只对当次命令生效；
不要改全局 git/pip 配置。

## 提交

git 分支 `main`。里程碑提交和 tag 由主会话的 agent 执行，子任务/子代理
不要自行 commit/tag。

- 提交信息：英文一句话标题（发版提交用 `Release X.Y.Z: ...`），需要时
  正文说明原因，结尾附 Devin 署名行（照抄 `git log` 中已有格式）。
- tag：附注 tag `vX.Y.Z`，信息 `Perfetto Trim X.Y.Z`，打在发版提交上；
  发版前先改 `src/pftrim/__init__.py` 的 `__version__`。
- 未经用户明确要求不要 push（含 tag）。
- 本机默认 shell 是 Windows PowerShell 5.1：不支持 `&&`（用 `; if ($?) {...}`），
  `Set-Content` 没有 `utf8NoBOM`，`@'...'@ | git commit -F -` 也传不进去；
  多行提交信息先写到临时文件再 `git commit -F <file>`。
