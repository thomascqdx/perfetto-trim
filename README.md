# Perfetto Trim（pftrim）

按时间线裁剪、切割 Android Perfetto trace 的小工具。输出仍是标准的
`.perfetto-trace`，可以直接用 Perfetto UI / trace_processor 打开；不经过
systrace 转换，窗口内的信息不丢失。适合 GB 级的大 trace：流式处理，内存
占用与文件大小无关。

- **裁剪（cut）**：截取一个时间区间。
- **切割（split）**：按份数、时长或大小切成多段，可加重叠。
- **查找（find）**：按 atrace slice 名或 logcat 内容查找，截取匹配附近的区间。
- **概况（info）**：时间范围、数据类型、CPU、密度分布、应用启动标记。

## 快速开始

1. 把 `pftrim.exe` 放到任意目录（不需要安装 Python）。
2. **双击运行**：控制台窗口会显示地址，并自动打开浏览器。关闭控制台窗口即退出。
3. 打开 trace：在页面顶部粘贴路径后点“打开”，或点“选择文件”；也可以在资源管理器选中
   文件按 Ctrl+Shift+C，回到页面空白处 Ctrl+V 直接打开，或把文件 / 文件夹拖进页面。
4. 在时间轴上拖动选出区间，点“裁剪选中区间”。输出文件默认写到输入文件所在目录。

首次打开一个文件需要扫描一遍（1.5 GB 约 1.5 分钟），扫描结果会缓存，再次打开同一文件是即时的。

## 网页界面

- **打开文件**：首页列出最近打开的文件（可单条移除或清空，已不存在的显示为灰色）。
  浏览器拖放拿不到文件的真实路径，pftrim 不会上传或复制文件，而是按文件名、大小、
  修改时间在最近打开过的目录（及其上一级）、下载、桌面、文档里查找原文件；找不到时
  请改用 Ctrl+Shift+C / Ctrl+V 粘贴路径，打开一次后同目录的文件即可直接拖放。
  拖入文件夹会列出其中的 trace 供选择。
- **时间轴**：柱高表示数据密度。拖动选择区间，拖动区间边缘微调，滚轮缩放，
  Shift+滚轮平移，双击复位；键盘：←/→ 平移，+/- 缩放，Esc 清除选择。
  蓝色条是检测到的应用启动区间。
- **裁剪**：起点/终点可以直接输入（秒，相对 trace 起点）。“预计大小”是按扫描
  得到的数据分布估算的。
- **切割**：选择按份数 / 按时长 / 按大小，切点会实时显示在时间轴上。
- **查找**：输入关键字后列出所有匹配；点击一行会把区间设为“匹配前后各 N 秒”并
  放大到那里；勾选多条后可一次截取（只读一遍原文件）。
- **输出目录**：留空则写到输入文件所在目录。完成后可“打开输出目录”。

页面只监听本机 `127.0.0.1`，每次启动生成随机口令，其他网页或其他电脑无法调用。

## 命令行

带参数运行即为命令行模式（`pftrim.exe <命令> ...`）。

```powershell
# 概况
pftrim info trace.perfetto-trace
pftrim info trace.perfetto-trace --json

# 裁剪：相对时间（相对 trace 起点）
pftrim cut trace.perfetto-trace --start 12.5s --duration 10s
pftrim cut trace.perfetto-trace --start 12.5s --end 22.5s -o D:\out
# 裁剪：最后 5 秒；绝对时间戳（纯整数，单位 ns）
pftrim cut trace.perfetto-trace --last 5s
pftrim cut trace.perfetto-trace --start 343631134880526 --end 343641134880526

# 切割
pftrim split trace.perfetto-trace --parts 4
pftrim split trace.perfetto-trace --every 30s --overlap 500ms
pftrim split trace.perfetto-trace --size 200MB

# 查找：列出匹配；截取第 3 条 / 全部（前后各 2 秒）
pftrim find trace.perfetto-trace DrawFrames --list
pftrim find trace.perfetto-trace "Choreographer#doFrame" --pick 3
pftrim find trace.perfetto-trace "ANR" --source logcat -i --all --before 5s --after 5s

# 网页界面（与双击相同）
pftrim ui --port 8765 --no-browser
```

| 参数 | 说明 |
|---|---|
| 时间 | `3.5s`、`1200ms`、`800us`；纯整数表示绝对时间戳（ns） |
| 大小 | `200MB`、`1.5GB`、`512KB` |
| `--keep-original-ts` | 带入的状态保留原始时间戳（默认改到区间起点，避免 UI 前段空白） |
| `--no-cache` | 不使用、不写入扫描缓存 |
| `-j N` / `--jobs N` | 并行解析进程数，默认 CPU 数-1（最多 3）；`-j 1` 单进程。结果与进程数无关 |
| find `--regex` / `-i` | 正则匹配 / 忽略大小写 |
| find `--source` | `atrace`、`logcat` 或 `all`（默认） |

## 输出说明

- 文件名：`<原名>__<起点ns>-<终点ns>.perfetto-trace`，时间戳是原 trace 中的绝对时间。
  区间是左闭右开 `[起点, 终点)`。
- 每次运行另写一个 `*.report.json`：实际窗口、各输出大小、警告、已知限制。
- `*.boundary.csv`：跨越区间边界的 slice 清单（真实开始、结束、时长），方便核对
  被切断的 slice 原本有多长。
- 保留规则：
  - 元数据（trace_config、clock_snapshot、process 信息、统计等）每个输出都保留；
  - ftrace 事件逐条按时间过滤，完全在区间内的数据包原样拷贝；
  - logcat 按每条日志的时间过滤；
  - 不认识的数据类型整包原样保留。
- **带入状态**：区间开始时已经存在的状态会补进输出，使 Perfetto 里看到的与原
  trace 一致：每个 CPU 正在运行的线程、CPU 频率 / idle、未结束的 atrace slice
  （同步、异步、命名轨道）、atrace 计数器当前值、跨边界的 binder 事务、
  sys_stats / process_stats 最近一份快照、进程与线程名。区间结束时仍未结束的
  slice 会在区间末尾补上结束事件。

正确性以 trace_processor 为准做了逐表对照：sched、thread_state、slice、counter、
android_logs、frame timeline，以及 trace 起止时间。

## 性能参考

测试机：12 线程 CPU、32 GB 内存；1.5 GB 真实 trace（288 秒，4670 万个 ftrace 事件）。

| 操作 | 耗时 | 内存峰值（含工作进程） |
|---|---|---|
| 首次打开 / info（扫描） | 95 s | 约 380 MB |
| 裁剪中间 10 秒 | 85 s | 约 460 MB |
| 切成 4 段 | 138 s | 约 500 MB |
| 查找关键字 | 110 s | 约 50 MB |

用绝对时间戳裁剪时不需要扫描；相对时间、切割、查找会复用扫描缓存
（`%LOCALAPPDATA%\pftrim\cache`）。

## 已知限制

- 不支持按进程或数据类型过滤（会破坏数据完整性）。
- Chrome / App SDK 的 track_event 按数据包整体保留，不做精细裁剪。
- 区间开始时处于非运行状态（睡眠等）的线程，其状态不会补出；lmk 的
  oom_score_adj 计数器不补。
- 区间开始前的快照类数据（sys_stats 等）如果在文件中出现得很晚（晚于输出中
  第一次缓冲区刷新），不会被带入。
- 使用 `--keep-original-ts` 时，区间附近少量 binder reply slice 可能显示为未结束。

## 常见问题

- **双击后浏览器没有打开**：复制控制台里显示的完整地址（含 `#t=...`）到浏览器。
- **页面提示“页面已失效”**：程序重启后口令会变，请使用新窗口里显示的地址。
- **杀毒软件拦截 exe**：单文件 exe 运行时会解压到临时目录，个别杀毒软件会误报，
  可加入信任列表。
- **输出比预计大**：每个输出都会复制一份元数据和带入状态（几 MB）；
  heapprofd 的一次 dump 不可拆分。

## 开发

源码结构、构建、测试、打包命令见 [`AGENTS.md`](AGENTS.md)，设计说明见
[`docs/PLAN.md`](docs/PLAN.md)。打包：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1   # -> dist\pftrim.exe
```
