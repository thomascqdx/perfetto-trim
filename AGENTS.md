# pftrim 开发说明

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
- trace_processor 二进制：环境变量 `PFTRIM_TP_BIN` 指定；默认用
  `~/.local/share/perfetto/prebuilts/trace_processor_shell-100334b6091596fb.exe`
  （v57.2，与 perfetto 0.58.2 对应）。
- 样本 trace 不进 git；`testdata/MANIFEST.json` 记录文件名、sha256、
  来源、用途，测试通过它定位文件，缺失时 `sample` 标记的测试自动 skip。

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

git 分支 `main`，里程碑提交 + tag 由负责人执行，子任务不要自行
commit/tag。
