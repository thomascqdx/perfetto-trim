"""`pftrim info` -- human-readable scan summary (Chinese)."""

from __future__ import annotations

import os
import sys
import time

from ..index import load_or_scan
from ..timespec import format_ns, format_size

_WARN_LABELS = {
    "unknown_clock": "未知时钟（无法换算的时间戳数）",
    "ftrace_lost_events": "ftrace 丢失事件数",
    "ftrace_out_of_order_events": "ftrace 乱序事件数",
    "ftrace_errors": "ftrace bundle 错误数",
}

_FLAG_LABELS = {
    "has_logcat": "logcat (android_log)",
    "has_frame_timeline": "帧时间线 (frame timeline)",
    "has_track_event": "track_event",
    "has_heapprofd": "heapprofd",
    "has_perf": "traced_perf",
    "has_battery": "电池计数器",
    "has_power_rails": "功耗轨 (power rails)",
}


def _progress_stderr():
    last = [0.0]

    def cb(done, total):
        now = time.monotonic()
        if now - last[0] < 0.2 and done < total:
            return
        last[0] = now
        pct = done * 100 // total if total else 0
        sys.stderr.write(f"\r扫描中 {pct}% ({format_size(done)}/{format_size(total)})")
        sys.stderr.flush()
    return cb


def _finish_progress():
    sys.stderr.write("\r" + " " * 60 + "\r")
    sys.stderr.flush()


def render_text(res) -> str:
    lines = []
    L = lines.append
    L(f"文件: {res.path}")
    size_s = format_size(res.file_size)
    extra = []
    if res.gzip:
        extra.append("gzip")
    if res.had_compressed_packets:
        extra.append("compressed_packets")
    L(f"大小: {size_s}" + (f"（{', '.join(extra)}）" if extra else ""))
    if res.start_ns is not None:
        L(f"时间范围: [{res.start_ns}, {res.end_ns}] ns"
          f"（时长 {format_ns(res.duration_ns)}）")
    else:
        L("时间范围: 无带时间戳的事件")
    L(f"packet 数: {res.packet_count}")
    L("")

    L("数据类型（按字节排序，前 12 项）:")
    types = sorted(res.per_type.items(), key=lambda kv: kv[1].bytes,
                   reverse=True)[:12]
    for name, st in types:
        ts = ""
        if st.min_ts is not None:
            ts = f"  [{format_ns(st.min_ts - res.start_ns)} ~" \
                 f" {format_ns(st.max_ts - res.start_ns)}]" \
                 if res.start_ns is not None else \
                 f"  [{st.min_ts} ~ {st.max_ts}]"
        L(f"  {name:<32} {st.count:>8} 个  {format_size(st.bytes):>10}{ts}")
    if len(res.per_type) > 12:
        L(f"  … 共 {len(res.per_type)} 种类型")
    if res.untimed_packets:
        L(f"  无时间戳数据: {res.untimed_packets} 个 packet,"
          f" {format_size(res.untimed_bytes)}")
    L("")

    ft = res.ftrace
    if ft["bundles"]:
        L(f"ftrace: {ft['bundles']} 个 bundle,"
          f" {sum(ft['event_counts'].values())} 个事件"
          f"（compact sched_switch {ft['compact_switch_events']} /"
          f" sched_waking {ft['compact_waking_events']}）")
        top = sorted(ft["event_counts"].items(),
                     key=lambda kv: kv[1], reverse=True)[:8]
        L("  事件 TOP: " + ", ".join(f"{k}={v}" for k, v in top))
        cpus = sorted(ft["per_cpu"])
        L(f"  CPU: {len(cpus)} 个 ({', '.join(str(c) for c in cpus[:16])}"
          f"{'…' if len(cpus) > 16 else ''})")
    flags = [_FLAG_LABELS[k] for k in _FLAG_LABELS if res.flags.get(k)]
    if flags:
        L("包含: " + "、".join(flags))
    if res.markers:
        L(f"标记: {len(res.markers)} 个"
          f"（如应用启动: {res.markers[0]['label']}）"
          + ("（已截断）" if res.markers_truncated else ""))
    if res.trace_config:
        cfg = res.trace_config
        bufs = sum(cfg.get("buffer_size_kb") or [])
        L(f"trace_config: 时长 {cfg.get('duration_ms')} ms,"
          f" buffer 共 {bufs} KB,"
          f" 数据源 {', '.join(cfg.get('data_sources') or [])}")
    if res.sequences:
        inc = sum(1 for s in res.sequences.values() if s.incremental)
        L(f"序列: {len(res.sequences)} 条"
          + (f"（其中 {inc} 条使用增量状态）" if inc else ""))
    if res.warnings:
        L("")
        L("警告:")
        for k, v in res.warnings.items():
            L(f"  {_WARN_LABELS.get(k, k)}: {v}")
    L("")
    src = "缓存命中" if res.cache_hit else f"本次扫描耗时 {res.scan_time_s:.2f}s"
    L(f"({src})")
    return "\n".join(lines)


def run(path, *, json_out=False, use_cache=True, progress=True) -> int:
    if not os.path.isfile(path):
        print(f"错误: 文件不存在: {path}", file=sys.stderr)
        return 2
    cb = _progress_stderr() if (
        progress and not json_out and sys.stderr.isatty()) else None
    try:
        res = load_or_scan(path, progress=cb, use_cache=use_cache)
    except Exception as e:
        print(f"错误: 无法解析 trace 文件: {e}", file=sys.stderr)
        return 2
    finally:
        if cb:
            _finish_progress()
    if json_out:
        import json as _json
        print(_json.dumps(res.to_dict(), ensure_ascii=False))
    else:
        print(render_text(res))
    return 0
