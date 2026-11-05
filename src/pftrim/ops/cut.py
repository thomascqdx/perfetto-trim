"""pftrim cut: resolve time specs -> windows -> engine.run."""

from __future__ import annotations

import json
import os
import sys
import time as _time

from ..engine import Options, Window, run
from ..index import load_or_scan
from ..timespec import parse_duration, parse_size, parse_time


class CutError(Exception):
    pass


def resolve_windows(trace, args, *, use_cache=True) -> tuple[list, object | None]:
    """-> (windows, ScanResult|None). Scan skipped for absolute bounds."""
    start_s = args.get("start")
    end_s = args.get("end")
    dur_s = args.get("duration")
    last_s = args.get("last")

    if last_s is not None:
        scan = load_or_scan(trace, use_cache=use_cache)
        if scan.end_ns is None:
            raise CutError("trace 中没有带时间戳的数据，无法按 --last 裁剪")
        end_ns = scan.end_ns
        start_ns = end_ns - parse_duration(last_s)
    else:
        # need trace start for relative times / clamping
        need_scan = not (_is_absolute(start_s) and _is_absolute(end_s))
        scan = load_or_scan(trace, use_cache=use_cache) if need_scan else None
        base = scan.start_ns if scan else 0
        start_ns = parse_time(start_s, base)
        if end_s is not None:
            end_ns = parse_time(end_s, base)
        elif dur_s is not None:
            end_ns = start_ns + parse_duration(dur_s)
        else:
            if scan is None:
                scan = load_or_scan(trace, use_cache=use_cache)
            end_ns = scan.end_ns

    if scan is not None and scan.start_ns is not None:
        start_ns = max(start_ns, scan.start_ns)
        end_ns = min(end_ns, scan.end_ns if scan.end_ns else end_ns)
    if end_ns <= start_ns:
        raise CutError(
            f"裁剪窗口为空: [{start_ns}, {end_ns})，请检查时间参数")
    return [Window(start_ns, end_ns)], scan


def _is_absolute(spec) -> bool:
    if isinstance(spec, int):
        return True
    return str(spec).isdigit()


def cut(args) -> int:
    trace = args["trace"]
    if not os.path.isfile(trace):
        print(f"错误: 输入文件不存在: {trace}", file=sys.stderr)
        return 2
    try:
        windows, _scan = resolve_windows(
            trace, args, use_cache=not args.get("no_cache"))
    except (CutError, ValueError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 2

    out_dir = args.get("out_dir") or os.path.dirname(os.path.abspath(trace))
    stem_path = os.path.abspath(trace)
    for w in windows:
        name = f"{_stem(trace)}__{w.start_ns}-{w.end_ns}.perfetto-trace"
        if os.path.abspath(os.path.join(out_dir, name)) == stem_path:
            print("错误: 输出文件与输入文件相同，拒绝覆盖", file=sys.stderr)
            return 2

    opts = Options(keep_original_ts=bool(args.get("keep_original_ts")),
                   reorder_window_ns=parse_duration(
                       args.get("reorder_window") or "2s"))
    t0 = _time.perf_counter()
    try:
        rep = run(trace, windows, out_dir, opts, progress=_progress)
    except Exception as e:  # noqa: BLE001 - surface as Chinese error
        print(f"错误: 裁剪失败: {e}", file=sys.stderr)
        return 2
    print(file=sys.stderr)  # clear progress line

    # write report json next to outputs
    report = {
        "input": rep.input,
        "outputs": [
            {"path": o.path, "start_ns": o.start_ns, "end_ns": o.end_ns,
             "bytes": o.bytes, "packets": o.packets,
             "ftrace_events_kept": o.ftrace_events_kept,
             "carryin_events": o.carryin_events,
             "class_counts": o.class_counts}
            for o in rep.outputs],
        "warnings": rep.warnings,
    }
    rname = (f"{_stem(trace)}__cut-"
             f"{_time.strftime('%Y%m%d-%H%M%S')}.report.json")
    rpath = os.path.join(out_dir, rname)
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    o = rep.outputs[0]
    dur_s = (o.end_ns - o.start_ns) / 1e9
    print(f"裁剪完成: {o.path}（窗口 {_fmt(o.start_ns)} ~ "
          f"{_fmt(o.end_ns)}，时长 {dur_s:.3f} s，"
          f"输出 {o.bytes / 1e6:.1f} MB，报告 {rpath}）")
    return 0


def _fmt(ns):
    return f"{ns} ns"


def _stem(path) -> str:
    base = os.path.basename(path)
    for suf in (".perfetto-trace", ".pftrace", ".trace", ".gz"):
        if base.endswith(suf):
            base = base[:-len(suf)]
    return base


_last_pct = [-1]


def _progress(done, total):
    if not total or not sys.stderr.isatty():
        return
    pct = int(done * 100 / total)
    if pct != _last_pct[0]:
        _last_pct[0] = pct
        print(f"\r裁剪进度 {pct}%", end="", file=sys.stderr)
