"""perfetto-trim split: one trace -> many windows in ONE engine pass."""
import json
import os
import sys
import time as _time

from ..engine import Options, Window, run
from ..index import load_or_scan
from ..engine import (resolve_reorder_ns, REORDER_AUTO_MARGIN_NS,
                      REORDER_AUTO_MAX_NS)
from ..timespec import parse_duration, parse_size
from .cut import _stem, _progress


class SplitError(Exception):
    pass


def _cut_points(scan, *, parts=None, every_ns=None, size_bytes=None):
    """-> (cut ts list, mode, target). Cut at hist bin boundaries."""
    if not scan.hist_bin_bytes:
        raise SplitError("scan 缺少直方图，无法计算切点")
    origin, bin_ns = scan.hist_origin_ns, scan.hist_bin_ns
    bins = scan.hist_bin_bytes
    if every_ns is not None:
        pts = []
        t = scan.start_ns + every_ns
        while t < scan.end_ns:
            pts.append(t)
            t += every_ns
        return pts, "every", every_ns
    if parts is not None:
        if parts < 2:
            raise SplitError("--parts 必须 >= 2")
        total = sum(bins)
        target = total / parts
        pts = []
        acc = 0.0
        nxt = target
        for i, b in enumerate(bins):
            acc += b
            while acc >= nxt and len(pts) < parts - 1:
                pts.append(origin + (i + 1) * bin_ns)
                nxt += target
        return pts, "parts", parts
    if size_bytes is not None:
        # per-output overhead = untimed metadata bytes + carry-in
        # allowance, capped: scan.untimed_bytes counts ALL untimed
        # packets in the file but only a fraction is replicated per
        # output (~3.2MB merged pt/snapshot/carry-in on the sample).
        overhead = min(scan.untimed_bytes + 256 * 1024,
                       4 * 1024 * 1024)
        if size_bytes <= overhead:
            raise SplitError(
                f"--size {size_bytes} <= 每段元数据开销 {overhead}，无法切分")
        timed = sum(bins)
        k = -(-timed // (size_bytes - overhead))
        target = timed / k
        pts = []
        acc = 0.0
        nxt = target
        for i, b in enumerate(bins):
            acc += b
            while acc >= nxt and len(pts) < k - 1:
                pts.append(origin + (i + 1) * bin_ns)
                nxt += target
        return pts, "size", size_bytes
    raise SplitError("需要 --parts / --every / --size 之一")


def split(args) -> int:
    trace = args["trace"]
    if not os.path.isfile(trace):
        print(f"错误: 输入文件不存在: {trace}", file=sys.stderr)
        return 2
    scan = load_or_scan(trace, use_cache=not args.get("no_cache"),
                        progress=_progress)
    try:
        every = parse_duration(args["every"]) if args.get("every") else None
        size = parse_size(args["size"]) if args.get("size") else None
        pts, mode, target = _cut_points(
            scan, parts=args.get("parts"), every_ns=every,
            size_bytes=size)
    except (SplitError, ValueError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 2

    ov = parse_duration(args["overlap"]) if args.get("overlap") else 0
    bounds = [scan.start_ns] + pts + [scan.end_ns + 1]
    windows = []
    for i in range(len(bounds) - 1):
        s = bounds[i] - (ov if i > 0 else 0)
        windows.append(Window(max(s, scan.start_ns), bounds[i + 1]))

    out_dir = args.get("out_dir") or os.path.dirname(os.path.abspath(trace))
    reorder, lag = resolve_reorder_ns(scan)
    if lag + REORDER_AUTO_MARGIN_NS > REORDER_AUTO_MAX_NS:
        print(f"警告: ftrace 乱序延迟 {lag / 1e9:.1f}s 超过 "
              f"{REORDER_AUTO_MAX_NS / 1e9:.0f}s 上限，按上限处理",
              file=sys.stderr)
    opts = Options(keep_original_ts=bool(args.get("keep_original_ts")),
                   reorder_window_ns=reorder)
    t0 = _time.perf_counter()
    rep = run(trace, windows, out_dir, opts, progress=_progress)
    print(file=sys.stderr)
    warn = []
    if mode == "size":
        for o in rep.outputs:
            if o.bytes > 1.1 * target:
                warn.append(
                    f"{os.path.basename(o.path)}: {o.bytes / 1e6:.1f}MB "
                    "超过目标 1.1x（可能是不可分的 heapprofd 组或"
                    "单个 10ms bin 过大）")
    rname = (f"{_stem(trace)}__split-"
             f"{_time.strftime('%Y%m%d-%H%M%S')}.report.json")
    rpath = os.path.join(out_dir, rname)
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump({"input": rep.input, "mode": mode, "target": target,
                   "cut_points_ns": pts,
                   "outputs": [{"path": o.path, "start_ns": o.start_ns,
                                "end_ns": o.end_ns, "bytes": o.bytes,
                                "packets": o.packets}
                               for o in rep.outputs],
                   "warnings": rep.warnings + warn,
                   "limitations": rep.limitations},
                  f, ensure_ascii=False, indent=2)
    mb = sum(o.bytes for o in rep.outputs) / 1e6
    dt = _time.perf_counter() - t0
    print(f"切分完成: {len(rep.outputs)} 段 -> {out_dir}（共 {mb:.1f} MB，"
          f"{dt:.1f}s，报告 {rpath}）")
    for w in warn:
        print(f"警告: {w}", file=sys.stderr)
    return 0
