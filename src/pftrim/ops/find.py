"""pftrim find: streaming match over atrace prints + android logcat."""
import json
import os
import re
import sys
import time as _time

from .. import Cancelled
from ..reader import iter_packets
from ..wire import iter_fields
from .. import fields, ftrace
from ..engine import Options, Window, run
from ..clock import ClockConverter
from ..index import load_or_scan
from ..timespec import parse_duration
from .cut import _stem, _progress


def _match_fn(pattern, regex, icase):
    if regex:
        rx = re.compile(pattern.encode(), re.I if icase else 0)
        return lambda b: bool(rx.search(b))
    if icase:
        p = pattern.encode().lower()
        return lambda b: p in b.lower()
    p = pattern.encode()
    return lambda b: p in b


def find_matches(trace, pattern, *, regex=False, icase=False,
                 source="all", max_matches=1000, cancel=None):
    """-> (records list, base_ns). One streaming pass over the trace."""
    m = _match_fn(pattern, regex, icase)
    conv = ClockConverter()
    start_ns = None
    recs = []
    stacks = {}       # tid -> [(name, ts, rec_ref)] atrace B ends
    async_open = {}   # (tgid, name, cookie) -> (ts, rec_ref)
    named_open = {}   # (tgid, track, cookie) -> (ts, rec_ref)
    stop = False
    for rec in iter_packets(trace, expand_compressed=True, cancel=cancel):
        if rec.field_no != fields.Trace.PACKET or stop:
            continue
        for fno, wt, val, _s, _e in iter_fields(rec.payload):
            if fno == fields.TracePacket.FTRACE_EVENTS and wt == 2:
                bv = ftrace.parse_bundle(val)
                for ev in bv.events:
                    ts, pid, et, evv = ftrace.event_meta(ev)
                    if et != fields.FtraceEvent.PRINT:
                        continue
                    buf = ftrace.print_buf(evv) or b""
                    parts = buf.split(b"|")
                    tag = parts[0]
                    if start_ns is None:
                        start_ns = ts
                    if tag == b"B":
                        rec = None
                        if source in ("atrace", "all") and \
                                len(parts) > 2 and m(parts[2]):
                            rec = {"ts_ns": ts, "source": "atrace",
                                   "name": _short(parts[2]),
                                   "pid": pid, "tid": pid,
                                   "end_ns": None}
                            recs.append(rec)
                        stacks.setdefault(pid, []).append(
                            (parts[2] if len(parts) > 2 else b"", ts,
                             rec))
                    elif tag == b"E":
                        st = stacks.get(pid)
                        if st:
                            _nm, _ts, rref = st.pop()
                            if rref is not None:
                                rref["end_ns"] = ts
                    elif tag in (b"S", b"F"):
                        nm = parts[2] if len(parts) > 2 else b""
                        ck = _int(parts[3]) if len(parts) > 3 else 0
                        tg = _int(parts[1]) if len(parts) > 1 else 0
                        rec = None
                        if source in ("atrace", "all") and m(nm):
                            rec = {"ts_ns": ts, "source": "async",
                                   "name": _short(nm), "pid": pid,
                                   "tid": pid, "end_ns": None}
                            recs.append(rec)
                        key = (tg, nm, ck)
                        if tag == b"S":
                            async_open.setdefault(key, (ts, rec))
                        else:
                            prev = async_open.pop(key, None)
                            if prev and prev[1] is not None:
                                prev[1]["end_ns"] = ts
                    elif tag in (b"G", b"H"):
                        track = parts[2] if len(parts) > 2 else b""
                        nm = parts[3] if len(parts) > 3 else b""
                        ck = _int(parts[4]) if len(parts) > 4 else (
                            _int(parts[3]) if len(parts) > 3 else 0)
                        tg = _int(parts[1]) if len(parts) > 1 else 0
                        hay = track + b" " + nm
                        rec = None
                        if source in ("atrace", "all") and m(hay):
                            rec = {"ts_ns": ts, "source": "named",
                                   "name": _short(track, nm),
                                   "pid": pid, "tid": pid,
                                   "end_ns": None}
                            recs.append(rec)
                        key = (tg, track, ck)
                        if tag == b"G":
                            named_open.setdefault(key, (ts, rec))
                        else:
                            prev = named_open.pop(key, None)
                            if prev and prev[1] is not None:
                                prev[1]["end_ns"] = ts
                    elif tag == b"C":
                        nm = parts[2] if len(parts) > 2 else b""
                        if source in ("atrace", "all") and m(nm):
                            recs.append({"ts_ns": ts, "source": "ctr",
                                         "name": _short(nm), "pid": pid,
                                         "tid": pid, "end_ns": None})
                    elif tag in (b"I", b"N"):
                        nm = parts[2] if len(parts) > 2 else (
                            parts[3] if len(parts) > 3 else b"")
                        if source in ("atrace", "all") and m(nm):
                            recs.append({"ts_ns": ts, "source": "atrace",
                                         "name": _short(nm), "pid": pid,
                                         "tid": pid, "end_ns": None})
                    if len(recs) >= max_matches:
                        stop = True
                        break
            elif fno == fields.TracePacket.ANDROID_LOG and wt == 2 \
                    and source in ("logcat", "all"):
                for f2, w2, v2, _s2, _e2 in iter_fields(val):
                    if w2 != 2:
                        continue
                    tsr = clk = tag = msg = None
                    for f3, w3, v3, _s3, _e3 in iter_fields(v2):
                        if w3 == 0 and f3 == 1:
                            tsr = v3
                        elif w3 == 0 and f3 == 11:
                            clk = v3
                        elif w3 == 2 and f3 == 3:
                            tag = v3
                        elif w3 == 2 and f3 == 4:
                            msg = v3
                    if tsr is None:
                        continue
                    ts = conv.to_boottime(clk, tsr)
                    if ts is None:
                        continue
                    if start_ns is None:
                        start_ns = ts
                    hay = (tag or b"") + b" " + (msg or b"")
                    if m(hay):
                        recs.append({"ts_ns": ts, "source": "logcat",
                                     "name": _short(tag, msg),
                                     "pid": None, "tid": None})
                        if len(recs) >= max_matches:
                            stop = True
                            break
            if stop:
                break
    try:
        base = load_or_scan(trace, use_cache=True).start_ns
    except Exception:
        base = None
    if base is None:
        base = start_ns
    for i, r in enumerate(recs):
        r["index"] = i + 1
        r["rel_s"] = (r["ts_ns"] - (base or r["ts_ns"])) / 1e9
    return recs, base


def _short(*bs):
    s = b" ".join(b or b"" for b in bs if b).decode("utf-8", "replace")
    return s[:120]


def _int(b):
    try:
        return int(b)
    except (ValueError, TypeError):
        return 0


def find(args) -> int:
    trace = args["trace"]
    if not os.path.isfile(trace):
        print(f"错误: 输入文件不存在: {trace}", file=sys.stderr)
        return 2
    recs, base = find_matches(
        trace, args["pattern"], regex=bool(args.get("regex")),
        icase=bool(args.get("ignore_case")),
        source=args.get("source") or "all",
        max_matches=int(args.get("max_matches") or 1000))
    if args.get("json"):
        print(json.dumps(recs, ensure_ascii=False, indent=2))
    else:
        print(f"{'#':>4} {'rel(s)':>12} {'ts_ns':>18} {'dur':>10} "
              f"{'src':>7}  name")
        for r in recs:
            dur = r.get("end_ns")
            durs = f"{(dur - r['ts_ns']) / 1e6:.2f}ms" if dur else "-"
            print(f"{r['index']:>4} {r['rel_s']:>12.3f} {r['ts_ns']:>18} "
                  f"{durs:>10} {r['source']:>7}  {r['name']}")
        print(f"共 {len(recs)} 条匹配")
    if args.get("pick") or args.get("all"):
        sel = recs[:int(args["pick"])] if args.get("pick") else recs
        before = parse_duration(args.get("before") or "2s")
        after = parse_duration(args.get("after") or "2s")
        # clamp to trace bounds (cached index when present, else the
        # matched pass's observed bounds -- scan skipped for speed)
        try:
            sc = load_or_scan(
                trace, use_cache=not args.get("no_cache", False))
            lo, hi = sc.start_ns, sc.end_ns
        except Exception:
            lo, hi = base, base
        windows = [
            Window(max(r["ts_ns"] - before, lo or r["ts_ns"] - before),
                   min((r.get("end_ns") or r["ts_ns"]) + after,
                       hi if hi is not None else
                       (r.get("end_ns") or r["ts_ns"]) + after))
            for r in sel]
        out_dir = args.get("out_dir") or \
            os.path.dirname(os.path.abspath(trace))
        rep = run(trace, windows, out_dir, Options(), progress=_progress)
        rname = (f"{_stem(trace)}__find-"
                 f"{_time.strftime('%Y%m%d-%H%M%S')}.report.json")
        with open(os.path.join(out_dir, rname), "w",
                  encoding="utf-8") as f:
            json.dump({"pattern": args["pattern"], "matches": recs,
                       "outputs": [{"path": o.path,
                                    "start_ns": o.start_ns,
                                    "end_ns": o.end_ns,
                                    "bytes": o.bytes}
                                   for o in rep.outputs]},
                      f, ensure_ascii=False, indent=2)
        print(f"已截取 {len(sel)} 个窗口 -> {out_dir}（报告 {rname}）")
    return 0
