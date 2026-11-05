"""pftrim bench: run each op in a fresh subprocess, record wall+peak RSS."""
import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(REPO, ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable

_CHILD = r"""
import json, os, sys, time
import ctypes, ctypes.wintypes
sys.path.insert(0, r"%(repo)s\src"); sys.path.insert(0, r"%(repo)s\tests")
from pftrim.engine import Options, Window, run
from pftrim.index import load_or_scan
from pftrim.ops import find as fm

trace, op, pat, outdir, tmid, dur = sys.argv[1], sys.argv[2], sys.argv[3], \
    sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
t0 = time.perf_counter()
res = {}
if op == "info":
    sc = load_or_scan(trace, use_cache=False)
    res = {"start_ns": sc.start_ns}
elif op == "cut":
    rep = run(trace, [Window(tmid - dur // 2, tmid + dur // 2)], outdir,
              Options())
    res = {"bytes": rep.outputs[0].bytes}
elif op == "cutrel":
    sc = load_or_scan(trace, use_cache=True)
    rep = run(trace, [Window(tmid - dur // 2, tmid + dur // 2)], outdir,
              Options())
    res = {"bytes": rep.outputs[0].bytes}
elif op == "split":
    sc = load_or_scan(trace, use_cache=True)
    from pftrim.ops.split import _cut_points
    pts, _, _ = _cut_points(sc, parts=4)
    b = [sc.start_ns] + pts + [sc.end_ns + 1]
    ws = [Window(b[i], b[i + 1]) for i in range(len(b) - 1)]
    rep = run(trace, ws, outdir, Options())
    res = {"parts": len(rep.outputs)}
elif op == "find":
    recs, _ = fm.find_matches(trace, pat, source="atrace")
    res = {"matches": len(recs)}
wall = time.perf_counter() - t0

class _PM(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("PageFaultCount", ctypes.wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]
pm = _PM()
pm.cb = ctypes.sizeof(pm)
_k32 = ctypes.WinDLL("kernel32")
_psapi = ctypes.WinDLL("psapi")
_k32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
_psapi.GetProcessMemoryInfo.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.POINTER(_PM), ctypes.wintypes.DWORD]
_psapi.GetProcessMemoryInfo(_k32.GetCurrentProcess(), ctypes.byref(pm),
                            ctypes.sizeof(pm))
print("RESULT:" + json.dumps({"wall": wall,
                             "peak_mb": pm.PeakWorkingSetSize / 1e6, **res}))
"""


def _bounds(trace):
    sys.path.insert(0, os.path.join(REPO, "src"))
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from pftrim.index import load_or_scan
    sc = load_or_scan(trace)
    return sc.start_ns, sc.end_ns


def run_op(trace, op, pattern, cached=True):
    start, end = _bounds(trace)
    tmid = (start + end) // 2
    dur = min(10_000_000_000, end - start)
    outdir = tempfile.mkdtemp(prefix="pfbench_")
    env = dict(os.environ)
    if op == "info":
        env["PFTRIM_CACHE_DIR"] = tempfile.mkdtemp(prefix="pfcache_")
    try:
        cmd = [PY, "-c", _CHILD % {"repo": REPO}, trace, op, pattern,
               outdir, str(tmid), str(dur)]
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
        for line in p.stdout.splitlines():
            if line.startswith("RESULT:"):
                return json.loads(line[7:])
        return {"error": (p.stderr or p.stdout)[-300:]}
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--ops", default="info,cut,cutrel,split,find")
    ap.add_argument("--pattern", default="DrawFrames")
    ap.add_argument("--out")
    a = ap.parse_args()
    size_mb = os.path.getsize(a.trace) / 1e6
    rows = []
    for op in a.ops.split(","):
        r = run_op(a.trace, op, a.pattern)
        r["op"] = op
        rows.append(r)
        print(f"{op:>8}: {r.get('wall', 0):7.1f}s  "
              f"{size_mb / max(r.get('wall', 1), 1e-9):5.1f} MB/s  "
              f"peak {r.get('peak_mb', 0):.0f} MB {r.get('error','')}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print("saved", a.out)


if __name__ == "__main__":
    main()
