"""Golden-output regression for perf work.

Generates reference outputs from a checkout of a known-good commit
(PFTRIM_GOLDEN_SRC, default %TEMP%\\pftrim_golden\\src) into
%TEMP%\\pftrim_golden_out (cached; --regen forces), then reruns the same
commands against the working tree's src/ and asserts byte-identical
.perfetto-trace outputs and equal info --json stdout (path fields
normalized).

Usage:
    python scripts/golden_check.py [--regen] [--only NAME,NAME]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACE = os.path.join(REPO, "testdata", "sample_tecno_kn8.perfetto-trace")
PY = os.path.join(REPO, ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable

GOLDEN_SRC = os.environ.get(
    "PFTRIM_GOLDEN_SRC",
    os.path.join(tempfile.gettempdir(), "pftrim_golden", "src"))
GOLDEN_OUT = os.environ.get(
    "PFTRIM_GOLDEN_OUT",
    os.path.join(tempfile.gettempdir(), "pftrim_golden_out"))
CUR_SRC = os.path.join(REPO, "src")

# sample bounds: 5537349512888059 .. 5537360124690214
S1, E1 = "5537353000000000", "5537356000000000"

CASES = [
    ("info", ["info", "{trace}", "--json", "--no-cache"], "stdout"),
    ("cut_abs", ["cut", "{trace}", "--start", S1, "--end", E1,
                 "-o", "{out}"], "files"),
    ("cut_rel", ["cut", "{trace}", "--start", "3s", "--duration", "1s",
                 "-o", "{out}"], "files"),
    ("split_parts", ["split", "{trace}", "--parts", "4",
                     "-o", "{out}", "--no-cache"], "files"),
    ("split_every", ["split", "{trace}", "--every", "2s",
                     "--overlap", "200ms", "-o", "{out}",
                     "--no-cache"], "files"),
    ("find_all", ["find", "{trace}", "DrawFrames", "--all",
                  "-o", "{out}", "--max-matches", "12"], "files"),
]


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest()


def _norm_stdout(b):
    # info --json: normalize absolute paths
    try:
        d = json.loads(b)
    except Exception:
        return b
    def scrub(o):
        if isinstance(o, dict):
            return {k: scrub(v) for k, v in o.items()}
        if isinstance(o, list):
            return [scrub(v) for v in o]
        if isinstance(o, str) and ("\\" in o or "/" in o):
            return "<path>" if os.sep in o else o
        return o
    return scrub(d)


def run_cases(src_dir, out_root, cases):
    results = {}
    for name, argv_tpl, kind in cases:
        outdir = os.path.join(out_root, name)
        shutil.rmtree(outdir, ignore_errors=True)
        os.makedirs(outdir, exist_ok=True)
        argv = [a.format(trace=TRACE, out=outdir) for a in argv_tpl]
        env = dict(os.environ)
        env["PYTHONPATH"] = src_dir
        p = subprocess.run([PY, "-m", "pftrim", *argv],
                           capture_output=True, text=True, env=env,
                           cwd=outdir)
        files = {}
        for fn in sorted(os.listdir(outdir)):
            if fn.endswith(".report.json"):
                continue
            files[fn] = _sha(os.path.join(outdir, fn))
        results[name] = {"stdout": p.stdout, "stderr": p.stderr,
                         "rc": p.returncode, "files": files}
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regen", action="store_true")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    cases = CASES
    if a.only:
        keep = set(a.only.split(","))
        cases = [c for c in CASES if c[0] in keep]

    marker = os.path.join(GOLDEN_OUT, ".done")
    if a.regen or not os.path.exists(marker):
        print(f"generating golden outputs from {GOLDEN_SRC} ...")
        shutil.rmtree(GOLDEN_OUT, ignore_errors=True)
        os.makedirs(GOLDEN_OUT, exist_ok=True)
        res = run_cases(GOLDEN_SRC, GOLDEN_OUT, cases)
        kinds = {n: k for n, _a, k in cases}
        for name, r in res.items():
            with open(os.path.join(GOLDEN_OUT, name,
                                   ".meta.json"), "w") as f:
                json.dump({"stdout": r["stdout"], "files": r["files"],
                           "rc": r["rc"], "stderr_tail": r["stderr"][-300:],
                           "_stdout_kind": kinds[name]}, f, indent=2)
        open(marker, "w").write("done\n")
        print("golden generated")

    tmp = tempfile.mkdtemp(prefix="pfcur_")
    try:
        cur = run_cases(CUR_SRC, tmp, cases)
    finally:
        pass  # keep tmp for debugging; cleaned next run
    bad = 0
    for name, r in cur.items():
        meta_p = os.path.join(GOLDEN_OUT, name, ".meta.json")
        meta = json.load(open(meta_p))
        if r["rc"] != meta["rc"]:
            print(f"[FAIL] {name}: rc {r['rc']} != {meta['rc']} :: "
                  f"{r['stderr'][-200:]}")
            bad += 1
            continue
        if meta.get("_stdout_kind") == "stdout":
            if _norm_stdout(r["stdout"]) != _norm_stdout(meta["stdout"]):
                print(f"[FAIL] {name}: stdout differs")
                bad += 1
        if r["files"] != meta["files"]:
            gk, ck = meta["files"], r["files"]
            diffs = [k for k in set(gk) | set(ck)
                     if gk.get(k) != ck.get(k)]
            print(f"[FAIL] {name}: {len(diffs)} file diffs "
                  f"{diffs[:6]}")
            bad += 1
    print("CUR_OUT:", tmp)
    print("PASS" if not bad else f"FAIL ({bad} case(s))")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
