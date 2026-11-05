"""Local web UI server (stdlib only).

Listens on 127.0.0.1 only (random port by default). Every /api request
must carry the per-launch random token in the X-Pftrim-Token header and
a 127.0.0.1/localhost Host header (DNS-rebinding guard); the browser gets
the token through the URL fragment, which is never sent to the server.

Long operations (scan / cut / split / find) run as background jobs with
progress + cancel; the page polls /api/jobs/<id>.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import Cancelled, __version__
from ..engine import Options, Window, run
from ..index import cache_dir, load_or_scan

STATIC = Path(__file__).with_name("static")
_TYPES = {".html": "text/html; charset=utf-8",
          ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8",
          ".svg": "image/svg+xml"}
MAX_RECENT = 10
MAX_BODY = 1 << 20


class ApiError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------------ jobs
class Job:
    def __init__(self, kind):
        self.id = secrets.token_hex(6)
        self.kind = kind
        self.state = "running"          # running|done|error|cancelled
        self.stage = ""
        self.progress = 0.0
        self.result = None
        self.error = None
        self.cancel = threading.Event()
        self.started = time.time()

    def set_progress(self, stage, done, total):
        self.stage = stage
        self.progress = (done / total) if total else 0.0

    def to_dict(self):
        return {"id": self.id, "kind": self.kind, "state": self.state,
                "stage": self.stage, "progress": round(self.progress, 4),
                "result": self.result, "error": self.error,
                "elapsed_s": round(time.time() - self.started, 1)}


class App:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.port = 0

    # --------------------------------------------------------- jobs
    def start_job(self, kind, fn):
        job = Job(kind)
        with self.lock:
            # keep the registry small: drop finished jobs older than 1h
            now = time.time()
            for k in [k for k, j in self.jobs.items()
                      if j.state != "running" and now - j.started > 3600]:
                del self.jobs[k]
            self.jobs[job.id] = job

        def runner():
            try:
                job.result = fn(job)
                job.state = "done"
                job.progress = 1.0
            except Cancelled:
                job.state = "cancelled"
            except Exception as e:  # noqa: BLE001 - reported to the page
                job.state = "error"
                job.error = str(e) or e.__class__.__name__
                traceback.print_exc()
        threading.Thread(target=runner, daemon=True).start()
        return job

    def job(self, jid) -> Job:
        j = self.jobs.get(jid)
        if j is None:
            raise ApiError("任务不存在", 404)
        return j

    # ------------------------------------------------------- recent
    @staticmethod
    def _recent_path() -> Path:
        return cache_dir().parent / "recent.json"

    def recent(self) -> list:
        try:
            items = json.loads(self._recent_path().read_text("utf-8"))
        except Exception:
            return []
        return [p for p in items if isinstance(p, str)][:MAX_RECENT]

    def add_recent(self, path):
        items = [path] + [p for p in self.recent() if p != path]
        try:
            rp = self._recent_path()
            rp.parent.mkdir(parents=True, exist_ok=True)
            rp.write_text(json.dumps(items[:MAX_RECENT], ensure_ascii=False),
                          "utf-8")
        except OSError:
            pass


# ------------------------------------------------------------ operations
def _trace_path(body) -> str:
    p = body.get("path")
    if not isinstance(p, str) or not p.strip():
        raise ApiError("缺少文件路径")
    p = os.path.abspath(p.strip().strip('"'))
    if not os.path.isfile(p):
        raise ApiError(f"文件不存在：{p}")
    return p


def _out_dir(body, trace) -> str:
    d = body.get("out_dir")
    d = os.path.abspath(d) if isinstance(d, str) and d.strip() else \
        os.path.dirname(trace)
    os.makedirs(d, exist_ok=True)
    return d


def _int(body, key, required=True):
    """int param; accepts JSON numbers or decimal strings (the page
    sends ns timestamps as strings to stay exact beyond 2**53)."""
    v = body.get(key)
    if v is None and not required:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ApiError(f"参数 {key} 必须是整数") from None


def _summary(res) -> dict:
    """ScanResult -> page payload (histogram included)."""
    d = res.to_dict()
    d["cache_hit"] = res.cache_hit
    d["scan_time_s"] = res.scan_time_s
    # JS numbers lose precision above 2**53 ns (~104 days of uptime):
    # the page works in ns relative to start and converts back with
    # BigInt from these strings.
    s = res.start_ns or 0
    d["start_ns_str"] = str(s)
    d["rel"] = {
        "end": (res.end_ns - s) if res.end_ns is not None else 0,
        "hist_origin": res.hist_origin_ns - s,
        "markers": [[m["ts"] - s,
                     None if m.get("end_ts") is None else m["end_ts"] - s,
                     m.get("label", "")] for m in res.markers],
    }
    # per-output metadata overhead estimate (same formula as split --size)
    d["overhead_bytes"] = min(res.untimed_bytes + 256 * 1024,
                              4 * 1024 * 1024)
    return d


def _outputs(rep) -> list:
    return [{"path": o.path, "start_ns": o.start_ns, "end_ns": o.end_ns,
             "bytes": o.bytes, "packets": o.packets} for o in rep.outputs]


def _write_report(out_dir, trace, kind, payload) -> str:
    from ..ops.cut import _stem
    name = (f"{_stem(trace)}__{kind}-"
            f"{time.strftime('%Y%m%d-%H%M%S')}.report.json")
    path = os.path.join(out_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def _run_windows(job, trace, windows, out_dir, keep, kind, extra=None):
    rep = run(trace, windows, out_dir, Options(keep_original_ts=keep),
              progress=lambda d, t: job.set_progress("写出", d, t),
              cancel=job.cancel)
    outs = _outputs(rep)
    report = {"input": rep.input, "outputs": outs,
              "warnings": rep.warnings, "limitations": rep.limitations,
              **(extra or {})}
    rpath = _write_report(out_dir, trace, kind, report)
    return {"outputs": outs, "out_dir": out_dir, "report": rpath,
            "warnings": rep.warnings}


def op_open(app, body):
    trace = _trace_path(body)
    use_cache = not body.get("no_cache")
    app.add_recent(trace)

    def fn(job):
        res = load_or_scan(
            trace, use_cache=use_cache, cancel=job.cancel,
            progress=lambda d, t: job.set_progress("扫描", d, t))
        return _summary(res)
    return app.start_job("open", fn)


def op_cut(app, body):
    trace = _trace_path(body)
    s, e = _int(body, "start_ns"), _int(body, "end_ns")
    if e <= s:
        raise ApiError("结束时间必须晚于开始时间")
    out_dir = _out_dir(body, trace)
    keep = bool(body.get("keep_original_ts"))
    return app.start_job("cut", lambda job: _run_windows(
        job, trace, [Window(s, e)], out_dir, keep, "cut"))


def op_split(app, body):
    from ..ops.split import SplitError, _cut_points
    from ..timespec import parse_duration, parse_size
    trace = _trace_path(body)
    out_dir = _out_dir(body, trace)
    keep = bool(body.get("keep_original_ts"))
    mode = body.get("mode")
    value = str(body.get("value") or "").strip()
    try:
        ov = parse_duration(body["overlap"]) if body.get("overlap") else 0
        kw = {"parts": int(value)} if mode == "parts" else \
            {"every_ns": parse_duration(value)} if mode == "every" else \
            {"size_bytes": parse_size(value)} if mode == "size" else None
    except (ValueError, TypeError) as ex:
        raise ApiError(f"切割参数无效：{ex}") from None
    if kw is None:
        raise ApiError("切割方式必须是 parts / every / size")

    def fn(job):
        sc = load_or_scan(trace, cancel=job.cancel,
                          progress=lambda d, t: job.set_progress(
                              "扫描", d, t))
        try:
            pts, m, target = _cut_points(sc, **kw)
        except SplitError as ex:
            raise ApiError(str(ex)) from None
        bounds = [sc.start_ns] + pts + [sc.end_ns + 1]
        wins = [Window(max(bounds[i] - (ov if i else 0), sc.start_ns),
                       bounds[i + 1]) for i in range(len(bounds) - 1)]
        return _run_windows(job, trace, wins, out_dir, keep, "split",
                            {"mode": m, "target": target,
                             "cut_points_ns": pts})
    return app.start_job("split", fn)


def op_find(app, body):
    from ..ops.find import find_matches
    trace = _trace_path(body)
    pattern = body.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ApiError("请输入要查找的关键字")
    source = body.get("source") or "all"
    if source not in ("atrace", "logcat", "all"):
        raise ApiError("来源必须是 atrace / logcat / all")
    if body.get("regex"):
        import re
        try:
            re.compile(pattern)
        except re.error as ex:
            raise ApiError(f"正则表达式无效：{ex}") from None
    maxm = min(_int(body, "max_matches", False) or 1000, 10000)

    def fn(job):
        recs, base = find_matches(
            trace, pattern, regex=bool(body.get("regex")),
            icase=bool(body.get("ignore_case")), source=source,
            max_matches=maxm, cancel=job.cancel,
            progress=lambda d, t: job.set_progress("查找", d, t))
        b = base or 0
        for r in recs:
            r["rel_ns"] = r["ts_ns"] - b
            r["end_rel_ns"] = None if r.get("end_ns") is None else \
                r["end_ns"] - b
        return {"matches": recs, "base_ns_str": str(b),
                "truncated": len(recs) >= maxm}
    return app.start_job("find", fn)


def op_cut_many(app, body):
    """Several windows in ONE engine pass (find results)."""
    trace = _trace_path(body)
    wins = body.get("windows")
    if not isinstance(wins, list) or not wins:
        raise ApiError("没有要截取的区间")
    try:
        windows = [Window(int(s), int(e)) for s, e in wins]
    except (TypeError, ValueError):
        raise ApiError("区间格式无效") from None
    if any(w.end_ns <= w.start_ns for w in windows):
        raise ApiError("区间的结束时间必须晚于开始时间")
    out_dir = _out_dir(body, trace)
    keep = bool(body.get("keep_original_ts"))
    return app.start_job("find_cut", lambda job: _run_windows(
        job, trace, windows, out_dir, keep, "find",
        {"pattern": body.get("pattern")}))


def op_pick(app, body):
    """Native Windows file dialog (tkinter) -> path or null."""
    out = {}

    def dlg():
        try:
            import tkinter
            from tkinter import filedialog
            root = tkinter.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            out["path"] = filedialog.askopenfilename(
                parent=root, title="选择 perfetto trace",
                filetypes=[("Perfetto trace",
                            "*.perfetto-trace *.pftrace *.trace *.gz"),
                           ("所有文件", "*.*")]) or None
            root.destroy()
        except Exception as ex:  # noqa: BLE001
            out["error"] = f"无法打开文件选择框：{ex}"
    t = threading.Thread(target=dlg, daemon=True)
    t.start()
    t.join()
    if "error" in out:
        raise ApiError(out["error"], 500)
    return {"path": os.path.normpath(out["path"]) if out.get("path")
            else None}


def op_open_dir(app, body):
    p = body.get("path")
    if not isinstance(p, str) or not p:
        raise ApiError("缺少路径")
    d = p if os.path.isdir(p) else os.path.dirname(p)
    if not os.path.isdir(d):
        raise ApiError(f"目录不存在：{d}")
    if hasattr(os, "startfile"):
        os.startfile(d)  # noqa: S606 - local UI, user-initiated
    return {"ok": True}


_POST = {"/api/open": op_open, "/api/cut": op_cut, "/api/split": op_split,
         "/api/find": op_find, "/api/cut_many": op_cut_many,
         "/api/pick": op_pick, "/api/open_dir": op_open_dir}


# --------------------------------------------------------------- handler
def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"pftrim/{__version__}"

        def log_message(self, fmt, *args):  # quiet: no request log spam
            pass

        # ------------------------------------------------- helpers
        def _send(self, status, body: bytes, ctype):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, obj):
            self._send(status, json.dumps(obj, ensure_ascii=False)
                       .encode("utf-8"), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            return host in (f"127.0.0.1:{app.port}", f"localhost:{app.port}")

        def _authorized(self) -> bool:
            tok = self.headers.get("X-Pftrim-Token") or ""
            return self._host_ok() and secrets.compare_digest(
                tok.encode(), app.token.encode())

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError("请求体过大", 413)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                obj = json.loads(raw or b"{}")
            except ValueError:
                raise ApiError("请求不是有效的 JSON") from None
            if not isinstance(obj, dict):
                raise ApiError("请求必须是 JSON 对象")
            return obj

        # --------------------------------------------------- verbs
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path.startswith("/api/"):
                return self._api("GET", path)
            if not self._host_ok():
                return self._send(403, b"forbidden", "text/plain")
            name = "index.html" if path in ("/", "/index.html") else \
                path.lstrip("/")
            f = (STATIC / name).resolve()
            if STATIC.resolve() not in f.parents or not f.is_file():
                return self._send(404, b"not found", "text/plain")
            self._send(200, f.read_bytes(),
                       _TYPES.get(f.suffix, "application/octet-stream"))

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if not path.startswith("/api/"):
                return self._send(404, b"not found", "text/plain")
            self._api("POST", path)

        def _api(self, verb, path):
            if not self._authorized():
                return self._json(403, {"error": "未授权的请求"})
            try:
                if verb == "GET" and path == "/api/recent":
                    return self._json(200, {"recent": app.recent()})
                if verb == "GET" and path == "/api/version":
                    return self._json(200, {"version": __version__})
                if verb == "GET" and path.startswith("/api/jobs/"):
                    return self._json(
                        200, app.job(path.rsplit("/", 1)[1]).to_dict())
                if verb == "POST" and path.startswith("/api/jobs/") and \
                        path.endswith("/cancel"):
                    j = app.job(path.split("/")[3])
                    j.cancel.set()
                    return self._json(200, j.to_dict())
                fn = _POST.get(path) if verb == "POST" else None
                if fn is None:
                    return self._json(404, {"error": "未知接口"})
                out = fn(app, self._body())
                self._json(200, out.to_dict() if isinstance(out, Job)
                           else out)
            except ApiError as e:
                self._json(e.status, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self._json(500, {"error": f"内部错误：{e}"})

    return Handler


def create_server(port: int = 0, app: App | None = None):
    """-> (server, app); server bound to 127.0.0.1 (not yet serving)."""
    app = app or App()
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    srv.daemon_threads = True
    app.port = srv.server_address[1]
    return srv, app


def serve(port: int = 0, open_browser: bool = True) -> int:
    srv, app = create_server(port)
    url = f"http://127.0.0.1:{app.port}/#t={app.token}"
    print(f"Perfetto Trim {__version__} 已启动：{url}")
    print("关闭此窗口即退出。")
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
