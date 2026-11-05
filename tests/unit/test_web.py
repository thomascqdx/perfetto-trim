"""Local web UI server: auth guard + job API end-to-end (sample)."""

import http.client
import json
import os
import threading
import time

import pytest

from pftrim.web.server import create_server


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("PFTRIM_CACHE_DIR", str(tmp_path / "cache"))
    srv, app = create_server(0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield app
    srv.shutdown()
    srv.server_close()


def _req(app, method, path, body=None, token=True, host=None):
    c = http.client.HTTPConnection("127.0.0.1", app.port, timeout=30)
    headers = {"Host": host or f"127.0.0.1:{app.port}"}
    if token:
        headers["X-Pftrim-Token"] = app.token if token is True else token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    raw = r.read()
    c.close()
    ctype = r.getheader("Content-Type") or ""
    return r.status, (json.loads(raw) if "json" in ctype else raw)


def _wait(app, job, timeout=300):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st, j = _req(app, "GET", f"/api/jobs/{job['id']}")
        assert st == 200
        if j["state"] != "running":
            return j
        time.sleep(0.2)
    raise AssertionError("job timeout")


def test_api_rejects_missing_or_wrong_token(server):
    assert _req(server, "GET", "/api/recent", token=False)[0] == 403
    assert _req(server, "GET", "/api/recent", token="nope")[0] == 403
    assert _req(server, "POST", "/api/open", {"path": "x"},
                token=False)[0] == 403
    assert _req(server, "GET", "/api/recent")[0] == 200


def test_api_rejects_foreign_host_header(server):
    # DNS-rebinding guard: a valid token from another origin is refused
    st, _ = _req(server, "GET", "/api/recent", host="evil.example:80")
    assert st == 403


def test_static_served_and_traversal_blocked(server):
    st, body = _req(server, "GET", "/", token=False)
    assert st == 200 and b"Perfetto Trim" in body
    assert _req(server, "GET", "/../server.py", token=False)[0] == 404
    assert _req(server, "GET", "/%2e%2e/server.py", token=False)[0] == 404


def test_bad_requests_report_reason(server, tmp_path):
    st, j = _req(server, "POST", "/api/open",
                 {"path": str(tmp_path / "missing.perfetto-trace")})
    assert st == 400 and "不存在" in j["error"]
    assert _req(server, "GET", "/api/jobs/nope")[0] == 404


@pytest.mark.sample
def test_open_cut_find_flow(server, sample_trace, tmp_path):
    st, job = _req(server, "POST", "/api/open", {"path": str(sample_trace)})
    assert st == 200
    j = _wait(server, job)
    assert j["state"] == "done", j
    info = j["result"]
    assert info["start_ns"] == 5537349512888059
    assert info["hist_bin_bytes"] and info["overhead_bytes"] > 0
    assert _req(server, "GET", "/api/recent")[1]["recent"] == \
        [os.path.abspath(sample_trace)]

    S = info["start_ns"] + 2_000_000_000
    out = tmp_path / "out"
    st, job = _req(server, "POST", "/api/cut",
                   {"path": str(sample_trace), "start_ns": S,
                    "end_ns": S + 1_000_000_000, "out_dir": str(out)})
    j = _wait(server, job)
    assert j["state"] == "done", j
    (o,) = j["result"]["outputs"]
    assert os.path.getsize(o["path"]) == o["bytes"] > 0
    assert os.path.isfile(j["result"]["report"])

    st, job = _req(server, "POST", "/api/find",
                   {"path": str(sample_trace), "pattern": "DrawFrames",
                    "source": "atrace"})
    j = _wait(server, job)
    assert j["state"] == "done", j
    assert len(j["result"]["matches"]) == 230

    m = j["result"]["matches"][:2]
    st, job = _req(server, "POST", "/api/cut_many",
                   {"path": str(sample_trace), "out_dir": str(out / "f"),
                    "windows": [[r["ts_ns"] - 10**8, r["ts_ns"] + 10**8]
                                for r in m]})
    j = _wait(server, job)
    assert j["state"] == "done" and len(j["result"]["outputs"]) == 2


@pytest.mark.sample
def test_split_and_cancel(server, sample_trace, tmp_path):
    st, job = _req(server, "POST", "/api/split",
                   {"path": str(sample_trace), "mode": "parts",
                    "value": "3", "out_dir": str(tmp_path / "s")})
    j = _wait(server, job)
    assert j["state"] == "done", j
    assert len(j["result"]["outputs"]) == 3

    st, job = _req(server, "POST", "/api/split",
                   {"path": str(sample_trace), "mode": "parts",
                    "value": "3", "out_dir": str(tmp_path / "c")})
    _req(server, "POST", f"/api/jobs/{job['id']}/cancel")
    j = _wait(server, job)
    assert j["state"] in ("cancelled", "done")
    if j["state"] == "cancelled":
        assert not any(p.suffix == ".perfetto-trace" or
                       p.name.endswith(".part")
                       for p in (tmp_path / "c").iterdir())

    st, j = _req(server, "POST", "/api/split",
                 {"path": str(sample_trace), "mode": "bogus", "value": "1"})
    assert st == 400
