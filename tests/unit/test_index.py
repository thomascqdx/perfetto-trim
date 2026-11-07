import os
import time

import pytest

from pftrim.index import load_or_scan

import builder as sb


def _trace(tmp_path, ts=100):
    p = tmp_path / "t.perfetto-trace"
    sb.write_trace(p, [sb.packet_field(
        sb.ftrace_packet(cpu=0, events=[sb.print_event(ts, 1, "B|1|x")]))])
    return p


@pytest.fixture
def cache_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PERFETTO_TRIM_CACHE_DIR", str(tmp_path / "cache"))
    return tmp_path / "cache"


def test_cache_hit_second_call(tmp_path, cache_env):
    p = _trace(tmp_path)
    r1 = load_or_scan(p)
    assert r1.cache_hit is False
    r2 = load_or_scan(p)
    assert r2.cache_hit is True
    assert r2.start_ns == r1.start_ns == 100


def test_cache_invalidated_on_mtime_change(tmp_path, cache_env):
    p = _trace(tmp_path)
    r1 = load_or_scan(p)
    assert not r1.cache_hit
    # rewrite -> new mtime -> new key -> rescan
    time.sleep(0.01)
    sb.write_trace(p, [sb.packet_field(
        sb.ftrace_packet(cpu=0, events=[sb.print_event(42, 1, "B|1|x")]))])
    os.utime(p)
    r2 = load_or_scan(p)
    assert r2.cache_hit is False
    assert r2.start_ns == 42


def test_corrupt_cache_rescans(tmp_path, cache_env):
    p = _trace(tmp_path)
    r1 = load_or_scan(p)
    assert not r1.cache_hit
    cache_env.mkdir(parents=True, exist_ok=True)
    for f in cache_env.iterdir():
        f.write_bytes(b"garbage-not-json")
    r2 = load_or_scan(p)
    assert r2.cache_hit is False
    assert r2.start_ns == 100


def test_no_cache_flag(tmp_path, cache_env):
    p = _trace(tmp_path)
    load_or_scan(p)
    r = load_or_scan(p, use_cache=False)
    assert r.cache_hit is False
