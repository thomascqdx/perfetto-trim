"""ops.cut.resolve_windows: end is [S, E) -- the trace's last event
(scan.end_ns) must be INSIDE the window, so the implicit/clamped end
is scan.end_ns + 1."""

import types

import pytest

from pftrim.ops import cut as cut_mod


@pytest.fixture
def fake_scan(monkeypatch):
    sc = types.SimpleNamespace(start_ns=100, end_ns=200)
    monkeypatch.setattr(cut_mod, "load_or_scan", lambda *a, **k: sc)
    return sc


def test_no_end_uses_end_ns_plus_one(fake_scan):
    wins, _ = cut_mod.resolve_windows("t", {"start": "0s"})
    assert (wins[0].start_ns, wins[0].end_ns) == (100, 201)


def test_explicit_end_clamped_to_end_ns_plus_one(fake_scan):
    wins, _ = cut_mod.resolve_windows(
        "t", {"start": "0s", "end": "999s"})
    assert (wins[0].start_ns, wins[0].end_ns) == (100, 201)


def test_explicit_end_inside_kept(fake_scan):
    wins, _ = cut_mod.resolve_windows(
        "t", {"start": "0s", "end": "50ns"})
    assert (wins[0].start_ns, wins[0].end_ns) == (100, 150)


def test_last(fake_scan):
    wins, _ = cut_mod.resolve_windows("t", {"last": "50ns"})
    assert (wins[0].start_ns, wins[0].end_ns) == (151, 201)


def test_absolute_bounds_no_scan(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("scan must not run for absolute bounds")
    monkeypatch.setattr(cut_mod, "load_or_scan", _boom)
    wins, scan = cut_mod.resolve_windows(
        "t", {"start": "1000", "end": "2000"})
    assert (wins[0].start_ns, wins[0].end_ns) == (1000, 2000)
    assert scan is None
