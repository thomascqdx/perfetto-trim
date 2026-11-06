"""TP-verified checks on the new-build KN8 trace (perf marker; slow).

    pytest -m perf tests/equivalence/test_kn8_interned_tp.py

This sample exercises the two KN8 bugs: ftrace packets carrying
interned_data AFTER ftrace_events (misclassified as android_log) and a
track_event sequence on a sequence-scoped incremental clock (seq 8).
Ground truth is ALWAYS trace_processor on the ORIGINAL trace.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tp import open_tp, query  # noqa: E402
from pftrim import fields, ftrace  # noqa: E402
from pftrim.engine import Options, Window, run  # noqa: E402
from pftrim.reader import iter_packets  # noqa: E402
from pftrim.scan import scan  # noqa: E402
from pftrim.wire import WT_LEN, iter_fields  # noqa: E402
from test_big_trace_tp import _digest  # noqa: E402
from test_cut_equivalence import (  # noqa: E402
    _assert_counters_atrace, _assert_open_slices, _assert_sched_eq,
    _assert_slices_eq, _counter, _counter_at)

pytestmark = [pytest.mark.sample, pytest.mark.tp, pytest.mark.perf]


@pytest.fixture(scope="module")
def kn8_scan(kn8_interned_trace):
    return scan(str(kn8_interned_trace))


@pytest.fixture(scope="module")
def kn8_tp(kn8_interned_trace):
    tp = open_tp(kn8_interned_trace)
    yield tp
    tp.close()


def _bundle_counts(path):
    """(total ftrace bundles, bundles with >=1 timed event) in a trace."""
    n = n_timed = 0
    for rec in iter_packets(path, expand_compressed=True):
        if rec.field_no != fields.Trace.PACKET:
            continue
        for fno, wt, val, _s, _e in iter_fields(rec.payload):
            if fno != fields.TracePacket.FTRACE_EVENTS or wt != WT_LEN:
                continue
            n += 1
            if _bundle_timed(val):
                n_timed += 1
    return n, n_timed


def _bundle_timed(bundle):
    bv = ftrace.parse_bundle(bundle)
    if bv.compact is not None:
        cs = ftrace.CompactSched.decode(bv.compact)
        for _ in cs.switch_timestamps():
            return True
        for _ in cs.waking_timestamps():
            return True
    for ev in bv.events:
        if ftrace.event_meta(ev)[0] is not None:
            return True
    return False


def _slice_cat_digest(tp, S, E):
    """(count, (name,ts) digest) of ALL slices with category not null
    starting inside [S,E) -- any track, incl. track_event slices."""
    r = query(tp, f"select count(*) as n, "
                  f"sum(abs(hash(coalesce(s.name,''), s.ts)) "
                  f"% 1000000007) as d from slice s "
                  f"where s.category is not null and s.ts >= {S} "
                  f"and s.ts < {E}")[0]
    return r["n"], r["d"] or 0


def test_scan_bounds_match_tp(kn8_scan, kn8_tp):
    tb = query(kn8_tp, "select start_ts, end_ts from trace_bounds")[0]
    assert (kn8_scan.start_ns, kn8_scan.end_ns) == \
        (tb["start_ts"], tb["end_ts"])


def test_full_range_cut(kn8_interned_trace, kn8_scan, kn8_tp, tmp_path):
    """[start, end+1): nothing dropped -- every timed ftrace bundle is
    emitted, output >= input, TP bounds + slice/sched/counter digests
    match the original over the full range."""
    S, E = kn8_scan.start_ns, kn8_scan.end_ns + 1
    rep = run(str(kn8_interned_trace), [Window(S, E)], str(tmp_path),
              Options())
    out = rep.outputs[0]
    assert out.bytes >= os.path.getsize(kn8_interned_trace)
    n_bundles, n_timed = _bundle_counts(kn8_interned_trace)
    assert n_bundles == kn8_scan.ftrace["bundles"]
    # every bundle with >=1 timed event overlaps the window -> emitted
    assert out.class_counts.get("ftrace", 0) == n_timed

    tp_out = open_tp(out.path)
    try:
        tb = query(tp_out, "select start_ts, end_ts from trace_bounds")[0]
        assert (tb["start_ts"], tb["end_ts"]) == \
            (kn8_scan.start_ns, kn8_scan.end_ns)
        for kind in ("slice", "sched", "counter"):
            assert _digest(tp_out, kind, S, E) == \
                _digest(kn8_tp, kind, S, E), kind
    finally:
        tp_out.close()


def test_mid_cut_track_event(kn8_interned_trace, kn8_scan, kn8_tp,
                             tmp_path):
    """10 s window centred on the median servicemanager-slice ts (the
    seq-8 track_event stream): in-window slices replay at the same
    (name, ts, dur); slices crossing E only need (name, ts) present --
    they may be closed/unclosed differently."""
    from collections import Counter

    rows = query(kn8_tp, "select ts from slice where category = "
                 "'servicemanager' order by ts")
    assert rows, "no servicemanager slices in the original"
    mid = rows[len(rows) // 2]["ts"]
    S = max(mid - 5_000_000_000, kn8_scan.start_ns)
    E = mid + 5_000_000_000
    rep = run(str(kn8_interned_trace), [Window(S, E)], str(tmp_path),
              Options())
    tp_out = open_tp(rep.outputs[0].path)
    try:
        tb = query(tp_out, "select * from trace_bounds")[0]
        assert tb["start_ts"] == S
        q = (f"select s.name, s.ts, s.dur from slice s where "
             f"s.category = 'servicemanager' and s.ts >= {S} "
             f"and s.ts < {E}")
        in_rows = query(kn8_tp, q)
        assert in_rows, "no in-window servicemanager slices"
        print(f"\nin-window servicemanager slices: {len(in_rows)}")
        out_rows = query(tp_out, q)
        # rows crossing E (end >= E or still open): only (name, ts) must
        # survive -- the tail of the slice is outside the window
        crossing = {(r["name"], r["ts"]) for r in in_rows
                    if r["dur"] == -1 or r["ts"] + r["dur"] >= E}
        in_exact = Counter(
            (r["name"], r["ts"], r["dur"]) for r in in_rows
            if (r["name"], r["ts"]) not in crossing)
        out_exact = Counter(
            (r["name"], r["ts"], r["dur"]) for r in out_rows
            if (r["name"], r["ts"]) not in crossing)
        assert out_exact == in_exact, \
            f"missing: {in_exact - out_exact} extra: {out_exact - in_exact}"
        out_name_ts = {(r["name"], r["ts"]) for r in out_rows}
        assert crossing <= out_name_ts, \
            f"crossing rows lost: {crossing - out_name_ts}"
    finally:
        tp_out.close()


def test_mid_10s_cut(kn8_interned_trace, kn8_scan, kn8_tp, tmp_path):
    """10 s window centred on the median track_event-slice ts:
    sched/slice/counter equivalence + the category-slice digest."""
    rows = query(kn8_tp, "select ts from slice where category is not "
                 "null order by ts")
    assert rows, "no categorized slices in the original"
    mid = rows[len(rows) // 2]["ts"]
    S, E = mid - 5_000_000_000, mid + 5_000_000_000
    rep = run(str(kn8_interned_trace), [Window(S, E)], str(tmp_path),
              Options())
    tp_out = open_tp(rep.outputs[0].path)
    try:
        tb = query(tp_out, "select * from trace_bounds")[0]
        assert tb["start_ts"] == S and tb["end_ts"] <= E
        _assert_sched_eq(tp_out, kn8_tp, S, E)
        assert _counter(tp_out, S + 1, E, "%cpu_freq%") == \
            _counter(kn8_tp, S + 1, E, "%cpu_freq%")
        assert _counter_at(tp_out, S, "%cpu_freq%") == \
            _counter_at(kn8_tp, S, "%cpu_freq%")
        assert _counter_at(tp_out, S, "cpuidle") == \
            _counter_at(kn8_tp, S, "cpuidle")
        _assert_slices_eq(tp_out, kn8_tp, S, E)
        _assert_counters_atrace(tp_out, kn8_tp, S, E)
        _assert_open_slices(tp_out, kn8_tp, S, E)
        # every categorized slice (any track, incl. track_event)
        # starting in-window is present at the same ts
        n_out, d_out = _slice_cat_digest(tp_out, S, E)
        n_in, d_in = _slice_cat_digest(kn8_tp, S, E)
        assert n_in > 0
        assert (n_out, d_out) == (n_in, d_in)
    finally:
        tp_out.close()
