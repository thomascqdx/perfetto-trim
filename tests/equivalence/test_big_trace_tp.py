"""M7: TP-verified checks on the real ~1.5 GB trace (perf marker; slow).

    pytest -m perf tests/equivalence/test_big_trace_tp.py

Ground truth is trace_processor on the ORIGINAL big trace.
"""

import hashlib

import pytest

from pftrim.engine import Options, Window, run
from pftrim.reader import iter_packets
from pftrim.scan import scan
from tp import open_tp, query
from test_cut_equivalence import (_assert_counters_atrace,
                                  _assert_open_slices, _assert_sched_eq,
                                  _assert_slices_eq, _counter, _counter_at)

pytestmark = [pytest.mark.perf, pytest.mark.tp]


@pytest.fixture(scope="module")
def big_scan(big_trace):
    return scan(big_trace)          # default jobs (parallel)


@pytest.fixture(scope="module")
def big_tp(big_trace):
    tp = open_tp(big_trace)
    yield tp
    tp.close()


def test_passthrough_byte_identity(big_trace):
    """Concatenated raw top-level records == the file (sha256)."""
    h_raw, h_file = hashlib.sha256(), hashlib.sha256()
    for rec in iter_packets(big_trace):
        h_raw.update(rec.raw)
    with open(big_trace, "rb") as f:
        for ch in iter(lambda: f.read(1 << 22), b""):
            h_file.update(ch)
    assert h_raw.hexdigest() == h_file.hexdigest()


def test_scan_bounds_match_tp(big_scan, big_tp):
    tb = query(big_tp, "select start_ts, end_ts from trace_bounds")[0]
    assert (big_scan.start_ns, big_scan.end_ns) == \
        (tb["start_ts"], tb["end_ts"])


def test_mid_10s_cut_equivalence(big_trace, big_scan, big_tp, tmp_path):
    mid = (big_scan.start_ns + big_scan.end_ns) // 2
    S, E = mid - 5_000_000_000, mid + 5_000_000_000
    rep = run(str(big_trace), [Window(S, E)], str(tmp_path), Options())
    tp_out = open_tp(rep.outputs[0].path)
    try:
        tb = query(tp_out, "select * from trace_bounds")[0]
        assert tb["start_ts"] == S and tb["end_ts"] <= E
        _assert_sched_eq(tp_out, big_tp, S, E)
        assert _counter(tp_out, S + 1, E, "%cpu_freq%") == \
            _counter(big_tp, S + 1, E, "%cpu_freq%")
        assert _counter_at(tp_out, S, "%cpu_freq%") == \
            _counter_at(big_tp, S, "%cpu_freq%")
        assert _counter_at(tp_out, S, "cpuidle") == \
            _counter_at(big_tp, S, "cpuidle")
        _assert_slices_eq(tp_out, big_tp, S, E)
        _assert_counters_atrace(tp_out, big_tp, S, E)
        _assert_open_slices(tp_out, big_tp, S, E)
    finally:
        tp_out.close()


# (row key expression, FROM/JOIN clause, ts column) per table; rows are
# aggregated inside TP as (count, sum of a row hash) -- millions of rows
# never cross into Python. TP's HASH() takes only text/int, no NULL.
_ROWS = {
    "slice": ("coalesce(s.name, ''), s.ts, t.tid",
              "slice s join thread_track tt on s.track_id=tt.id "
              "join thread t on tt.utid=t.utid", "s.ts"),
    # dur excluded: a slice crossing a split point ends at E in its part
    "sched": ("cpu, ts", "sched_slice", "ts"),
    "counter": ("coalesce(tr.name, ''), c.ts, cast(c.value as text)",
                "counter c join track tr on c.track_id=tr.id", "c.ts"),
}


def _digest(tp, kind, S, E, skip_ts=()):
    """(row count, order-independent hash sum) of rows with S<=ts<E."""
    key, frm, tcol = _ROWS[kind]
    skip = (f" and {tcol} not in ({','.join(map(str, sorted(skip_ts)))})"
            if skip_ts else "")
    r = query(tp, f"select count(*) as n, "
                  f"sum(abs(hash({key})) % 1000000007) as d from {frm} "
                  f"where {tcol}>={S} and {tcol}<{E}{skip}")[0]
    return r["n"], r["d"] or 0


def test_split_parts4_completeness(big_trace, big_scan, big_tp, tmp_path):
    """Union of per-part in-window rows == original (counts + hash)."""
    from pftrim.ops.split import _cut_points
    pts, _, _ = _cut_points(big_scan, parts=4)
    bounds = [big_scan.start_ns] + pts + [big_scan.end_ns + 1]
    windows = [Window(bounds[i], bounds[i + 1]) for i in range(4)]
    rep = run(str(big_trace), windows, str(tmp_path), Options())
    assert len(rep.outputs) == 4
    replay_ts = {w.start_ns for w in windows[1:]}
    union = {k: [0, 0] for k in _ROWS}
    for o, w in zip(rep.outputs, windows):
        tp = open_tp(o.path)
        try:
            for k in _ROWS:
                n, h = _digest(tp, k, w.start_ns, w.end_ns, replay_ts)
                union[k][0] += n
                union[k][1] += h
        finally:
            tp.close()
    for k in _ROWS:
        exp = _digest(big_tp, k, big_scan.start_ns, big_scan.end_ns + 1,
                      replay_ts)
        assert tuple(union[k]) == exp, k
