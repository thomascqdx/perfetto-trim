import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "scripts"))
from make_big_trace import make_big_trace  # noqa: E402


@pytest.mark.perf
@pytest.mark.sample
@pytest.mark.tp
def test_big_trace_tp_verification(tmp_path, sample_trace):
    """TP loads a 2-copy output; bounds and sched_slice counts are
    predicted exactly from the ORIGINAL's TP results + the shift."""
    from tp import open_tp, query
    src = open_tp(sample_trace)
    b0 = query(src, "select start_ts, end_ts from trace_bounds")[0]
    n0 = query(src, "select count(*) as c from sched_slice")[0]["c"]
    src.close()
    step = (b0["end_ts"] - b0["start_ts"]) + 1_000_000_000

    out = tmp_path / "big.pftrace"
    make_big_trace(str(sample_trace), str(out), 2)

    tp = open_tp(str(out))
    try:
        row = query(tp, "select start_ts, end_ts from trace_bounds")[0]
        assert row["start_ts"] == b0["start_ts"]
        assert row["end_ts"] == b0["end_ts"] + step
        # sched_slice = 2*orig + 8: the per-cpu first-switch skip only
        # happens once (copy 0), so copy 1 contributes all its switches.
        assert query(
            tp, "select count(*) as c from sched_slice")[0]["c"] == \
            2 * n0 + 8
    finally:
        tp.close()


@pytest.mark.sample
def test_scan_memory_bounded(tmp_path, sample_trace):
    """Scan memory must be ~independent of trace size: peak(4x) <
    1.5*peak(1x) and <64MB on a ~128MB concatenated trace.

    jobs=1: this checks the scan algorithm's own state; with worker
    processes the main process additionally holds a constant number of
    in-flight batch results (OrderedPool max_inflight), measured on the
    real 1.5 GB trace by scripts/bench.py (peak_tree_mb)."""
    import tracemalloc
    from pftrim.scan import scan
    big = tmp_path / "big4.pftrace"
    make_big_trace(str(sample_trace), str(big), 4)

    peaks = {}
    for tag, p in (("1x", str(sample_trace)), ("4x", str(big))):
        tracemalloc.start()
        scan(p, jobs=1)
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks[tag] = peak
    assert peaks["1x"] < 64 * 1024 * 1024
    assert peaks["4x"] < 64 * 1024 * 1024
    assert peaks["4x"] < 1.5 * peaks["1x"]
