"""M5 split + M6 find acceptance tests (TP oracle, sample)."""
import os
import threading

import pytest

from pftrim import Cancelled
from pftrim.engine import Options, Window, run
from pftrim.index import load_or_scan
from pftrim.ops import find as find_mod
from pftrim.ops import split as split_mod
from tests.tp import open_tp, query


def _slice_rows(tp, S, E):
    return {(r["tid"], r["name"], r["ts"]) for r in query(
        tp, f"select s.name, s.ts, t.tid from slice s join thread_track "
        f"tt on s.track_id=tt.id join thread t on tt.utid=t.utid "
        f"where s.ts>={S} and s.ts<{E}")}


def _sched_rows(tp, S, E):
    return {(r["cpu"], r["ts"]) for r in query(
        tp, f"select cpu, ts from sched_slice where ts>={S} and ts<{E}")}


def _ctr_rows(tp, S, E):
    return {(r["name"], r["ts"], r["value"]) for r in query(
        tp, f"select tr.name as name, c.ts, c.value from counter c "
        f"join track tr on c.track_id=tr.id where c.ts>={S} and c.ts<{E}")}


def _ts_rows(tp, S, E):
    # thread_state rows strictly inside the window (running only --
    # boundary states are synthetic by design)
    return {(r["utid"], r["ts"]) for r in query(
        tp, f"select utid, ts from thread_state where ts>{S} and ts<{E} "
        f"and dur>0")}


def _run_split(trace, tmp_path, windows, keep=False):
    rep = run(trace, windows, str(tmp_path),
              Options(keep_original_ts=keep))
    return rep


@pytest.mark.sample
@pytest.mark.tp
class TestSplitCompleteness:
    """union of per-part in-window rows == original (no dup/missing)."""

    def _check(self, sample_trace, sample_tp, tmp_path, parts, overlap=0):
        scan = load_or_scan(sample_trace)
        from pftrim.ops.split import _cut_points
        pts, _, _ = _cut_points(scan, parts=parts)
        bounds = [scan.start_ns] + pts + [scan.end_ns + 1]
        windows = []
        for i in range(len(bounds) - 1):
            s = bounds[i] - (overlap if i > 0 else 0)
            windows.append(Window(max(s, scan.start_ns), bounds[i + 1]))
        rep = _run_split(sample_trace, tmp_path, windows)
        assert len(rep.outputs) == parts
        union_slice = set()
        union_sched = set()
        union_ctr = set()
        union_ts = set()
        # carry-in boundary replays land at each window's actual start
        # (the extended start for --overlap): drop rows at those ts.
        replay_ts = {w.start_ns for w in windows[1:]}
        for o, w in zip(rep.outputs, windows):
            tp = open_tp(o.path)
            for (tid, name, ts) in _slice_rows(tp, w.start_ns,
                                             w.end_ns - 1):
                if ts not in replay_ts:
                    union_slice.add((tid, name, ts))
            for (cpu, ts) in _sched_rows(tp, w.start_ns, w.end_ns - 1):
                if ts not in replay_ts:
                    union_sched.add((cpu, ts))
            for (n, ts, v) in _ctr_rows(tp, w.start_ns, w.end_ns - 1):
                if ts not in replay_ts:
                    union_ctr.add((n, ts, v))
            for (u, ts) in _ts_rows(tp, w.start_ns, w.end_ns - 1):
                union_ts.add((u, ts))
            tp.close()
        for i, (S, E) in enumerate([(w.start_ns, w.end_ns - 1)
                                    for w in windows]):
            assert _slice_rows(sample_tp, S, E) <= union_slice, \
                f"slice rows missing in window {i}"
            assert union_ctr >= _ctr_rows(sample_tp, S, E)
        assert union_slice == _slice_rows(
            sample_tp, scan.start_ns, scan.end_ns), \
            f"slice union mismatch {len(union_slice)}"
        assert union_ctr == _ctr_rows(
            sample_tp, scan.start_ns, scan.end_ns)

    def test_split_parts4(self, sample_trace, sample_tp, tmp_path):
        self._check(sample_trace, sample_tp, tmp_path, 4)

    def test_split_overlap(self, sample_trace, sample_tp, tmp_path):
        self._check(sample_trace, sample_tp, tmp_path, 4,
                    overlap=500_000_000)


@pytest.mark.sample
class TestSplitModes:
    def test_size_8mb(self, sample_trace, tmp_path):
        scan = load_or_scan(sample_trace)
        from pftrim.ops.split import _cut_points, SplitError
        # error path: size <= per-output overhead
        with pytest.raises(SplitError, match="开销"):
            _cut_points(scan, size_bytes=1 * 1024 * 1024)
        pts, mode, target = _cut_points(
            scan, size_bytes=8 * 1024 * 1024)
        bounds = [scan.start_ns] + pts + [scan.end_ns + 1]
        windows = [Window(bounds[i], bounds[i + 1])
                   for i in range(len(bounds) - 1)]
        rep = _run_split(sample_trace, tmp_path, windows)
        sizes = [o.bytes for o in rep.outputs]
        print("\nsize_8mb:", [round(b / 1e6, 2) for b in sizes])
        for b in sizes[:-1]:
            assert abs(b - 8e6) / 8e6 < 0.25, f"part {b / 1e6}MB"

    def test_every_3s(self, sample_trace, tmp_path):
        scan = load_or_scan(sample_trace)
        from pftrim.ops.split import _cut_points
        pts, mode, _ = _cut_points(scan, every_ns=3_000_000_000)
        assert pts == [scan.start_ns + 3e9, scan.start_ns + 6e9,
                       scan.start_ns + 9e9]

    def test_split_cancel(self, sample_trace, tmp_path):
        ev = threading.Event()
        ev.set()
        with pytest.raises(Cancelled):
            run(sample_trace, [Window(0, 10**18)], str(tmp_path),
                Options(), cancel=ev)
        assert not list(tmp_path.glob("*.part"))

    def test_find_cancel(self, sample_trace):
        ev = threading.Event()
        ev.set()
        with pytest.raises(Cancelled):
            find_mod.find_matches(sample_trace, "x", cancel=ev)


@pytest.mark.sample
@pytest.mark.tp
class TestFindOracle:
    def test_drawframes_count(self, sample_trace, sample_tp):
        recs, _ = find_mod.find_matches(
            sample_trace, "DrawFrames", source="atrace")
        exp = {r["ts"] for r in query(
            sample_tp, "select s.ts from slice s join thread_track tt "
            "on s.track_id=tt.id where s.name like '%DrawFrames%'")}
        got = {r["ts_ns"] for r in recs}
        assert len(recs) == len(exp)
        assert got == exp
