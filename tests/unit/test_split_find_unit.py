"""M5 split / M6 find tests (cut-point unit tests + cancellation)."""
import os
import threading

import pytest

from pftrim import Cancelled
from pftrim.ops.split import _cut_points, SplitError


class _Scan:
    def __init__(self, bins, origin=0, bin_ns=10_000_000, start=0,
                 end=None, untimed=0):
        self.hist_bin_bytes = bins
        self.hist_origin_ns = origin
        self.hist_bin_ns = bin_ns
        self.start_ns = start
        self.end_ns = end if end is not None else len(bins) * bin_ns
        self.untimed_bytes = untimed


def test_cut_points_every():
    sc = _Scan([1] * 10, start=0)
    pts, mode, _ = _cut_points(sc, every_ns=30_000_000)
    assert pts == [30_000_000, 60_000_000, 90_000_000]
    assert mode == "every"


def test_cut_points_parts_byte_equal():
    # 4 bins of sizes 10,10,10,10 -> 2 cuts of 20 each
    sc = _Scan([10, 10, 10, 10], bin_ns=1_000)
    pts, mode, target = _cut_points(sc, parts=2)
    assert pts == [2_000]
    # 4 parts: 1 cut per bin boundary
    pts, _, _ = _cut_points(sc, parts=4)
    assert pts == [1_000, 2_000, 3_000]


def test_cut_points_size():
    # 100 bytes timed, untimed overhead 10MB+256k -> size just over
    sc = _Scan([25] * 4, bin_ns=1_000, untimed=1_000_000)
    pts, mode, target = _cut_points(
        sc, size_bytes=1_000_000 + 256 * 1024 + 50)
    # k = ceil(100 / 50) = 2 -> one cut at cumulative 50
    assert mode == "size"
    assert pts == [2_000]
    # error when size <= overhead
    with pytest.raises(SplitError):
        _cut_points(sc, size_bytes=100)


def test_cut_points_parts_errors():
    sc = _Scan([1, 1])
    with pytest.raises(SplitError):
        _cut_points(sc, parts=1)


def test_cancel_engine(tmp_path):
    from tests.synthetic import builder as sb
    import google.protobuf as pb  # noqa
    ev = sb.print_event(100, 1, "B|1|x")
    path = tmp_path / "t.perfetto-trace"
    path.write_bytes(
        sb.packet_field(sb.ftrace_packet(cpu=0, events=[ev])))
    ev2 = threading.Event()
    ev2.set()
    from pftrim.engine import run, Window, Options
    with pytest.raises(Cancelled):
        run(str(path), [Window(0, 10**9)], str(tmp_path / "o"),
            Options(), cancel=ev2)
    # no .part leftovers
    assert not list((tmp_path / "o").glob("*.part")) \
        if (tmp_path / "o").exists() else True


def test_find_matches_synthetic(tmp_path):
    from tests.synthetic import builder as sb
    evs = [sb.print_event(100, 1, "B|1|DrawFrames 7"),
           sb.print_event(200, 1, "B|1|other"),
           sb.print_event(300, 1, "E|1"),
           sb.print_event(400, 1, "S|1|asyncName|9"),
           sb.print_event(500, 1, "F|1|asyncName|9")]
    path = tmp_path / "t.perfetto-trace"
    path.write_bytes(
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)))
    from pftrim.ops import find
    recs, _ = find.find_matches(str(path), "DrawFrames",
                                source="atrace")
    assert len(recs) == 1 and recs[0]["ts_ns"] == 100
    recs2, _ = find.find_matches(str(path), "Name", source="atrace")
    names = {r["name"].strip() for r in recs2}
    assert "asyncName" in names
