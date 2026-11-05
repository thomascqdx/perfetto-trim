"""M4 boundary-state tests -- synthetic traces, TP v57 as oracle."""

import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import builder as sb  # noqa: E402
from tp import open_tp, query  # noqa: E402
from pftrim.engine import Options, Window, run  # noqa: E402
from pftrim.wire import len_field, varint_field  # noqa: E402
from pftrim import fields  # noqa: E402


def _trace(tmp_path, evs, extra_tops=(), name="t.perfetto-trace"):
    tops = [sb.packet_field(sb.clock_snapshot_packet({1: 0, 6: 0}))]
    tops += list(extra_tops)
    tops.append(sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)))
    p = tmp_path / name
    sb.write_trace(p, tops)
    return p


def _run(p, tmp_path, S, E, keep_ts=False):
    rep = run(str(p), [Window(S, E)], str(tmp_path / "o"),
              Options(keep_original_ts=keep_ts))
    return rep.outputs[0].path, rep


def _slices(path):
    tp = open_tp(path)
    try:
        rows = query(tp, "select s.ts, s.dur, s.name, s.depth "
                         "from slice s order by s.ts, s.depth")
        return [(r["ts"], r["dur"], r["name"], r["depth"])
                for r in rows]
    finally:
        tp.close()


def _pev(ts, pid, buf):
    return sb.print_event(ts, pid, buf)


@pytest.mark.tp
def test_nested_sync_slices_cross_S(tmp_path):
    # outer+inner open before S; inner ends in-window, outer after E
    evs = [_pev(100, 42, "B|42|outer"), _pev(200, 42, "B|42|inner"),
           _pev(600, 42, "E"), _pev(3000, 42, "E")]
    p = _trace(tmp_path, evs)
    out, rep = _run(p, tmp_path, 500, 2000)
    sl = _slices(out)
    # carry-in reopens both at S; inner closes at 600, outer closed at E-1
    names = sorted(n for _, _, n, _ in sl)
    assert names == ["inner", "outer"]
    inner = [s for s in sl if s[2] == "inner"][0]
    outer = [s for s in sl if s[2] == "outer"][0]
    assert inner[0] == 500 and inner[1] == 100 and inner[3] == 1
    assert outer[0] == 500 and outer[3] == 0
    assert outer[1] == 1500 - 1 or outer[1] == 1499  # closed at E-1
    # boundary.csv: start+end rows for both slices, real ends filled
    csvp = out[:-len(".perfetto-trace")] + ".boundary.csv"
    rows = list(csv.DictReader(open(csvp, encoding="utf-8")))
    st = [r for r in rows if r["side"] == "start"]
    en = [r for r in rows if r["side"] == "end"]
    # inner closed at 600 (in-window) -> only outer still open at E
    assert len(st) == 2 and len(en) == 1 and en[0]["name"] == "outer"
    o = [r for r in st if r["name"] == "outer"][0]
    assert o["real_start_ns"] == "100" and o["real_end_ns"] == "3000"
    assert o["real_dur_ns"] == "2900"


@pytest.mark.tp
def test_async_slice_cross_S(tmp_path):
    evs = [_pev(100, 42, "S|42|asyncJob|7"), _pev(800, 42, "F|42|asyncJob|7")]
    p = _trace(tmp_path, evs)
    out, rep = _run(p, tmp_path, 500, 2000)
    sl = _slices(out)
    assert len(sl) == 1 and sl[0][2] == "asyncJob"
    assert sl[0][0] == 500 and sl[0][1] == 300  # S..800


@pytest.mark.tp
def test_counter_C_in_effect_at_S(tmp_path):
    evs = [_pev(100, 42, "C|42|mem|5"), _pev(400, 42, "C|42|mem|9"),
           _pev(900, 42, "C|42|mem|1")]
    p = _trace(tmp_path, evs)
    out, rep = _run(p, tmp_path, 500, 2000)
    tp = open_tp(out)
    try:
        rows = query(tp, "select ts, value from counter order by ts")
        assert rows and rows[0]["ts"] == 500
        assert rows[0]["value"] == 9.0  # value in effect at S
    finally:
        tp.close()


@pytest.mark.tp
def test_no_dur_neg1_slices_at_E(tmp_path):
    # slice open at E must be closed at E-1 -> no dur=-1 atrace slices
    evs = [_pev(100, 42, "B|42|long"), _pev(3000, 42, "E")]
    p = _trace(tmp_path, evs)
    out, rep = _run(p, tmp_path, 500, 2000)
    sl = _slices(out)
    assert all(d != -1 for _, d, *_ in sl)


@pytest.mark.tp
def test_binder_carryin(tmp_path):
    tx = pb_binder(50, 100, 42)
    evs = [tx, _pev(900, 42, "B|42|x")]
    p = _trace(tmp_path, evs)
    out, rep = _run(p, tmp_path, 500, 2000)
    # carry-in binder event emitted at S
    assert rep.outputs[0].carryin_events >= 1


def pb_binder(etype, ts, pid):
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb
    ev = pb.FtraceEvent(timestamp=ts, pid=pid)
    ev.binder_transaction.debug_id = 1
    ev.binder_transaction.target_node = 2
    ev.binder_transaction.to_proc = 3
    ev.binder_transaction.to_thread = 4
    ev.binder_transaction.reply = 0
    ev.binder_transaction.flags = 0
    ev.binder_transaction.code = 1
    return ev


@pytest.mark.tp
def test_android_log_tp_parity(tmp_path):
    from pftrim.scan import scan
    tops = [sb.packet_field(sb.clock_snapshot_packet({1: 0, 6: 0})),
            sb.packet_field(sb.android_log_packet(
                [(100, "t", "a"), (900, "t", "b"), (5000, "t", "c")]))]
    p = tmp_path / "l.perfetto-trace"
    sb.write_trace(p, tops)
    res = scan(str(p))
    tp = open_tp(str(p))
    try:
        tb = query(tp, "select * from trace_bounds")[0]
        assert res.start_ns == tb["start_ts"]
        assert res.end_ns == tb["end_ts"]
        n_in = query(tp, "select count(*) as c from android_logs "
                         "where ts >= 500 and ts < 2000")[0]["c"]
    finally:
        tp.close()
    out, rep = _run(p, tmp_path, 500, 2000)
    tp2 = open_tp(out)
    try:
        assert query(tp2, "select count(*) as c from android_logs")[0][
                   "c"] == n_in == 1
    finally:
        tp2.close()


@pytest.mark.tp
def test_frame_start_crosses_S(tmp_path):
    # hand-encoded FrameTimelineEvent: actual_display_frame_start{cookie=9}
    ft = fields.FrameTimelineEvent
    start_inner = varint_field(1, 9)  # COOKIE=1 in all frame sub-msgs
    inner = len_field(ft.ACTUAL_DISPLAY_FRAME_START, start_inner)
    pkt = varint_field(fields.TracePacket.TIMESTAMP, 100) + \
        len_field(fields.TracePacket.FRAME_TIMELINE_EVENT, inner)
    evs = [_pev(900, 42, "B|42|x"), _pev(1500, 42, "E")]
    p = _trace(tmp_path, evs, extra_tops=[sb.packet_field(pkt)])
    out, rep = _run(p, tmp_path, 500, 2000)
    tp = open_tp(out)
    try:
        rows = query(tp, "select ts from slice where ts < 900")
        # frame start packet carried in at S=500
        assert rep.outputs[0].carryin_events >= 1
    finally:
        tp.close()


def test_multi_window_independent(tmp_path):
    evs = [_pev(100, 42, "B|42|a"), _pev(300, 42, "B|42|b"),
           _pev(800, 42, "E"), _pev(2000, 42, "E"),
           _pev(5000, 42, "B|42|c"), _pev(6000, 42, "E")]
    p = _trace(tmp_path, evs)
    wins = [Window(500, 1500), Window(1500, 3000), Window(3000, 7000)]
    rep1 = run(str(p), wins, str(tmp_path / "m"))
    for i, w in enumerate(wins):
        rep2 = run(str(p), [w], str(tmp_path / f"s{i}"))
        assert open(rep1.outputs[i].path, "rb").read() == \
            open(rep2.outputs[0].path, "rb").read()


def test_late_events_warning(tmp_path):
    # the third event's ts is behind an already-released ts -> late
    evs = [_pev(10_000_000_000, 42, "B|42|x"),
           _pev(20_000_000_000, 42, "B|42|z"),
           _pev(100, 42, "B|42|y")]
    p = _trace(tmp_path, evs)
    rep = run(str(p), [Window(0, 30_000_000_000)], str(tmp_path / "o"))
    assert any("reorder_late_events" in w for w in rep.warnings)
