"""Engine tests for sequence-scoped incremental clocks (TP ParsePacket
semantics) and the ftrace+interned_data classification fix."""

import os
import sys

import pytest

from pftrim import fields, ftrace
from pftrim.engine import Options, Window, run
from pftrim.reader import iter_packets
from pftrim.wire import WT_LEN, WT_VARINT, iter_fields

import builder as sb
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

BOOT = 481_000_000_000
SEQ = 8


def _run(tmp_path, tops, windows, keep_ts=False):
    p = tmp_path / "in.perfetto-trace"
    sb.write_trace(p, tops)
    rep = run(str(p), windows, str(tmp_path / "out"), Options(
        keep_original_ts=keep_ts))
    return rep, [o.path for o in rep.outputs]


def _payloads(path):
    out = []
    for rec in iter_packets(path):
        if rec.field_no == fields.Trace.PACKET:
            out.append(bytes(rec.payload))
    return out


def test_ftrace_packet_with_trailing_interned_data(tmp_path):
    """A ftrace bundle packet carrying interned_data AFTER ftrace_events
    (real KN8 layout) must be handled as ftrace, not android_log."""
    evs = [sb.print_event(100, 1, "B|1|x"),
           sb.print_event(200, 1, "E|1")]
    pkt = pb.TracePacket(
        ftrace_events=pb.FtraceEventBundle(cpu=0, event=evs),
        interned_data=pb.InternedData(),
        trusted_packet_sequence_id=2, trusted_uid=7).SerializeToString()
    rep, outs = _run(tmp_path, [sb.packet_field(pkt)],
                     [Window(0, 10_000)])
    ts_list = []
    for p in _payloads(outs[0]):
        for fno, wt, val, _s, _e in iter_fields(p):
            if fno == fields.TracePacket.FTRACE_EVENTS and wt == WT_LEN:
                bv = ftrace.parse_bundle(val)
                ts_list += [ftrace.event_meta(ev)[0] for ev in bv.events]
    assert {100, 200} <= set(ts_list)
    assert rep.outputs[0].class_counts.get("ftrace", 0) >= 1


# ------------------------------------------------- incremental clocks
def _reset_packet(boot_val, seq=SEQ):
    """[first_packet_on_sequence, timestamp=0, sequence_flags=1,
    trace_packet_defaults{clock 64}, clock_snapshot{6:B, 64:B inc}] --
    mirrors the real KN8 track_event sequence reset packet."""
    cs = pb.ClockSnapshot()
    for cid in (6, 64):
        c = cs.clocks.add()
        c.clock_id = cid
        c.timestamp = boot_val
        if cid == 64:
            c.is_incremental = True
    cs.primary_trace_clock = 6
    return pb.TracePacket(
        timestamp=0,
        sequence_flags=fields.SEQ_INCREMENTAL_STATE_CLEARED,
        first_packet_on_sequence=True,
        trace_packet_defaults=pb.TracePacketDefaults(
            timestamp_clock_id=64),
        clock_snapshot=cs,
        trusted_packet_sequence_id=seq,
        trusted_uid=1000).SerializeToString()


def _td_packet(delta, seq=SEQ):
    return pb.TracePacket(
        timestamp=delta,
        sequence_flags=fields.SEQ_NEEDS_INCREMENTAL_STATE,
        track_descriptor=pb.TrackDescriptor(uuid=42, name="track1"),
        trusted_packet_sequence_id=seq).SerializeToString()


def _te_packet(delta, name=b"ev", seq=SEQ):
    return pb.TracePacket(
        timestamp=delta,
        sequence_flags=fields.SEQ_NEEDS_INCREMENTAL_STATE,
        track_event=pb.TrackEvent(
            type=pb.TrackEvent.TYPE_INSTANT, track_uuid=42,
            name=name.decode()),
        trusted_packet_sequence_id=seq).SerializeToString()


# file-order layout mirroring the real KN8 trace:
#   reset1 -> track_descriptor -> te[d1..d5] -> reset2 -> te[d6..d10]
_DELTAS = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
_TD_DELTA = 5
_RESET2_BOOT = BOOT + 1500


def _inc_tops():
    tops = [sb.packet_field(sb.clock_snapshot_packet({6: BOOT - 1}))]
    tops.append(sb.packet_field(_reset_packet(BOOT)))
    tops.append(sb.packet_field(_td_packet(_TD_DELTA)))
    for d in _DELTAS[:5]:
        tops.append(sb.packet_field(_te_packet(d, b"te%d" % d)))
    tops.append(sb.packet_field(_reset_packet(_RESET2_BOOT)))
    for d in _DELTAS[5:]:
        tops.append(sb.packet_field(_te_packet(d, b"te%d" % d)))
    return tops


# absolute timestamps (on the incremental clock == BOOTTIME here) of the
# track_event packets in the original, in file order.
_ABS = [BOOT + _TD_DELTA + s for s in
        (100, 300, 600, 1000, 1500)] + \
     [_RESET2_BOOT + s for s in (600, 1300, 2100, 3000, 4000)]


def _replay_inc(path, seq=SEQ):
    """Replay the output's incremental-clock chain per TP rules
    (independent of ClockConverter): a clock_snapshot packet sets last
    to the clock-64 value; a timestamped packet advances last += ts.
    Returns (track_event abs ts list, clock_snapshot count)."""
    last = None
    abs_ts = []
    n_snap = 0
    for p in _payloads(path):
        pseq = ts = None
        snap = is_te = False
        snap_val = None
        for fno, wt, val, _s, _e in iter_fields(p):
            if fno == fields.TracePacket.TRUSTED_PACKET_SEQUENCE_ID \
                    and wt == WT_VARINT:
                pseq = val
            elif fno == fields.TracePacket.TIMESTAMP and wt == WT_VARINT:
                ts = val
            elif fno == fields.TracePacket.CLOCK_SNAPSHOT and wt == WT_LEN:
                snap = True
                for cf, cw, cv, _cs, _ce in iter_fields(val):
                    if cf == fields.ClockSnapshot.CLOCKS and cw == WT_LEN:
                        cid = cts = None
                        for gf, gw, gv, _gs, _ge in iter_fields(cv):
                            if gf == fields.ClockSnapshot.Clock.CLOCK_ID:
                                cid = gv
                            elif gf == fields.ClockSnapshot.Clock.TIMESTAMP:
                                cts = gv
                        if cid == 64:
                            snap_val = cts
            elif fno == fields.TracePacket.TRACK_EVENT and wt == WT_LEN:
                is_te = True
        if pseq != seq:
            continue
        if snap:
            n_snap += 1
            last = snap_val
            continue
        if ts is not None and last is not None:
            last += ts
        if is_te:
            abs_ts.append(last)
    return abs_ts, n_snap


def _expected(S, E):
    return [a for a in _ABS if S <= a < E]


def test_incremental_track_event_mid_cut(tmp_path):
    """Mid-window cut of a seq-scoped incremental track_event stream:
    the output's delta chain replays to exactly the in-window absolute
    timestamps, and every reset packet is carried over verbatim."""
    S, E = BOOT + 1000, BOOT + 3000
    rep, outs = _run(tmp_path, _inc_tops(), [Window(S, E)])
    abs_ts, n_snap = _replay_inc(outs[0])
    assert abs_ts == _expected(S, E)
    assert n_snap == 2
    # both reset packets are emitted verbatim (every window sees every
    # incremental-clock reset)
    assert rep.outputs[0].class_counts.get("metadata", 0) >= 2


def test_incremental_track_event_split_overlap(tmp_path):
    """3 overlapping windows: each output replays to its own in-window
    subset of the original absolute timestamps."""
    wins = [Window(BOOT + 1000, BOOT + 2000),
            Window(BOOT + 1800, BOOT + 3200),
            Window(BOOT + 3000, BOOT + 7000)]
    rep, outs = _run(tmp_path, _inc_tops(), wins)
    assert len(outs) == 3
    for w, out in zip(wins, outs):
        abs_ts, n_snap = _replay_inc(out)
        assert abs_ts == _expected(w.start_ns, w.end_ns)
        assert n_snap == 2


def test_full_range_keeps_all_incremental_events(tmp_path):
    rep, outs = _run(tmp_path, _inc_tops(), [Window(0, BOOT + 10_000)])
    abs_ts, n_snap = _replay_inc(outs[0])
    assert abs_ts == _ABS
    assert n_snap == 2


# ------------------------------------------- optional TP verification
def _reset_packet_tp(boot_val, seq=SEQ):
    """Reset packet carrying the full TP-parseable state: interned
    names/categories, incremental_state_cleared, packet defaults with
    track_event_defaults (track_uuid 42)."""
    cs = pb.ClockSnapshot()
    for cid in (6, 64):
        c = cs.clocks.add()
        c.clock_id = cid
        c.timestamp = boot_val
        if cid == 64:
            c.is_incremental = True
    cs.primary_trace_clock = 6
    return pb.TracePacket(
        timestamp=0,
        sequence_flags=fields.SEQ_INCREMENTAL_STATE_CLEARED,
        first_packet_on_sequence=True,
        incremental_state_cleared=True,
        interned_data=pb.InternedData(
            event_names=[pb.EventName(iid=1, name="evA")],
            event_categories=[pb.EventCategory(iid=1, name="cat")]),
        trace_packet_defaults=pb.TracePacketDefaults(
            timestamp_clock_id=64,
            track_event_defaults=pb.TrackEventDefaults(track_uuid=42)),
        clock_snapshot=cs,
        trusted_packet_sequence_id=seq,
        trusted_uid=1000).SerializeToString()


def _te_packet_tp(delta, seq=SEQ):
    return pb.TracePacket(
        timestamp=delta,
        sequence_flags=fields.SEQ_NEEDS_INCREMENTAL_STATE,
        track_event=pb.TrackEvent(
            type=pb.TrackEvent.TYPE_INSTANT, track_uuid=42,
            name_iid=1, category_iids=[1]),
        trusted_packet_sequence_id=seq).SerializeToString()


def _inc_tops_tp():
    tops = [sb.packet_field(sb.clock_snapshot_packet({6: BOOT - 1}))]
    tops.append(sb.packet_field(_reset_packet_tp(BOOT)))
    tops.append(sb.packet_field(_td_packet(_TD_DELTA)))
    for d in _DELTAS[:5]:
        tops.append(sb.packet_field(_te_packet_tp(d)))
    tops.append(sb.packet_field(_reset_packet_tp(_RESET2_BOOT)))
    for d in _DELTAS[5:]:
        tops.append(sb.packet_field(_te_packet_tp(d)))
    return tops


@pytest.mark.tp
def test_incremental_track_event_cut_tp(tmp_path):
    """The cut output loaded in trace_processor produces the same
    in-window track_event slices as the original."""
    from tp import open_tp, query

    S, E = BOOT + 1000, BOOT + 3000
    src = tmp_path / "in.perfetto-trace"
    sb.write_trace(src, _inc_tops_tp())
    rep = run(str(src), [Window(S, E)], str(tmp_path / "out"), Options())
    out = rep.outputs[0].path

    tp_in = open_tp(src)
    try:
        q = (f"select ts from slice where category='cat' and "
             f"ts >= {S} and ts < {E} order by ts")
        in_ts = [r["ts"] for r in query(tp_in, q)]
        assert in_ts == _expected(S, E)   # TP sanity vs our own math
    finally:
        tp_in.close()
    tp_out = open_tp(out)
    try:
        out_ts = [r["ts"] for r in query(tp_out, q)]
    finally:
        tp_out.close()
    assert out_ts == in_ts
