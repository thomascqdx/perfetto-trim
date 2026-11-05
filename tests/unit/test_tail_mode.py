"""Tail-mode: cutting the first seconds of a big trace must not decode
trailing ftrace bundles, and must still forward trailing metadata."""

import pytest

import builder as sb
import pftrim.engine as engine
from pftrim.engine import Window, run
from pftrim import fields
from pftrim.reader import iter_packets
from pftrim.wire import iter_fields, WT_LEN
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb


def _wake_ev(ts, pid, comm, woken, prio=120):
    return pb.FtraceEvent(
        timestamp=ts, pid=pid,
        sched_wakeup=pb.SchedWakeupFtraceEvent(
            comm=comm, pid=woken, prio=prio, target_cpu=0))


def _big_trace(path, n_bundles=600, evs_per=2000):
    """~45 MB trace: switch@1000 establishes sched state; huge tail of
    dropped wakes (before 2nd switch -> TP drops them); final switch;
    trailing ftrace_stats (metadata)."""
    evs = [sb.sched_switch_event(1000, 1, "k", 2, "a", 1)]
    evs += [_wake_ev(2000 + i, 1, "w", i, 120) for i in range(10)]
    evs.append(sb.sched_switch_event(10_000, 1, "a", 1, "b", 2))
    with open(path, "wb") as f:
        f.write(sb.packet_field(sb.clock_snapshot_packet({1: 0, 6: 0})))
        f.write(sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)))
        for b in range(n_bundles):
            # tail must span > reorder_window + lookahead (2+10 s) of
            # trace time for a released item to cross E+lookahead while
            # packets still stream -> ~4 s per bundle of 2000 events.
            base = 20_000_000_000 + b * 4_000_000_000
            tail = [_wake_ev(base + i * 2_000_000, 1, "w", i)
                    for i in range(evs_per)]
            f.write(sb.packet_field(sb.ftrace_packet(cpu=0, events=tail)))
        f.write(sb.packet_field(pb.TracePacket(
            ftrace_stats=pb.FtraceStats()).SerializeToString()))


@pytest.mark.perf
def test_cut_tail_mode_no_decode(tmp_path):
    src = tmp_path / "big.perfetto-trace"
    _big_trace(src)
    rep = run(str(src), [Window(0, 10_000)], str(tmp_path / "o"))
    # the huge tail was never decoded: 1 head bundle + minimal lookahead
    assert rep.bundles_decoded < 10
    # trailing ftrace_stats metadata IS in the output
    has_stats = False
    for rec in iter_packets(rep.outputs[0].path):
        if rec.field_no != fields.Trace.PACKET:
            continue
        for fno, wt, val, s, e in iter_fields(rec.payload):
            if fno == fields.TracePacket.FTRACE_STATS:
                has_stats = True
    assert has_stats


@pytest.mark.perf
def test_independence_tail(tmp_path):
    """20-Window run writes byte-identical outputs vs per-window runs;
    tail mode kicks in for the early windows too."""
    src = tmp_path / "big.perfetto-trace"
    _big_trace(src, n_bundles=200)
    N = 20
    E = 20_000_000_000 + 200 * 4_000_000_000
    wins = [Window(i * E // N, (i + 1) * E // N) for i in range(N)]
    rep1 = run(str(src), wins, str(tmp_path / "m"))
    outs1 = [o.path for o in rep1.outputs]
    for i, w in enumerate(wins):
        rep2 = run(str(src), [w], str(tmp_path / f"s{i}"))
        assert open(outs1[i], "rb").read() == \
            open(rep2.outputs[0].path, "rb").read(), f"window {i}"
    # early windows finished early -> tail mode engaged (few bundles)
    assert rep1.bundles_decoded < 210  # << 200 tail bundles decoded
