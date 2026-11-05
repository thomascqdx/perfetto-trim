import pytest

from pftrim.engine import Options, Window, run
from pftrim.reader import iter_packets
from pftrim.wire import iter_fields, WT_LEN
from pftrim import fields

import builder as sb
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb


def _run(tmp_path, tops, S=0, E=10_000, keep_ts=False):
    p = tmp_path / "in.perfetto-trace"
    sb.write_trace(p, tops)
    rep = run(str(p), [Window(S, E)], str(tmp_path / "out"), Options(
        keep_original_ts=keep_ts))
    return rep, rep.outputs[0].path


def _payloads(path):
    out = []
    for rec in iter_packets(path):
        if rec.field_no == fields.Trace.PACKET:
            out.append(bytes(rec.payload))
    return out


def test_metadata_and_unknown_in_all_outputs(tmp_path):
    from pftrim.wire import varint_field
    tops = [
        sb.packet_field(sb.clock_snapshot_packet({6: 0})),
        sb.packet_field(pb.TracePacket(
            cpu_info=pb.CpuInfo()).SerializeToString()),
        sb.packet_field(varint_field(9999, 1)),  # unknown field no
    ]
    rep, out = _run(tmp_path, tops)
    pays = _payloads(out)
    assert len(pays) == 3  # snapshot + cpu_info + unknown all emitted


def test_timed_filtering(tmp_path):
    bat_in = pb.TracePacket(
        battery=pb.BatteryCounters(capacity_percent=50),
        timestamp=500).SerializeToString()
    bat_out = pb.TracePacket(
        battery=pb.BatteryCounters(capacity_percent=60),
        timestamp=50_000).SerializeToString()
    rep, out = _run(tmp_path, [sb.packet_field(bat_in),
                               sb.packet_field(bat_out)])
    pays = _payloads(out)
    # only the in-window battery packet should appear
    assert len(pays) == 1


def test_process_tree_synth_includes_early_state(tmp_path):
    pt1 = pb.ProcessTree()
    proc = pt1.processes.add(pid=100); proc.cmdline.append("appA")
    th = pt1.threads.add(tid=101, tgid=100); th.name = "thrA"
    pkt = pb.TracePacket(process_tree=pt1).SerializeToString()
    rep, out = _run(tmp_path, [sb.packet_field(pkt)], S=100, E=5000)
    # synthesized merged packet must contain pid 100 bytes
    pays = _payloads(out)
    found = False
    for p in pays:
        for fno, wt, val, _s, _e in iter_fields(p):
            if fno == fields.TracePacket.PROCESS_TREE and wt == WT_LEN:
                for ifno, iwt, ival, _is, _ie in iter_fields(val):
                    if ifno == fields.ProcessTree.PROCESSES and \
                            iwt == WT_LEN:
                        for pf, pw, pv, _ps, _pe in iter_fields(ival):
                            if pf == 1 and pw == 0 and pv == 100:
                                found = True
    assert found


def test_android_log_filtered(tmp_path):
    # REALTIME+BOOTTIME snapshot (identity) so log ts convert (A1)
    snap = sb.packet_field(sb.clock_snapshot_packet({1: 0, 6: 0}))
    log = sb.android_log_packet([(50, "t", "out"), (500, "t", "in")])
    rep, out = _run(tmp_path, [snap, sb.packet_field(log)],
                    S=100, E=1000)
    pays = _payloads(out)
    # one log packet with only the in-window event
    logpkts = [p for p in pays if any(
        f == fields.TracePacket.ANDROID_LOG
        for f, w, v, _s, _e in iter_fields(p))]
    assert len(logpkts) == 1
    n = 0
    for fno, wt, val, _s, _e in iter_fields(logpkts[0]):
        if fno == fields.TracePacket.ANDROID_LOG and wt == WT_LEN:
            for lf, lw, lv, _ls, _le in iter_fields(val):
                if lf == fields.AndroidLogPacket.EVENTS:
                    n += 1
    assert n == 1


def test_compressed_inner_expanded(tmp_path):
    inner = pb.TracePacket(ftrace_events=pb.FtraceEventBundle(
        cpu=0, event=[sb.print_event(100, 1, "B|1|x")])).SerializeToString()
    outer = pb.TracePacket(
        compressed_packets=__import__("zlib").compress(
            sb.packet_field(inner)),
        trusted_packet_sequence_id=7, trusted_uid=11).SerializeToString()
    rep, out = _run(tmp_path, [sb.packet_field(outer)])
    pays = _payloads(out)
    # filtered bundle + E-boundary closer + optional identity bundle
    assert len(pays) >= 2
    seqs = [v for f, w, v, _s, _e in iter_fields(pays[0])
            if f == fields.TracePacket.TRUSTED_PACKET_SEQUENCE_ID]
    assert seqs == [7]  # outer trusted seq injected into inner


def test_ftrace_filter_keeps_only_window(tmp_path):
    evs = [sb.print_event(100, 1, "B|1|x"),
           sb.print_event(50_000, 1, "E|1")]
    rep, out = _run(tmp_path,
                    [sb.packet_field(sb.ftrace_packet(cpu=0, events=evs))],
                    S=50, E=1000)
    # bundle survives + E-boundary closer + optional identity bundle
    pays = _payloads(out)
    assert len(pays) >= 2


def test_report_contents(tmp_path):
    rep, out = _run(tmp_path, [sb.packet_field(
        sb.ftrace_packet(cpu=0, events=[sb.print_event(100, 1, "B|1|x")]))])
    assert rep.outputs[0].packets >= 1
    assert rep.outputs[0].bytes > 0
