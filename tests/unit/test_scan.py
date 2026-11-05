import pytest

from pftrim.scan import scan

import builder as sb
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb


def _write(tmp_path, tops, name="t.perfetto-trace"):
    p = tmp_path / name
    sb.write_trace(p, tops)
    return p


def _pf(top_fields):
    return [sb.packet_field(p) for p in top_fields]


def test_scan_synthetic_basic(tmp_path):
    tops = _pf([
        sb.clock_snapshot_packet({6: 1000, 3: 500}),
        sb.ftrace_packet(cpu=0, events=[sb.print_event(100, 1, "B|1|x"),
                                        sb.print_event(300, 1, "E|1")]),
        sb.process_tree_packet(),
    ])
    res = scan(_write(tmp_path, tops))
    assert res.start_ns == 100
    assert res.end_ns == 300
    assert res.packet_count == 3
    assert res.ftrace["event_counts"]["print"] == 2
    assert sum(res.hist_bin_bytes) + res.untimed_bytes == \
        (tmp_path / "t.perfetto-trace").stat().st_size


# ---- trace_bounds parity vs trace_processor -----------------------------

@pytest.mark.tp
class TestTraceBoundsParity:
    def _bounds(self, tmp_path, name, packets):
        from tp import open_tp, query
        p = _write(tmp_path, _pf(packets), name)
        res = scan(p)
        tp = open_tp(p)
        try:
            row = query(tp, "select start_ts, end_ts from trace_bounds")[0]
        finally:
            tp.close()
        if res.start_ns is None:
            res.start_ns = res.end_ns = 0  # TP reports (0,0) for empty bounds
        return res, row

    def test_metadata_does_not_extend_bounds(self, tmp_path):
        # clock_snapshot + process_tree carry packet ts far earlier than
        # any event: they must NOT contribute to bounds.
        early = sb.clock_snapshot_packet(
            {6: 10_000, 3: 5_000}, timestamp=10_000)
        tree = sb.process_tree_packet(timestamp=9_000)
        ft = sb.ftrace_packet(cpu=0, events=[sb.print_event(100, 1, "B|1|x")])
        res, row = self._bounds(tmp_path, "a.perfetto-trace",
                                [early, tree, ft])
        assert (res.start_ns, res.end_ns) == (row["start_ts"], row["end_ts"])

    def test_android_log_extends_bounds(self, tmp_path):
        # LogEvent.timestamp is CLOCK_REALTIME (A1 fix): TP converts via
        # the clock_snapshot -- REALTIME+BOOTTIME needed for ingestion.
        snap = sb.clock_snapshot_packet({1: 0, 6: 0})
        log = sb.android_log_packet([(50, "t", "early"),
                                     (400, "t", "late")])
        ft = sb.ftrace_packet(cpu=0, events=[
            sb.print_event(100, 1, "B|1|x"),
            sb.print_event(300, 1, "E|1")])
        res, row = self._bounds(tmp_path, "b.perfetto-trace",
                                [snap, ft, log])
        assert (res.start_ns, res.end_ns) == (row["start_ts"],
                                            row["end_ts"])
        assert res.flags.get("has_logcat") is True
        st = res.per_type["android_log"]
        assert (st.count, st.min_ts, st.max_ts) == (1, 50, 400)

    def test_ftrace_before_service_event(self, tmp_path):
        svc = pb.TracePacket(
            service_event=pb.TracingServiceEvent(),
            timestamp=999_999).SerializeToString()
        ft = sb.ftrace_packet(cpu=0, events=[
            sb.sched_switch_event(100, 1, "a", 1, "b", 2),
            sb.print_event(300, 1, "E|1")])
        res, row = self._bounds(tmp_path, "c.perfetto-trace", [ft, svc])
        assert (res.start_ns, res.end_ns) == (row["start_ts"], row["end_ts"])
        assert res.start_ns == 100  # early ftrace events count

    def test_first_compact_switch_dropped(self, tmp_path):
        # TP drops the first compact sched_switch per cpu and wakings
        # before the first switch (in global ts order).
        cs = sb.compact_sched(switch_ts=[2000], switch_next_pid=[42],
                              intern_table=["swapper"])
        cs.waking_timestamp.append(1000)
        cs.waking_pid.append(7)
        cs.waking_target_cpu.append(0)
        cs.waking_prio.append(120)
        cs.waking_comm_index.append(0)
        cs.waking_common_flags.append(0)
        ft = sb.ftrace_packet(cpu=0, compact=cs)
        res, row = self._bounds(tmp_path, "d.perfetto-trace", [ft])
        assert (res.start_ns, res.end_ns) == (row["start_ts"], row["end_ts"])
        # switch@2000 skipped, waking@1000 dropped -> no ts rows
        assert res.start_ns == 0

    def test_waking_after_switch_counts(self, tmp_path):
        cs = sb.compact_sched(switch_ts=[2000], switch_next_pid=[42],
                              intern_table=["swapper"])
        cs.waking_timestamp.append(2500)
        cs.waking_pid.append(7)
        cs.waking_target_cpu.append(0)
        cs.waking_prio.append(120)
        cs.waking_comm_index.append(0)
        cs.waking_common_flags.append(0)
        res, row = self._bounds(tmp_path, "e.perfetto-trace",
                                [sb.ftrace_packet(cpu=0, compact=cs)])
        assert (res.start_ns, res.end_ns) == (row["start_ts"], row["end_ts"])
        assert res.start_ns == 2500

    def test_interleaved_cpu_bundles(self, tmp_path):
        # CPU1's earlier bundle is written after CPU0's later bundle:
        # file order != ts order by ~1 s. Bounds must still match TP.
        ft1 = sb.ftrace_packet(cpu=1, events=[
            sb.sched_switch_event(100, 1, "a", 1, "b", 2)])
        ft0 = sb.ftrace_packet(cpu=0, events=[
            sb.print_event(900_000_000, 1, "B|5|x"),
            sb.print_event(1_200_000_000, 1, "E|5")])
        ft0b = sb.ftrace_packet(cpu=0, events=[
            sb.print_event(2_000_000_000, 1, "I|5|done")])
        res, row = self._bounds(tmp_path, "g.perfetto-trace",
                                [ft0, ft0b, ft1])  # ft1 ts=100 written LAST
        assert (res.start_ns, res.end_ns) == (row["start_ts"], row["end_ts"])

    def test_battery_packet_ts_counts(self, tmp_path):
        bat = pb.TracePacket(
            battery=pb.BatteryCounters(capacity_percent=50),
            timestamp=50).SerializeToString()
        ft = sb.ftrace_packet(cpu=0, events=[sb.print_event(300, 1, "E|1")])
        res, row = self._bounds(tmp_path, "f.perfetto-trace", [ft, bat])
        assert (res.start_ns, res.end_ns) == (row["start_ts"], row["end_ts"])
        assert res.start_ns == 50


# ---- histogram / conservation --------------------------------------------

def test_histogram_literal(tmp_path):
    # two events in bin 0 ([0,10ms)), one packet in bin 1
    tops = _pf([
        sb.clock_snapshot_packet({1: 0, 6: 0}),
        sb.ftrace_packet(cpu=0, events=[sb.print_event(1_000_000, 1, "B|1|x"),
                                        sb.print_event(9_000_000, 1, "E|1")]),
        sb.android_log_packet([(15_000_000, "t", "m")]),
    ])
    res = scan(_write(tmp_path, tops))
    assert res.start_ns == 1_000_000
    # bins are 10ms from start_ns=1ms -> bin0=[1ms,11ms): 2 ftrace events;
    # bin1=[11ms,21ms): log event
    assert res.hist_bin_events[:2] == [2, 1]
    assert res.hist_bin_bytes[0] > 0 and res.hist_bin_bytes[1] > 0


@pytest.mark.sample
def test_sample_scan_parity(sample_trace, sample_tp):
    from tp import query
    res = scan(sample_trace)
    row = query(sample_tp, "select start_ts, end_ts from trace_bounds")[0]
    assert res.start_ns == row["start_ts"]
    assert res.end_ns == row["end_ts"]
    # conservation: histogram bytes + untimed == file size
    assert sum(res.hist_bin_bytes) + res.untimed_bytes == res.file_size
    assert res.packet_count > 0


@pytest.mark.sample
def test_sample_event_counts_vs_tp(sample_trace, sample_tp):
    from tp import query
    res = scan(sample_trace)
    # TP drops the first compact switch per cpu (8 cpus)
    tp_slices = query(sample_tp, "select count(*) as c from sched_slice")[0]["c"]
    assert res.ftrace["event_counts"]["sched_switch"] - tp_slices == 8
    # slices count should be >= our parseable print B events
    tp_slice_rows = query(sample_tp, "select count(*) as c from slice")[0]["c"]
    assert res.ftrace["event_counts"]["print"] >= tp_slice_rows
