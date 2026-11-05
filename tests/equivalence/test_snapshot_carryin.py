"""Snapshot carry-ins (sys_stats / process_stats / process_tree) must
precede the window's in-window packets of the same sequence -- TP's
sorter drops a packet older than what it already flushed
(stats: sorter_push_event_out_of_order), losing the value at S."""

import pytest
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

from pftrim.engine import Options, Window, run
from synthetic import builder as B
from tp import open_tp, query

pytestmark = pytest.mark.tp

_SEQ = 3


def _sys_stats(ts, idle):
    st = pb.SysStats()
    c = st.cpu_stat.add()
    c.cpu_id = 0
    c.idle_ns = idle
    c.user_ns = idle // 2
    return B.packet_field(B.packet_bytes(pb.TracePacket(
        timestamp=ts, trusted_packet_sequence_id=_SEQ, sys_stats=st)))


def _service_event(**kw):
    return B.packet_field(B.packet_bytes(pb.TracePacket(
        trusted_packet_sequence_id=1,
        service_event=pb.TracingServiceEvent(**kw))))


def _trace(tmp_path):
    """write_into_file-style stream: TP (v57 kDefault sorting) extracts
    incrementally after >=2 flushes + a ReadBuffer event
    (trace_sorter.h NotifyReadBufferEvent), as in real long traces."""
    fields_ = [B.packet_field(B.clock_snapshot_packet({6: 1_000_000_000}))]
    for k in range(20):
        fields_.append(_sys_stats(1_000_000_000 + k * 500_000_000,
                                  1000 * (k + 1)))
        fields_.append(_service_event(all_data_sources_flushed=True))
        fields_.append(_service_event(all_data_sources_flushed=True))
        fields_.append(_service_event(read_tracing_buffers_completed=True))
    return B.write_trace(tmp_path / "sys.perfetto-trace", fields_)


def _idle_at(tp, S):
    rows = query(tp, f"select c.value from counter c join track tr on "
                     f"c.track_id=tr.id where tr.name='cpu.times.idle_ns' "
                     f"and c.ts <= {S} order by c.ts desc limit 1")
    return rows[0]["value"] if rows else None


def _out_of_order(tp):
    rows = query(tp, "select value from stats where "
                     "name='sorter_push_event_out_of_order'")
    return rows[0]["value"] if rows else 0


@pytest.mark.parametrize("keep_ts", [False, True])
def test_sys_stats_value_at_window_start(tmp_path, keep_ts):
    src = _trace(tmp_path)
    S, E = 5_250_000_000, 8_000_000_000
    out_dir = tmp_path / "out"
    rep = run(str(src), [Window(S, E)], str(out_dir),
              Options(keep_original_ts=keep_ts))
    tp_in = open_tp(src)
    tp_out = open_tp(rep.outputs[0].path)
    try:
        assert _out_of_order(tp_out) == 0
        assert _idle_at(tp_out, S) == _idle_at(tp_in, S) == 9000
        # in-window rows unchanged
        q = ("select c.ts, c.value from counter c join track tr on "
             "c.track_id=tr.id where tr.name='cpu.times.idle_ns' "
             f"and c.ts > {S} and c.ts < {E} order by c.ts")
        assert query(tp_out, q) == query(tp_in, q)
    finally:
        tp_in.close()
        tp_out.close()
