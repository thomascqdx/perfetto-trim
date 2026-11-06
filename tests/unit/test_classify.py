import builder as sb
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

from pftrim import classify, fields

_TP = fields.TracePacket


def test_ftrace_then_interned_is_ftrace():
    """[ftrace_events, interned_data] -> (MULTI_EVENT, FTRACE_EVENTS):
    a trailing metadata field must not mask the real data field."""
    pkt = pb.TracePacket(
        ftrace_events=pb.FtraceEventBundle(cpu=0),
        interned_data=pb.InternedData(),
        trusted_packet_sequence_id=2,
        trusted_uid=1000,
    ).SerializeToString()
    cls, fno = classify.classify_packet(pkt)
    assert cls == classify.MULTI_EVENT
    assert fno == _TP.FTRACE_EVENTS


def test_track_event_then_interned_is_timed():
    pkt = pb.TracePacket(
        track_event=pb.TrackEvent(),
        interned_data=pb.InternedData(),
        trusted_packet_sequence_id=8,
    ).SerializeToString()
    cls, fno = classify.classify_packet(pkt)
    assert cls == classify.TIMED
    assert fno == _TP.TRACK_EVENT


def test_last_class_field_wins():
    pkt = pb.TracePacket(
        interned_data=pb.InternedData(),
        sys_stats=pb.SysStats(),
    ).SerializeToString()
    cls, fno = classify.classify_packet(pkt)
    assert cls == classify.SNAPSHOT
    assert fno == _TP.SYS_STATS


def test_metadata_only_returns_last_field():
    """METADATA packets keep reporting the last data field (the engine
    checks SERVICE_EVENT on those)."""
    pkt = pb.TracePacket(
        cpu_info=pb.CpuInfo(),
        interned_data=pb.InternedData(),
    ).SerializeToString()
    cls, fno = classify.classify_packet(pkt)
    assert cls == classify.METADATA
    assert fno == _TP.CPU_INFO  # last data field on the wire


def test_timed_never_overrides_earlier_class():
    # TracePacket data fields are a oneof -- append a second class field
    # after the wire-encoded snapshot field.
    pkt = pb.TracePacket(
        process_stats=pb.ProcessStats(collection_end_timestamp=1),
    ).SerializeToString() + sb.len_field(
        _TP.BATTERY, pb.BatteryCounters(
            capacity_percent=50).SerializeToString())
    cls, fno = classify.classify_packet(pkt)
    assert cls == classify.SNAPSHOT
    assert fno == _TP.PROCESS_STATS
