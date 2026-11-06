import pytest
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

from pftrim import fields, wire
from pftrim.clock import ClockConverter

import builder as sb

BOOTTIME = fields.BUILTIN_CLOCK_BOOTTIME      # 6
MONOTONIC = fields.BUILTIN_CLOCK_MONOTONIC    # 3
REALTIME = fields.BUILTIN_CLOCK_REALTIME      # 1


def _snapshot(clocks, primary=BOOTTIME):
    return sb.clock_snapshot_packet(clocks, primary=primary)


def test_boottime_passthrough():
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    assert conv.to_boottime(BOOTTIME, 12345) == 12345


def test_monotonic_conversion():
    conv = ClockConverter()
    # snapshot: at instant X, boot=1_000_000, mono=500_000
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    # mono ts 600_000 -> 100us later -> boot 1_100_000
    assert conv.to_boottime(MONOTONIC, 600_000) == 1_100_000
    assert conv.to_boottime(MONOTONIC, 0) == 500_000


def test_uses_most_recent_snapshot():
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    conv.update(_snapshot({BOOTTIME: 2_000_000, MONOTONIC: 900_000}))
    assert conv.to_boottime(MONOTONIC, 950_000) == 2_050_000


def test_unknown_clock_returns_none_and_warns():
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000}))
    assert conv.to_boottime(80, 5) is None           # sequence-scoped
    assert conv.to_boottime(REALTIME, 5) is None     # known but unreported
    assert conv.unknown_clock_warnings == 2


def test_no_snapshot_yet():
    conv = ClockConverter()
    assert conv.to_boottime(MONOTONIC, 5) is None
    assert conv.to_boottime(BOOTTIME, 5) == 5


def test_global_incremental_snapshot_rejected():
    """TP: a non-sequence clock marked is_incremental is a snapshot
    error -- the WHOLE snapshot is ignored."""
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    bad = sb.clock_snapshot_packet(
        {BOOTTIME: 100_000, MONOTONIC: 100_000}, is_incremental=True)
    assert conv.update_snapshot(_snap_payload(bad)) == {}
    assert conv.unknown_clock_warnings == 1
    # anchors unchanged: same conversion as before the bad snapshot
    assert conv.to_boottime(MONOTONIC, 600_000) == 1_100_000


def _snap_payload(packet_bytes):
    """Extract the clock_snapshot message payload from a packet."""
    for fno, wt, val, _s, _e in wire.iter_fields(packet_bytes):
        if fno == fields.TracePacket.CLOCK_SNAPSHOT and wt == wire.WT_LEN:
            return val
    raise AssertionError("no clock_snapshot")


def _seq_snapshot(conv, clocks, seq, **kw):
    """Ingest a seq-scoped snapshot built as a packet."""
    return conv.update(sb.clock_snapshot_packet(
        clocks, trusted_packet_sequence_id=seq, **kw))


def test_sequence_incremental_clock():
    """Clock 64 on seq 8, is_incremental: snapshot is ABSOLUTE, packet
    timestamps are deltas accumulating from it."""
    conv = ClockConverter()
    B = 481_373_226_182
    inc = _seq_snapshot(conv, {BOOTTIME: B, 64: B}, seq=8,
                        incremental_ids={64})
    assert inc == {("s", 8, 64): B}
    d1, d2 = 2_065_538, 1_605_220_923
    ts, info = conv.packet_time(8, d1, 64)
    assert ts == B + d1
    assert info == (("s", 8, 64), B + d1, 1, d1)
    ts, info = conv.packet_time(8, d2, 64)
    assert ts == B + d1 + d2
    assert info == (("s", 8, 64), B + d1 + d2, 1, d2)


def test_sequence_incremental_unit_multiplier():
    conv = ClockConverter()
    # clock 64 in us (mult 1000): snapshot ts 1000 -> abs 1_000_000 ns,
    # anchored to BOOTTIME 1_000_000 (identity offset).
    _seq_snapshot(conv, {BOOTTIME: 1_000_000, 64: 1000}, seq=8,
                  incremental_ids={64}, unit_multipliers={64: 1000})
    # deltas are in clock units: last_ns += d * unit_multiplier_ns
    ts, info = conv.packet_time(8, 2000, 64)
    assert info == (("s", 8, 64), 3_000_000, 1000, 2000)
    assert ts == 3_000_000


def test_sequence_clocks_are_per_seq():
    """Same clock id 64 on seqs 8 and 9: independent chains."""
    conv = ClockConverter()
    B = 481_373_226_182
    _seq_snapshot(conv, {BOOTTIME: B, 64: B}, seq=8,
                  incremental_ids={64})
    _seq_snapshot(conv, {BOOTTIME: B + 5, 64: B + 5}, seq=9,
                  incremental_ids={64})
    assert conv.packet_time(8, 10, 64)[0] == B + 10
    assert conv.packet_time(9, 20, 64)[0] == B + 5 + 20
    assert conv.packet_time(8, 30, 64)[0] == B + 10 + 30


def test_observe_returns_snapshot_dict_and_skips_ts():
    """observe() applies defaults + snapshot and returns the inc dict;
    a packet carrying clock_snapshot never converts its timestamp."""
    conv = ClockConverter()
    B = 481_373_226_182
    pkt = sb.clock_snapshot_packet(
        {BOOTTIME: B, 64: B}, incremental_ids={64},
        trusted_packet_sequence_id=8, timestamp=12345)
    inc = conv.observe(pkt, seq=8)
    assert inc == {("s", 8, 64): B}
    assert conv.packet_timestamp_ns(pkt) is None


def test_packet_defaults_resolution_via_observe():
    """trace_packet_defaults' timestamp_clock_id is the fallback for
    packet_time when the packet has no explicit timestamp_clock_id."""
    conv = ClockConverter()
    B = 481_373_226_182
    _seq_snapshot(conv, {BOOTTIME: B, 64: B}, seq=8,
                  incremental_ids={64})
    pkt = sb.packet_bytes(pb.TracePacket(
        timestamp=7,
        trace_packet_defaults=pb.TracePacketDefaults(
            timestamp_clock_id=64),
        trusted_packet_sequence_id=8))
    assert conv.observe(pkt, seq=8) is None   # no clock_snapshot
    ts, info = conv.packet_time(8, 7, None)
    assert ts == B + 7


def test_packet_timestamp_defaults():
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    # sequence 7 defaults to MONOTONIC
    defaults = sb.trace_packet_defaults_packet(
        timestamp_clock_id=MONOTONIC, sequence_id=7)
    assert conv.packet_timestamp_ns(defaults) is None  # no timestamp
    # packet on seq 7 without timestamp_clock_id uses the default
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb
    pkt = pb.TracePacket(timestamp=600_000,
                         trusted_packet_sequence_id=7).SerializeToString()
    assert conv.packet_timestamp_ns(pkt) == 1_100_000


def test_packet_timestamp_explicit_clock_wins():
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb
    pkt = pb.TracePacket(
        timestamp=600_000,
        timestamp_clock_id=BOOTTIME,
        trusted_packet_sequence_id=7).SerializeToString()
    conv.set_sequence_clock(7, MONOTONIC)
    assert conv.packet_timestamp_ns(pkt) == 600_000  # explicit clock wins


def test_packet_timestamp_no_timestamp():
    conv = ClockConverter()
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb
    pkt = pb.TracePacket(trusted_uid=5).SerializeToString()
    assert conv.packet_timestamp_ns(pkt) is None
