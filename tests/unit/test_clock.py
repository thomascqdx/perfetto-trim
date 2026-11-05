import pytest

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


def test_incremental_snapshot():
    conv = ClockConverter()
    conv.update(_snapshot({BOOTTIME: 1_000_000, MONOTONIC: 500_000}))
    # incremental: timestamps are deltas vs previous snapshot
    conv.update(sb.clock_snapshot_packet(
        {BOOTTIME: 100_000, MONOTONIC: 100_000}, is_incremental=True))
    # abs: boot=1_100_000, mono=600_000
    assert conv.to_boottime(MONOTONIC, 700_000) == 1_200_000


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
