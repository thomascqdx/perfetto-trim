"""Synthetic trace builder for tests (dev-only; uses perfetto_trace_pb2).

All helpers return serialized bytes so tests can stitch streams without the
protobuf runtime. Top-level field encoders are tiny local copies -- do NOT
import pftrim.wire here so the tests exercise wire.py independently.
"""

from __future__ import annotations

import pathlib
import zlib

from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

WT_VARINT = 0
WT_FIXED64 = 1
WT_LEN = 2
WT_FIXED32 = 5

TRACE_PACKET_FIELD = 1  # Trace.packet


def varint(value: int) -> bytes:
    value &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field_no: int, wire_type: int) -> bytes:
    return varint((field_no << 3) | wire_type)


def len_field(field_no: int, payload: bytes) -> bytes:
    return tag(field_no, WT_LEN) + varint(len(payload)) + payload


def varint_field(field_no: int, value: int) -> bytes:
    return tag(field_no, WT_VARINT) + varint(value)


def packet_bytes(packet: pb.TracePacket) -> bytes:
    return packet.SerializeToString()


def top_field(field_no: int, payload: bytes, wire_type: int = WT_LEN) -> bytes:
    """A raw top-level Trace field (e.g. a packet, or an unknown field)."""
    if wire_type == WT_LEN:
        return len_field(field_no, payload)
    if wire_type == WT_VARINT:
        return tag(field_no, WT_VARINT) + payload  # payload = raw varint bytes
    return tag(field_no, wire_type) + payload


def trace_bytes(top_fields: list[bytes]) -> bytes:
    """Concatenate serialized top-level fields into a trace stream."""
    return b"".join(top_fields)


def packet_field(packet_payload: bytes) -> bytes:
    """Wrap a serialized TracePacket as a Trace.packet top-level field."""
    return len_field(TRACE_PACKET_FIELD, packet_payload)


def write_trace(path, top_fields: list[bytes]) -> pathlib.Path:
    path = pathlib.Path(path)
    path.write_bytes(trace_bytes(top_fields))
    return path


def clock_snapshot_packet(
    clocks: dict[int, int],
    primary: int = 6,
    is_incremental: bool = False,
    incremental_ids: set[int] | None = None,
    unit_multipliers: dict[int, int] | None = None,
    **pkt_kw,
) -> bytes:
    cs = pb.ClockSnapshot()
    inc_ids = incremental_ids or set()
    for clock_id, ts in sorted(clocks.items()):
        c = cs.clocks.add()
        c.clock_id = clock_id
        c.timestamp = ts
        if is_incremental or clock_id in inc_ids:
            c.is_incremental = True
        if unit_multipliers and clock_id in unit_multipliers:
            c.unit_multiplier_ns = unit_multipliers[clock_id]
    cs.primary_trace_clock = primary
    pkt = pb.TracePacket(clock_snapshot=cs, **pkt_kw)
    return packet_bytes(pkt)


def print_event(ts: int, pid: int, buf: bytes | str, common_flags: int = 0) -> pb.FtraceEvent:
    ev = pb.FtraceEvent(timestamp=ts, pid=pid)
    if common_flags:
        ev.common_flags = common_flags
    if isinstance(buf, str):
        buf = buf.encode()
    ev.print.buf = buf
    return ev


def sched_switch_event(ts: int, pid: int, prev_comm: str, prev_pid: int,
                       next_comm: str, next_pid: int,
                       prev_state: int = 0, prev_prio: int = 100,
                       next_prio: int = 100) -> pb.FtraceEvent:
    ev = pb.FtraceEvent(timestamp=ts, pid=pid)
    ss = ev.sched_switch
    ss.prev_comm = prev_comm
    ss.prev_pid = prev_pid
    ss.next_comm = next_comm
    ss.next_pid = next_pid
    ss.prev_state = prev_state
    ss.prev_prio = prev_prio
    ss.next_prio = next_prio
    return ev


def sched_waking_event(ts: int, pid: int, comm: str, woken_pid: int,
                       target_cpu: int = 0, prio: int = 100) -> pb.FtraceEvent:
    ev = pb.FtraceEvent(timestamp=ts, pid=pid)
    w = ev.sched_waking
    w.comm = comm
    w.pid = woken_pid
    w.target_cpu = target_cpu
    w.prio = prio
    return ev


def compact_sched(switch_ts: list[int], switch_next_pid: list[int],
                  intern_table: list[str] | None = None) -> pb.FtraceEventBundle.CompactSched:
    cs = pb.FtraceEventBundle.CompactSched()
    cs.switch_timestamp.extend(switch_ts)
    cs.switch_next_pid.extend(switch_next_pid)
    cs.switch_prev_state.extend([0] * len(switch_ts))
    cs.switch_next_prio.extend([120] * len(switch_ts))
    cs.switch_next_comm_index.extend([0] * len(switch_ts))
    if intern_table:
        cs.intern_table.extend(intern_table)
    return cs


def ftrace_packet(cpu: int = 0, events: list[pb.FtraceEvent] | None = None,
                  compact: pb.FtraceEventBundle.CompactSched | None = None,
                  bundle_kw: dict | None = None, **pkt_kw) -> bytes:
    bundle = pb.FtraceEventBundle(cpu=cpu)
    for ev in events or []:
        bundle.event.append(ev)
    if compact is not None:
        bundle.compact_sched.CopyFrom(compact)
    for k, v in (bundle_kw or {}).items():
        setattr(bundle, k, v)
    pkt = pb.TracePacket(ftrace_events=bundle, **pkt_kw)
    return packet_bytes(pkt)


def process_tree_packet(**pkt_kw) -> bytes:
    pt = pb.ProcessTree()
    p = pt.processes.add(pid=100, ppid=1)
    p.cmdline.append("/system/bin/surfaceflinger")
    t = pt.threads.add(tid=101, tgid=100)
    t.name = "surfaceflinger"
    pkt = pb.TracePacket(process_tree=pt, **pkt_kw)
    return packet_bytes(pkt)


def android_log_packet(logs: list[tuple[int, str, str]], **pkt_kw) -> bytes:
    """logs: list of (timestamp_ns, tag, message)."""
    alp = pb.AndroidLogPacket()
    for ts, tag_, msg in logs:
        ev = alp.events.add()
        ev.timestamp = ts
        ev.tag = tag_
        ev.message = msg
        ev.pid = 100
        ev.tid = 101
        ev.uid = 1000
    pkt = pb.TracePacket(android_log=alp, **pkt_kw)
    return packet_bytes(pkt)


def unknown_packet(field_no: int = 9999, payload: bytes = b"\xde\xad\xbe\xef",
                   **pkt_kw) -> bytes:
    """A TracePacket payload containing an unknown field."""
    pkt = pb.TracePacket(**pkt_kw)
    return packet_bytes(pkt) + len_field(field_no, payload)


def raw_trace_packet(raw: bytes) -> bytes:
    """Inject raw bytes inside a Trace.packet field verbatim (pre-corrupted)."""
    return raw


def compressed_packet(inner_packet_payloads: list[bytes], **pkt_kw) -> bytes:
    """Wrap serialized TracePacket payloads inside compressed_packets (zlib)."""
    inner = trace_bytes([packet_field(p) for p in inner_packet_payloads])
    pkt = pb.TracePacket(**pkt_kw)
    pkt.compressed_packets = zlib.compress(inner)
    return packet_bytes(pkt)


def trace_packet_defaults_packet(timestamp_clock_id: int, sequence_id: int,
                                 **pkt_kw) -> bytes:
    pkt = pb.TracePacket(
        trace_packet_defaults=pb.TracePacketDefaults(
            timestamp_clock_id=timestamp_clock_id),
        trusted_packet_sequence_id=sequence_id,
        **pkt_kw,
    )
    return packet_bytes(pkt)
