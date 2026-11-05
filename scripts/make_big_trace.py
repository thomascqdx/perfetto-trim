#!/usr/bin/env python3
"""Concatenate N time-shifted copies of a trace for scale testing.

Each copy i is shifted by i * (duration_ns + 1 s) so all timestamps are
strictly increasing across copies. Every known timestamp field is
shifted; metadata packets (trace_config, system_info, clock_snapshot,
process_tree, ...) are kept only from copy 0.

Streams packet-by-packet: O(packet) memory. Importable:

    from make_big_trace import make_big_trace
    make_big_trace("in.pftrace", "out.pftrace", copies=4)
"""

from __future__ import annotations

import argparse
import os
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pftrim import fields  # noqa: E402
from pftrim.reader import iter_packets  # noqa: E402
from pftrim.scan import scan  # noqa: E402
from pftrim.wire import (WT_LEN, WT_VARINT, decode_packed_varints,
                         encode_packed_varints, iter_fields, len_field,
                         varint_field)  # noqa: E402
from pftrim.writer import TraceWriter  # noqa: E402

_TP = fields.TracePacket

# TracePacket fields dropped for copies > 0 (metadata / bookkeeping that
# must appear exactly once in the merged trace).
_META_ONCE = frozenset({
    _TP.PROCESS_TREE, _TP.INODE_FILE_MAP, _TP.CLOCK_SNAPSHOT,
    _TP.TRACE_CONFIG, _TP.SYSTEM_INFO, _TP.PACKAGES_LIST,
    _TP.SERVICE_EVENT, _TP.FTRACE_STATS, _TP.TRACE_STATS,
    _TP.TRACE_PACKET_DEFAULTS, _TP.INTERNED_DATA, _TP.TRACK_DESCRIPTOR,
    _TP.MODULE_SYMBOLS, _TP.DEOBFUSCATION_MAPPING, _TP.CPU_INFO,
    _TP.EXTENSION_DESCRIPTOR, _TP.TRANSLATION_TABLE, _TP.TRACE_PROVENANCE,
    _TP.TRACE_ATTRIBUTES, _TP.SYNCHRONIZATION_MARKER, _TP.MACHINE_ID,
    _TP.TRACE_UUID, _TP.CLONE_SNAPSHOT_TRIGGER,
})


def _shift_varints(payload, field_nos, delta):
    """Re-encode `payload` with varint fields in field_nos += delta."""
    if delta == 0:
        return bytes(payload)
    out = bytearray()
    for fno, wt, val, s, e in iter_fields(payload):
        if wt == WT_VARINT and fno in field_nos:
            out += varint_field(fno, val + delta)
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)


def _shift_first_packed(payload, field_nos, delta):
    """Shift only the FIRST element of packed-varint columns in
    field_nos (compact_sched timestamps are deltas accumulated from 0)."""
    out = bytearray()
    for fno, wt, val, s, e in iter_fields(payload):
        if wt == WT_LEN and fno in field_nos:
            vals = decode_packed_varints(val)
            if vals:
                vals[0] += delta
            out += len_field(fno, encode_packed_varints(vals))
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)


def _shift_compact(payload, delta):
    return _shift_first_packed(
        payload,
        {fields.FtraceEventBundle.CompactSched.SWITCH_TIMESTAMP,
         fields.FtraceEventBundle.CompactSched.WAKING_TIMESTAMP},
        delta)


def _shift_ftrace_event(payload, delta):
    return _shift_varints(payload, {fields.FtraceEvent.TIMESTAMP}, delta)


def _shift_bundle(payload, delta):
    if delta == 0:
        return bytes(payload)
    _B = fields.FtraceEventBundle
    out = bytearray()
    for fno, wt, val, s, e in iter_fields(payload):
        if fno == _B.EVENT and wt == WT_LEN:
            out += len_field(fno, _shift_ftrace_event(val, delta))
        elif fno == _B.COMPACT_SCHED and wt == WT_LEN:
            out += len_field(fno, _shift_compact(val, delta))
        elif wt == WT_VARINT and fno in (
                _B.FTRACE_TIMESTAMP, _B.BOOT_TIMESTAMP,
                _B.LAST_READ_EVENT_TIMESTAMP,
                _B.PREVIOUS_BUNDLE_END_TIMESTAMP):
            out += varint_field(fno, val + delta)
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)


def _shift_clock_snapshot(payload, delta):
    out = bytearray()
    for fno, wt, val, s, e in iter_fields(payload):
        if fno == fields.ClockSnapshot.CLOCKS and wt == WT_LEN:
            out += len_field(
                fno, _shift_varints(
                    val, {fields.ClockSnapshot.Clock.TIMESTAMP}, delta))
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)


def _shift_android_log(payload, delta):
    _A = fields.AndroidLogPacket
    out = bytearray()
    for fno, wt, val, s, e in iter_fields(payload):
        if fno == _A.EVENTS and wt == WT_LEN:
            out += len_field(
                fno, _shift_varints(
                    val, {_A.LogEvent.TIMESTAMP}, delta))
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)


def _shift_packet(payload, delta, drop_meta: bool):
    """Rebuild one TracePacket payload with all known timestamps shifted
    by delta. Returns None if the packet is metadata-only and drop_meta
    (i.e. it is entirely metadata fields for copy>0)."""
    out = bytearray()
    has_non_meta = False
    for fno, wt, val, s, e in iter_fields(payload):
        meta = fno in _META_ONCE
        if not meta:
            has_non_meta = True
        elif drop_meta:
            continue  # metadata: keep only copy 0
        if fno == _TP.TIMESTAMP and wt == WT_VARINT:
            out += varint_field(fno, val + delta)
        elif fno == _TP.FTRACE_EVENTS and wt == WT_LEN:
            out += len_field(fno, _shift_bundle(val, delta))
        elif fno == _TP.CLOCK_SNAPSHOT and wt == WT_LEN:
            out += len_field(fno, _shift_clock_snapshot(val, delta))
        elif fno == _TP.ANDROID_LOG and wt == WT_LEN:
            out += len_field(fno, _shift_android_log(val, delta))
        elif fno == _TP.PROCESS_TREE and wt == WT_LEN:
            out += len_field(
                fno, _shift_varints(
                    val, {fields.ProcessTree.COLLECTION_END_TIMESTAMP},
                    delta))
        elif fno == _TP.COMPRESSED_PACKETS and wt == WT_LEN:
            out += len_field(
                fno, zlib.compress(_shift_trace(val, delta, drop_meta)))
        else:
            out += bytes(memoryview(payload)[s:e])
    if not out:
        return None
    return bytes(out)


def _shift_trace(data: bytes, delta: int, drop_meta: bool) -> bytes:
    """Shift a serialized Trace (sequence of field-1 packet records)."""
    out = bytearray()
    for fno, wt, val, s, e in iter_fields(data):
        if fno == fields.Trace.PACKET and wt == WT_LEN:
            p = _shift_packet(val, delta, drop_meta)
            if p is not None:
                out += len_field(fno, p)
        else:
            out += bytes(memoryview(data)[s:e])
    return bytes(out)


def _packet_duration_ns(path) -> int:
    res = scan(path)
    assert res.start_ns is not None and res.end_ns is not None, \
        "trace has no timestamped events"
    return res.end_ns - res.start_ns


def make_big_trace(in_path, out_path, copies: int,
                   progress=None) -> dict:
    """Write `copies` time-shifted copies of in_path to out_path."""
    dur_ns = _packet_duration_ns(in_path)
    step = dur_ns + 1_000_000_000
    written = 0
    with TraceWriter(out_path) as w:
        for i in range(copies):
            delta = i * step
            for rec in iter_packets(in_path, expand_compressed=False):
                if rec.field_no != fields.Trace.PACKET or delta == 0:
                    w.write_raw(bytes(rec.raw))  # verbatim
                    continue
                p = _shift_packet(rec.payload, delta, drop_meta=i > 0)
                if p is not None:
                    w.write_packet(p)
                    written += 1
    return {
        "copies": copies,
        "step_ns": step,
        "duration_ns": dur_ns,
        "packets_written": written,
        "size": os.path.getsize(out_path),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--copies", type=int, default=4)
    args = ap.parse_args(argv)
    info = make_big_trace(args.input, args.output, args.copies)
    print(f"wrote {info['packets_written']} packets, "
          f"{info['size'] / 1e6:.1f} MB, step {info['step_ns'] / 1e9:.3f}s "
          f"x{info['copies']} copies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
