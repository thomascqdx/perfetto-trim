"""ClockSnapshot handling: convert packet timestamps to BOOTTIME ns.

Feeds on ClockSnapshot payloads (sequence of (clock_id, timestamp) pairs
taken at the same instant). Conversion uses the most recent snapshot.
Unknown or sequence-scoped clock ids (>= 64) yield None and count a
warning on the converter.
"""

from __future__ import annotations

from . import fields
from .wire import WT_LEN, WT_VARINT, iter_fields

BUILTIN_CLOCK_BOOTTIME = fields.BUILTIN_CLOCK_BOOTTIME  # 6
BUILTIN_CLOCK_MAX_ID = fields.BUILTIN_CLOCK_MAX_ID      # 63


def _clock_entries(payload):
    """Parse a ClockSnapshot payload -> (primary_clock_id, {id: (ts_ns, incremental)})."""
    cs = fields.ClockSnapshot
    clk = fields.ClockSnapshot.Clock
    primary = None
    entries: dict[int, tuple[int, bool]] = {}
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno == cs.PRIMARY_TRACE_CLOCK and wt == WT_VARINT:
            primary = val
        elif fno == cs.CLOCKS and wt == WT_LEN:
            cid = ts = None
            inc = False
            mult = 1
            for cfno, cwt, cval, _cs, _ce in iter_fields(val):
                if cfno == clk.CLOCK_ID:
                    cid = cval
                elif cfno == clk.TIMESTAMP:
                    ts = cval
                elif cfno == clk.IS_INCREMENTAL:
                    inc = bool(cval)
                elif cfno == clk.UNIT_MULTIPLIER_NS:
                    mult = cval or 1
            if cid is not None and ts is not None:
                entries[cid] = (ts * mult, inc)
    return primary, entries


class ClockConverter:
    def __init__(self):
        # clock_id -> (clock_ts_at_snapshot, boot_ts_at_snapshot), both ns.
        self._anchors: dict[int, tuple[int, int]] = {}
        # clock_id -> last absolute timestamp (for incremental snapshots).
        self._last_ts: dict[int, int] = {}
        self.primary_clock: int | None = None
        # sequence_id -> default timestamp clock id (trace_packet_defaults).
        self._seq_clock: dict[int, int] = {}
        self.unknown_clock_warnings = 0
        self.snapshots_seen = 0

    def update(self, packet_payload) -> None:
        """Ingest a TracePacket payload containing a clock_snapshot field.

        No-op if the packet has no clock_snapshot.
        """
        tp = fields.TracePacket
        snapshot = None
        for fno, wt, val, _s, _e in iter_fields(packet_payload):
            if fno == tp.CLOCK_SNAPSHOT and wt == WT_LEN:
                snapshot = val
        if snapshot is None:
            return
        primary, entries = _clock_entries(snapshot)
        if primary is not None:
            self.primary_clock = primary
        # Resolve incremental timestamps against the previous absolute value.
        abs_ts: dict[int, int] = {}
        for cid, (ts, inc) in entries.items():
            if inc and cid in self._last_ts:
                ts = self._last_ts[cid] + ts
            abs_ts[cid] = ts
        self._last_ts.update(abs_ts)
        boot = abs_ts.get(BUILTIN_CLOCK_BOOTTIME)
        if boot is not None:
            for cid, ts in abs_ts.items():
                self._anchors[cid] = (ts, boot)
        self.snapshots_seen += 1

    def set_sequence_clock(self, sequence_id: int, clock_id: int) -> None:
        self._seq_clock[sequence_id] = clock_id

    def update_packet_defaults(self, sequence_id: int, defaults_payload) -> None:
        """Ingest a TracePacketDefaults payload for a sequence."""
        for fno, wt, val, _s, _e in iter_fields(defaults_payload):
            if fno == fields.TracePacketDefaults.TIMESTAMP_CLOCK_ID and wt == WT_VARINT:
                self._seq_clock[sequence_id] = val

    def to_boottime(self, clock_id: int, ts: int) -> int | None:
        """Convert a timestamp on clock_id to BOOTTIME ns (None if unknown)."""
        if clock_id == BUILTIN_CLOCK_BOOTTIME:
            return ts
        anchor = self._anchors.get(clock_id)
        if anchor is None:
            self.unknown_clock_warnings += 1
            return None
        clock_ts, boot_ts = anchor
        return ts - clock_ts + boot_ts

    def packet_timestamp_ns(self, payload) -> int | None:
        """Effective BOOTTIME timestamp of a TracePacket payload, or None.

        Clock resolution order: packet.timestamp_clock_id, else the
        sequence's trace_packet_defaults timestamp_clock_id, else BOOTTIME.
        A trace_packet_defaults field on the packet itself is registered
        for its sequence as a side effect.
        """
        tp = fields.TracePacket
        ts = clock_id = seq = None
        defaults = None
        for fno, wt, val, _s, _e in iter_fields(payload):
            if fno == tp.TIMESTAMP and wt == WT_VARINT:
                ts = val
            elif fno == tp.TIMESTAMP_CLOCK_ID and wt == WT_VARINT:
                clock_id = val
            elif fno == tp.TRUSTED_PACKET_SEQUENCE_ID and wt == WT_VARINT:
                seq = val
            elif fno == tp.TRACE_PACKET_DEFAULTS and wt == WT_LEN:
                defaults = val
        if defaults is not None and seq is not None:
            self.update_packet_defaults(seq, defaults)
        if ts is None:
            return None
        if clock_id is None:
            clock_id = self._seq_clock.get(seq, BUILTIN_CLOCK_BOOTTIME)
        return self.to_boottime(clock_id, ts)
