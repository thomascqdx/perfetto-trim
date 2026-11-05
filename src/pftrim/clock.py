"""ClockSnapshot handling: convert packet/ftrace timestamps to BOOTTIME ns.

Mirrors trace_processor v57 semantics:

- ClockSnapshot packets give (clock_id, timestamp) pairs at one instant;
  conversion uses the *closest snapshot at or before* the source timestamp
  (the first snapshot if the ts predates all of them) and applies that
  snapshot's offset -- the same nearest-snapshot-offset rule as
  ClockSynchronizer::ConvertSlowpath.
- Ftrace bundles with ftrace_clock GLOBAL/LOCAL get a sequence-scoped
  clock (id 64 per sequence) fed by the bundle's
  (ftrace_timestamp, boot_timestamp) pair, like
  FtraceTokenizer::HandleFtraceClockSnapshot. MONO_RAW maps to the
  MONOTONIC_RAW builtin clock. UNSPECIFIED/missing is BOOTTIME.
- Unknown clocks (no snapshot at all) yield None and count a warning.
"""

from __future__ import annotations

import bisect

from . import fields
from .wire import WT_LEN, WT_VARINT, iter_fields

BUILTIN_CLOCK_BOOTTIME = fields.BUILTIN_CLOCK_BOOTTIME        # 6
BUILTIN_CLOCK_MONOTONIC_RAW = fields.BUILTIN_CLOCK_MONOTONIC_RAW  # 5
BUILTIN_CLOCK_MAX_ID = fields.BUILTIN_CLOCK_MAX_ID            # 63
SEQUENCE_CLOCK_BASE = 64

_FTRACE_SEQ_KEY_PREFIX = "f"


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
        # clock key -> sorted list of (src_ts_ns, boot_ts_ns) snapshot points.
        # key is an int for builtin clocks, ('f', seq_id) for the
        # sequence-scoped ftrace clock.
        self._anchors: dict = {}
        # clock_id -> last absolute timestamp (for incremental snapshots).
        self._last_ts: dict[int, int] = {}
        self.primary_clock: int | None = None
        # sequence_id -> default timestamp clock id (trace_packet_defaults).
        self._seq_clock: dict[int, int] = {}
        # last ftrace_timestamp registered per sequence (dedup).
        self._last_ftrace_snap: dict[int, int] = {}
        self.unknown_clock_warnings = 0
        self.snapshots_seen = 0

    def _add_anchor(self, key, src_ts: int, boot_ts: int) -> None:
        bisect.insort(self._anchors.setdefault(key, []), (src_ts, boot_ts))

    def update(self, packet_payload) -> None:
        """Ingest a TracePacket payload containing a clock_snapshot field.

        No-op if the packet has no clock_snapshot.
        """
        tp = fields.TracePacket
        for fno, wt, val, _s, _e in iter_fields(packet_payload):
            if fno == tp.CLOCK_SNAPSHOT and wt == WT_LEN:
                self.update_snapshot(val)
                return

    def update_snapshot(self, snapshot_payload) -> None:
        """Ingest a ClockSnapshot message payload directly."""
        primary, entries = _clock_entries(snapshot_payload)
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
                self._add_anchor(cid, ts, boot)
        self.snapshots_seen += 1

    def set_sequence_clock(self, sequence_id: int, clock_id: int) -> None:
        self._seq_clock[sequence_id] = clock_id

    def sequence_clock(self, sequence_id) -> int:
        """Default timestamp clock id for a sequence (BOOTTIME if unset)."""
        return self._seq_clock.get(sequence_id, BUILTIN_CLOCK_BOOTTIME)

    def update_packet_defaults(self, sequence_id: int, defaults_payload) -> None:
        """Ingest a TracePacketDefaults payload for a sequence."""
        for fno, wt, val, _s, _e in iter_fields(defaults_payload):
            if fno == fields.TracePacketDefaults.TIMESTAMP_CLOCK_ID and wt == WT_VARINT:
                self._seq_clock[sequence_id] = val

    def register_ftrace_snapshot(self, sequence_id: int,
                                 ftrace_ts: int, boot_ts: int) -> None:
        """Feed a bundle's (ftrace_timestamp, boot_timestamp) pair into the
        sequence-scoped ftrace clock (GLOBAL/LOCAL)."""
        key = (_FTRACE_SEQ_KEY_PREFIX, sequence_id)
        if self._last_ftrace_snap.get(key) == ftrace_ts:
            return
        self._add_anchor(key, ftrace_ts, boot_ts)
        self._last_ftrace_snap[key] = ftrace_ts

    def to_boottime(self, clock_id, ts: int) -> int | None:
        """Convert a timestamp on clock_id to BOOTTIME ns (None if unknown).

        clock_id is a builtin id (int) or ('f', seq_id) for the
        sequence-scoped ftrace clock.
        """
        if clock_id == BUILTIN_CLOCK_BOOTTIME:
            return ts
        anchors = self._anchors.get(clock_id)
        if not anchors:
            self.unknown_clock_warnings += 1
            return None
        i = bisect.bisect_right(anchors, (ts, 1 << 62)) - 1
        if i < 0:
            i = 0  # predates all snapshots: use the earliest offset (as TP)
        src, boot = anchors[i]
        return ts - src + boot

    def ftrace_to_boottime(self, ftrace_clock_enum: int | None,
                           sequence_id: int | None, ts: int) -> int | None:
        """Convert an ftrace event timestamp to BOOTTIME per the bundle's
        ftrace_clock enum (mirrors HandleFtraceClockSnapshot)."""
        if ftrace_clock_enum in (None, fields.FTRACE_CLOCK_UNSPECIFIED):
            return ts
        if ftrace_clock_enum == fields.FTRACE_CLOCK_MONO_RAW:
            return self.to_boottime(BUILTIN_CLOCK_MONOTONIC_RAW, ts)
        if ftrace_clock_enum in (fields.FTRACE_CLOCK_GLOBAL,
                                 fields.FTRACE_CLOCK_LOCAL):
            if sequence_id is None:
                self.unknown_clock_warnings += 1
                return None
            return self.to_boottime((_FTRACE_SEQ_KEY_PREFIX, sequence_id), ts)
        # FTRACE_CLOCK_UNKNOWN or anything else: TP errors out; we warn.
        self.unknown_clock_warnings += 1
        return None

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
