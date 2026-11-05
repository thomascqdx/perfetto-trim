"""FtraceEventBundle / FtraceEvent / CompactSched parsing (stdlib only).

compact_sched delta encoding (verified vs trace_processor v57
ftrace_tokenizer.cc TokenizeFtraceCompactSched*): `switch_timestamp` /
`waking_timestamp` are delta-encoded with the accumulator starting at 0 --
i.e. element 0 is the absolute timestamp, element i is the delta vs the
previous element. Re-encoding deltas reproduces the stored values exactly.

CompactSched.decode keeps the raw bytes of each field occurrence, so
encode() reproduces the original bytes verbatim (even for non-canonical
packed/unpacked/mixed encodings); column values are decoded lazily.
"""

from __future__ import annotations

from . import fields
from .wire import (
    WT_LEN,
    WT_VARINT,
    WireError,
    _varint_slow,
    decode_packed_varints,
    encode_packed_varints,
    iter_fields,
    len_field,
    read_varint,
    varint_field,
)

_B = fields.FtraceEventBundle
_CS = fields.FtraceEventBundle.CompactSched

# CompactSched column groups (field numbers from generated fields.py).
SWITCH_TS = _CS.SWITCH_TIMESTAMP            # 1 (delta-encoded, acc from 0)
SWITCH_PREV_STATE = _CS.SWITCH_PREV_STATE   # 2
SWITCH_NEXT_PID = _CS.SWITCH_NEXT_PID       # 3
SWITCH_NEXT_PRIO = _CS.SWITCH_NEXT_PRIO     # 4
INTERN_TABLE = _CS.INTERN_TABLE             # 5 (strings)
SWITCH_NEXT_COMM_INDEX = _CS.SWITCH_NEXT_COMM_INDEX  # 6
WAKING_TS = _CS.WAKING_TIMESTAMP            # 7 (delta-encoded, acc from 0)
WAKING_PID = _CS.WAKING_PID                 # 8
WAKING_TARGET_CPU = _CS.WAKING_TARGET_CPU   # 9
WAKING_PRIO = _CS.WAKING_PRIO               # 10
WAKING_COMM_INDEX = _CS.WAKING_COMM_INDEX   # 11
WAKING_COMMON_FLAGS = _CS.WAKING_COMMON_FLAGS  # 12

# scan-visible event names for compact events
COMPACT_SWITCH_NAME = "sched_switch"
COMPACT_WAKING_NAME = "sched_waking"


class CompactSched:
    """Decoded compact_sched with verbatim round-trip encoding.

    `occurrences`: list of (field_no, wire_type, raw_mv) in stream order.
    raw_mv covers the whole field occurrence (tag included).
    """

    __slots__ = ("occurrences", "_cache")

    def __init__(self, occurrences=None):
        self.occurrences = list(occurrences) if occurrences else []
        self._cache: dict[int, list] = {}

    @classmethod
    def decode(cls, payload) -> "CompactSched":
        occ = []
        for fno, wt, _v, s, e in iter_fields(payload):
            occ.append((fno, wt, memoryview(payload)[s:e]))
        return cls(occ)

    def encode(self) -> bytes:
        return b"".join(bytes(raw) for _f, _w, raw in self.occurrences)

    def raw_encode(self) -> bytes:
        return self.encode()

    def column(self, field_no: int) -> list[int]:
        """All values of a packed/varint column, decoded lazily."""
        vals = self._cache.get(field_no)
        if vals is None:
            vals = []
            for fno, wt, raw in self.occurrences:
                if fno != field_no:
                    continue
                if wt == WT_LEN:
                    vals.extend(decode_packed_varints(_len_payload(raw)))
                elif wt == WT_VARINT:
                    _tag, pos = read_varint(raw, 0)
                    v, _ = read_varint(raw, pos)
                    vals.append(v)
            self._cache[field_no] = vals
        return vals

    def intern_table(self) -> list[bytes]:
        vals = self._cache.get(-INTERN_TABLE)
        if vals is None:
            vals = [bytes(_len_payload(raw))
                    for fno, _w, raw in self.occurrences if fno == INTERN_TABLE]
            self._cache[-INTERN_TABLE] = vals
        return vals

    @staticmethod
    def _accumulate(deltas: list[int]) -> list[int]:
        out = []
        acc = 0
        for d in deltas:
            acc += d
            out.append(acc)
        return out

    def switch_timestamps(self) -> list[int]:
        return self._accumulate(self.column(SWITCH_TS))

    def waking_timestamps(self) -> list[int]:
        return self._accumulate(self.column(WAKING_TS))

    def replace_column(self, field_no: int, values: list[int]) -> None:
        """Re-encode one column (packed varint), dropping other occurrences
        of the same field. Used by later filtering milestones."""
        new_occ = []
        written = False
        for fno, wt, raw in self.occurrences:
            if fno != field_no:
                new_occ.append((fno, wt, raw))
            elif not written:
                new_occ.append((field_no, WT_LEN,
                                len_field(field_no, encode_packed_varints(values))))
                written = True
        if not written:
            new_occ.append((field_no, WT_LEN,
                            len_field(field_no, encode_packed_varints(values))))
        self.occurrences = new_occ
        self._cache.pop(field_no, None)

    def switch_event_count(self) -> int:
        return len(self.column(SWITCH_TS))

    def waking_event_count(self) -> int:
        return len(self.column(WAKING_TS))


def _len_payload(raw_mv) -> memoryview:
    """raw covers tag+len+payload of a LEN field -> payload slice."""
    _tag, pos = read_varint(raw_mv, 0)
    ln, pos = read_varint(raw_mv, pos)
    return raw_mv[pos:pos + ln]


def encode_compact_field(field_no: int, values: list[int]) -> bytes:
    return len_field(field_no, encode_packed_varints(values))


def build_compact_sched(columns: dict[int, list[int]],
                        intern_table: list[bytes] | None = None) -> bytes:
    """Encode a CompactSched payload from column lists (field order 1..12)."""
    out = bytearray()
    for fno in sorted(columns):
        out += encode_compact_field(fno, columns[fno])
    for s in intern_table or []:
        out += len_field(INTERN_TABLE, s)
    return bytes(out)


class BundleView:
    """Lazily-parsed FtraceEventBundle payload."""

    __slots__ = (
        "cpu", "lost_events", "ftrace_clock", "ftrace_timestamp",
        "boot_timestamp", "previous_bundle_end_timestamp",
        "last_read_event_timestamp", "error", "events", "compact",
        "other_ranges",
    )

    def __init__(self):
        self.cpu = 0
        self.lost_events = 0
        self.ftrace_clock = None
        self.ftrace_timestamp = None
        self.boot_timestamp = None
        self.previous_bundle_end_timestamp = None
        self.last_read_event_timestamp = None
        self.error = None
        self.events: list = []          # list[memoryview] of FtraceEvent
        self.compact = None             # memoryview of CompactSched payload
        self.other_ranges: list = []    # (start, end) verbatim fields


def parse_bundle(payload) -> BundleView:
    bv = BundleView()
    for fno, wt, val, s, e in iter_fields(payload):
        if fno == _B.CPU and wt == WT_VARINT:
            bv.cpu = val
        elif fno == _B.EVENT and wt == WT_LEN:
            bv.events.append(val)
        elif fno == _B.LOST_EVENTS and wt == WT_VARINT:
            bv.lost_events = val
        elif fno == _B.COMPACT_SCHED and wt == WT_LEN:
            bv.compact = val
        elif fno == _B.FTRACE_CLOCK and wt == WT_VARINT:
            bv.ftrace_clock = val
        elif fno == _B.FTRACE_TIMESTAMP and wt == WT_VARINT:
            bv.ftrace_timestamp = val
        elif fno == _B.BOOT_TIMESTAMP and wt == WT_VARINT:
            bv.boot_timestamp = val
        elif fno == _B.LAST_READ_EVENT_TIMESTAMP and wt == WT_VARINT:
            bv.last_read_event_timestamp = val
        elif fno == _B.PREVIOUS_BUNDLE_END_TIMESTAMP and wt == WT_VARINT:
            bv.previous_bundle_end_timestamp = val
        elif fno == _B.ERROR and wt == WT_VARINT:
            bv.error = val
        else:
            bv.other_ranges.append((s, e))
    return bv


def event_meta(ev) -> tuple:
    """(timestamp|None, pid|None, event_field_no|None, event_value_mv|None)

    For an FtraceEvent payload. The event field is the (single) oneof
    member; ts=field 1, pid=field 2, common_flags=field 5 are skipped.
    """
    mv = memoryview(ev)
    n = len(mv)
    pos = 0
    ts = pid = None
    etype = None
    eval_ = None
    while pos < n:
        b = mv[pos]
        pos += 1
        if b & 0x80:
            tag_val, pos = _varint_slow(mv, pos, b, n)
        else:
            tag_val = b
        fno = tag_val >> 3
        wt = tag_val & 7
        if wt == WT_VARINT:
            b = mv[pos]
            pos += 1
            if b & 0x80:
                v, pos = _varint_slow(mv, pos, b, n)
            else:
                v = b
            if fno == 1:
                ts = v
            elif fno == 2:
                pid = v
        elif wt == WT_LEN:
            b = mv[pos]
            pos += 1
            if b & 0x80:
                ln, pos = _varint_slow(mv, pos, b, n)
            else:
                ln = b
            if fno >= 3:
                etype = fno
                eval_ = mv[pos:pos + ln]
            pos += ln
        elif wt == 1:
            pos += 8
        elif wt == 5:
            pos += 4
        else:
            raise WireError(f"unsupported wire type {wt} in FtraceEvent")
    return ts, pid, etype, eval_


def print_buf(event_value) -> bytes | None:
    """Extract `buf` (bytes) from a PrintFtraceEvent payload.

    Direct byte scan: `buf` is a LEN field at
    fields.PrintFtraceEvent.BUF; other fields are skipped inline.
    """
    want_tag = (fields.PrintFtraceEvent.BUF << 3) | WT_LEN
    mv = memoryview(event_value)
    n = len(mv)
    pos = 0
    while pos < n:
        b = mv[pos]
        pos += 1
        if b & 0x80:
            tag_val, pos = _varint_slow(mv, pos, b, n)
        else:
            tag_val = b
        wt = tag_val & 7
        if tag_val == want_tag:
            b = mv[pos]
            pos += 1
            if b & 0x80:
                ln, pos = _varint_slow(mv, pos, b, n)
            else:
                ln = b
            return bytes(mv[pos:pos + ln])
        if wt == WT_VARINT:
            while True:
                if pos >= n:
                    return None
                b = mv[pos]
                pos += 1
                if not b & 0x80:
                    break
        elif wt == WT_LEN:
            b = mv[pos]
            pos += 1
            if b & 0x80:
                ln, pos = _varint_slow(mv, pos, b, n)
            else:
                ln = b
            pos += ln
        elif wt == 1:
            pos += 8
        elif wt == 5:
            pos += 4
        else:
            raise WireError(f"unsupported wire type {wt} in PrintFtraceEvent")
    return None


def iter_compact_event_timestamps(compact: CompactSched):
    """Yield (kind, abs_ts) for each compact event in column order."""
    for ts in compact.switch_timestamps():
        yield COMPACT_SWITCH_NAME, ts
    for ts in compact.waking_timestamps():
        yield COMPACT_WAKING_NAME, ts


def rewrite_event_ts(ev_payload, ts: int) -> bytes:
    """Copy an FtraceEvent with its timestamp (field 1) rewritten."""
    out = bytearray()
    wrote = False
    for fno, wt, _v, s, e in iter_fields(ev_payload):
        if fno == fields.FtraceEvent.TIMESTAMP and wt == WT_VARINT:
            out += varint_field(fno, ts)
            wrote = True
        else:
            out += bytes(memoryview(ev_payload)[s:e])
    if not wrote:
        out += varint_field(fields.FtraceEvent.TIMESTAMP, ts)
    return bytes(out)


# Carry-in counter events: ftrace event field no -> inner key field no.
# (kind_tag, inner_key_field) per event type, keyed by etype field number.
_COUNTER_KEY_FIELD = {
    fields.FtraceEvent.CPU_FREQUENCY: ("cpu_freq", 2),   # cpu_id
    fields.FtraceEvent.CPU_FREQUENCY_LIMITS: ("cpu_freq_limits", 3),  # cpu_id
    fields.FtraceEvent.CPU_IDLE: ("cpu_idle", 2),        # cpu_id
    fields.FtraceEvent.GPU_FREQUENCY: ("gpu_freq", 1),   # gpu_id
    fields.FtraceEvent.KGSL_GPU_FREQUENCY: ("gpu_freq", 2),  # gpu_id
}


def counter_key(etype: int, event_value):
    """(kind, key) if this event type is a carry-in counter, else None.
    Key = inner cpu_id/gpu_id field."""
    spec = _COUNTER_KEY_FIELD.get(etype)
    if spec is None or event_value is None:
        return None
    kind, key_fno = spec
    for fno, wt, val, _s, _e in iter_fields(event_value):
        if fno == key_fno and wt == WT_VARINT:
            return (kind, val)
    return (kind, 0)


def compact_switch_row(compact: CompactSched, i: int):
    """(prev_state, next_pid, next_prio, next_comm) for switch row i."""
    return (
        compact.column(SWITCH_PREV_STATE)[i],
        compact.column(SWITCH_NEXT_PID)[i],
        compact.column(SWITCH_NEXT_PRIO)[i],
        compact.intern_table()[compact.column(SWITCH_NEXT_COMM_INDEX)[i]],
    )


def build_carryin_compact_sched(ts: int, prev_state: int, next_pid: int,
                                next_prio: int, next_comm: bytes) -> bytes:
    """Single-switch CompactSched with its own 1-entry intern_table."""
    return build_compact_sched(
        {SWITCH_TS: [ts], SWITCH_PREV_STATE: [prev_state],
         SWITCH_NEXT_PID: [next_pid], SWITCH_NEXT_PRIO: [next_prio],
         SWITCH_NEXT_COMM_INDEX: [0]},
        [next_comm])


def build_bundle(cpu: int, events: list = (), compact: bytes | None = None,
                 prev_end_ts: int | None = None) -> bytes:
    """Encode an FtraceEventBundle payload."""
    out = bytearray()
    out += varint_field(_B.CPU, cpu)
    for ev in events:
        out += len_field(_B.EVENT, ev)
    if compact is not None:
        out += len_field(_B.COMPACT_SCHED, compact)
    if prev_end_ts is not None:
        out += varint_field(_B.PREVIOUS_BUNDLE_END_TIMESTAMP, prev_end_ts)
    return bytes(out)


def filter_compact(compact: CompactSched, sw_keep: list[bool],
                   wk_keep: list[bool]) -> bytes:
    """Filter compact_sched rows by boolean masks; delta re-encodes the
    timestamp columns; keeps intern_table and field order unchanged."""
    cs = CompactSched(list(compact.occurrences))
    if not all(sw_keep):
        for fno in (SWITCH_TS, SWITCH_PREV_STATE, SWITCH_NEXT_PID,
                    SWITCH_NEXT_PRIO, SWITCH_NEXT_COMM_INDEX):
            col = compact.column(fno)
            if fno == SWITCH_TS:
                abs_ts = compact.switch_timestamps()
                kept = [t for t, k in zip(abs_ts, sw_keep) if k]
                deltas = []
                prev = 0
                for t in kept:
                    deltas.append(t - prev)
                    prev = t
                cs.replace_column(fno, deltas)
            else:
                cs.replace_column(
                    fno, [v for v, k in zip(col, sw_keep) if k])
    if not all(wk_keep):
        for fno in (WAKING_TS, WAKING_PID, WAKING_TARGET_CPU, WAKING_PRIO,
                    WAKING_COMM_INDEX, WAKING_COMMON_FLAGS):
            col = compact.column(fno)
            if fno == WAKING_TS:
                abs_ts = compact.waking_timestamps()
                kept = [t for t, k in zip(abs_ts, wk_keep) if k]
                deltas = []
                prev = 0
                for t in kept:
                    deltas.append(t - prev)
                    prev = t
                cs.replace_column(fno, deltas)
            else:
                cs.replace_column(
                    fno, [v for v, k in zip(col, wk_keep) if k])
    return cs.encode()


def filter_bundle(payload, in_window) -> bytes | None:
    """Filter a FtraceEventBundle by per-event keep decision.

    `in_window(raw_ts)->bool` is called with the RAW ftrace timestamp.
    Returns the (possibly re-encoded) bundle payload, or None if no
    events remain. Returns the original bytes verbatim when all events
    are kept (fast path).
    """
    bv = parse_bundle(payload)
    total = 0
    if bv.compact is not None:
        compact = CompactSched.decode(bv.compact)
        sw_ts = compact.switch_timestamps()
        wk_ts = compact.waking_timestamps()
        sw_keep = [in_window(t) for t in sw_ts]
        wk_keep = [in_window(t) for t in wk_ts]
        total += len(sw_ts) + len(wk_ts)
    else:
        compact = None
        sw_keep = wk_keep = []
    ev_keep = []
    for ev in bv.events:
        ts, _pid, _et, _ev = event_meta(ev)
        k = ts is not None and in_window(ts)
        ev_keep.append(k)
        total += 1
    return filter_bundle_mask(payload, compact, ev_keep, sw_keep,
                              wk_keep, total)


def filter_bundle_mask(payload, compact, ev_keep, sw_keep, wk_keep,
                       total=None) -> bytes | None:
    """Mask-variant of filter_bundle: caller supplies per-event keep
    masks (computed once per bundle for many windows)."""
    if total is None:
        total = len(ev_keep) + len(sw_keep) + len(wk_keep)
    kept_n = sum(1 for k in sw_keep if k) + sum(1 for k in wk_keep if k) \
        + sum(1 for k in ev_keep if k)
    if kept_n == 0:
        return None
    if kept_n == total:
        return bytes(payload)

    out = bytearray()
    # Re-encoded bundle drops the boundary-hint fields: their original
    # values refer to the unfiltered stream and TP uses them to close
    # pending slices/counters at bundle end -- wrong after filtering.
    ev_i = 0
    for fno, wt, val, s, e in iter_fields(payload):
        if fno == _B.EVENT and wt == WT_LEN:
            if ev_keep[ev_i]:
                out += bytes(memoryview(payload)[s:e])
            ev_i += 1
        elif fno == _B.COMPACT_SCHED and wt == WT_LEN:
            if compact is not None:
                out += len_field(
                    fno, filter_compact(compact, sw_keep, wk_keep))
        elif fno in (_B.LAST_READ_EVENT_TIMESTAMP,
                     _B.PREVIOUS_BUNDLE_END_TIMESTAMP):
            continue
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)
