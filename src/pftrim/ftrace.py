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
        tag_val, pos = read_varint(mv, pos)
        fno = tag_val >> 3
        wt = tag_val & 7
        if wt == WT_VARINT:
            v, pos = read_varint(mv, pos)
            if fno == 1:
                ts = v
            elif fno == 2:
                pid = v
        elif wt == WT_LEN:
            ln, pos = read_varint(mv, pos)
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
    """Extract `buf` (bytes) from a PrintFtraceEvent payload."""
    for fno, wt, val, _s, _e in iter_fields(event_value):
        if fno == fields.PrintFtraceEvent.BUF and wt == WT_LEN:
            return bytes(val)
    return None


def iter_compact_event_timestamps(compact: CompactSched):
    """Yield (kind, abs_ts) for each compact event in column order."""
    for ts in compact.switch_timestamps():
        yield COMPACT_SWITCH_NAME, ts
    for ts in compact.waking_timestamps():
        yield COMPACT_WAKING_NAME, ts
