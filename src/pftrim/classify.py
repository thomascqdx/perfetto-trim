"""Packet classification for the cut/split engine (PLAN 3.2).

Classifies a TracePacket payload by its data field(s) so the engine can
decide, per window, whether the packet is emitted verbatim (METADATA /
UNKNOWN), filtered by timestamp (TIMED / MULTI_EVENT), merged
(PROCESS_TREE / SNAPSHOT), or handled for incremental state.

One source of truth for the metadata field set -- scan.py reuses
``METADATA_FIELDS``.
"""

from __future__ import annotations

from . import fields
from .wire import iter_fields

_TP = fields.TracePacket

# ---- classes -------------------------------------------------------------
METADATA = "metadata"        # verbatim to every output
PROCESS_TREE = "process_tree"
SNAPSHOT = "snapshot"        # last pre-window copy, ts rewritten
TIMED = "timed"              # keep iff S <= packet_ts < E
MULTI_EVENT = "multi_event"  # ftrace_events / android_log: filter events
HEAPPROFD = "heapprofd"      # profile_packet groups, whole-group windows
UNKNOWN = "unknown"          # verbatim to every output

# Verbatim-to-all-outputs fields (metadata / bookkeeping / config /
# descriptors / stats). Keep in sync with scan.META_FIELDS via import of
# the same constant -- scan derives its set from this one.
METADATA_FIELDS = frozenset({
    _TP.TRACE_CONFIG, _TP.SYSTEM_INFO, _TP.CLOCK_SNAPSHOT,
    _TP.PACKAGES_LIST, _TP.TRACE_STATS, _TP.FTRACE_STATS,
    _TP.SERVICE_EVENT, _TP.TRACE_UUID, _TP.CPU_INFO,
    _TP.ANDROID_SYSTEM_PROPERTY, _TP.INITIAL_DISPLAY_STATE,
    _TP.TRACK_DESCRIPTOR, _TP.PROCESS_DESCRIPTOR, _TP.THREAD_DESCRIPTOR,
    _TP.EXTENSION_DESCRIPTOR, _TP.TRANSLATION_TABLE, _TP.MODULE_SYMBOLS,
    _TP.DEOBFUSCATION_MAPPING, _TP.TRIGGER, _TP.CHROME_TRIGGER,
    _TP.SYNCHRONIZATION_MARKER, _TP.MACHINE_ID,
    _TP.INODE_FILE_MAP, _TP.INTERNED_DATA, _TP.TRACE_PROVENANCE,
    _TP.TRACE_ATTRIBUTES, _TP.CLONE_SNAPSHOT_TRIGGER,
})

_SNAPSHOT_FIELDS = frozenset({_TP.PROCESS_STATS, _TP.SYS_STATS})
_MULTI_FIELDS = frozenset({_TP.FTRACE_EVENTS, _TP.ANDROID_LOG})

# packet head / state fields kept on stripped copies for
# incremental-state sequences
STATE_HEAD_FIELDS = frozenset({
    _TP.TRUSTED_PACKET_SEQUENCE_ID, _TP.TRUSTED_UID, _TP.TRUSTED_PID,
    _TP.SEQUENCE_FLAGS, _TP.INCREMENTAL_STATE_CLEARED,
    _TP.FIRST_PACKET_ON_SEQUENCE, _TP.PREVIOUS_PACKET_DROPPED,
    _TP.INTERNED_DATA, _TP.TRACE_PACKET_DEFAULTS, _TP.TIMESTAMP_CLOCK_ID,
    _TP.CLOCK_SNAPSHOT,
})

# fields that mark a sequence as carrying incremental state
_INCR_MARKERS = frozenset({
    _TP.INTERNED_DATA, _TP.INCREMENTAL_STATE_CLEARED,
    _TP.TRACE_PACKET_DEFAULTS,
})


def data_fields(payload):
    """Yield (field_no, wire_type, value) of DATA fields only (head and
    bookkeeping fields skipped)."""
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno in _HEAD_FIELDS:
            continue
        yield fno, wt, val


_HEAD_FIELDS = frozenset({
    _TP.TIMESTAMP, _TP.TIMESTAMP_CLOCK_ID, _TP.TRUSTED_UID,
    _TP.TRUSTED_PACKET_SEQUENCE_ID, _TP.TRUSTED_PID, _TP.SEQUENCE_FLAGS,
    _TP.INCREMENTAL_STATE_CLEARED, _TP.PREVIOUS_PACKET_DROPPED,
    _TP.FIRST_PACKET_ON_SEQUENCE, _TP.TRACE_UUID, _TP.MACHINE_ID,
})


def classify_packet(payload) -> tuple[str, int | None]:
    """(class, data_field_no). Packets with no data field -> METADATA.

    data_field_no is the field that determined the class (e.g.
    FTRACE_EVENTS for [ftrace_events, interned_data] packets -- a
    trailing metadata field does not mask the real data field). Only
    for METADATA packets does it fall back to the last data field (the
    engine checks SERVICE_EVENT on those)."""
    last_fno = None
    cls_fno = None
    result = METADATA
    for fno, wt, _v in data_fields(payload):
        last_fno = fno
        if fno in METADATA_FIELDS:
            continue          # metadata can coexist with another class
        if fno == _TP.PROCESS_TREE:
            result = PROCESS_TREE
            cls_fno = fno
        elif fno in _SNAPSHOT_FIELDS:
            result = SNAPSHOT
            cls_fno = fno
        elif fno in _MULTI_FIELDS:
            result = MULTI_EVENT
            cls_fno = fno
        elif fno == _TP.PROFILE_PACKET:
            result = HEAPPROFD
            cls_fno = fno
        elif fno not in fields.TRACE_PACKET_FIELD_NAMES:
            result = UNKNOWN
            cls_fno = fno
        elif result == METADATA:
            # TIMED never overrides an earlier class field.
            result = TIMED
            cls_fno = fno
    # A packet with only metadata fields -> METADATA; the last non-meta
    # class field wins otherwise.
    return result, (cls_fno if result != METADATA else last_fno)


def marks_incremental(payload) -> bool:
    """True if this packet marks its sequence as carrying incremental
    state (interned_data / cleared flag / packet defaults)."""
    for fno, wt, _v, _s, _e in iter_fields(payload):
        if fno in _INCR_MARKERS:
            return True
    return False


def strip_to_state(payload) -> bytes:
    """Keep only head/state fields (no data, no timestamp) -- used for
    out-of-window packets on incremental-state sequences."""
    out = bytearray()
    for fno, wt, _v, s, e in iter_fields(payload):
        if fno == _TP.TIMESTAMP:
            continue
        if fno in STATE_HEAD_FIELDS:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out)
