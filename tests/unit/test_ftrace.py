import pytest

from pftrim import fields, ftrace
from pftrim.reader import iter_packets
from pftrim.wire import iter_fields, WT_LEN

import builder as sb


def _cs_bytes(cols, intern=None):
    return ftrace.build_compact_sched(cols, intern)


def test_compact_delta_decoding():
    # switch_timestamp[0] is absolute, rest are deltas (acc from 0) --
    # verified vs TP v57 ftrace_tokenizer.cc.
    payload = _cs_bytes({ftrace.SWITCH_TS: [1000, 5, 7, 200],
                         ftrace.SWITCH_NEXT_PID: [1, 2, 3, 4]})
    cs = ftrace.CompactSched.decode(payload)
    assert cs.switch_timestamps() == [1000, 1005, 1012, 1212]
    assert cs.column(ftrace.SWITCH_NEXT_PID) == [1, 2, 3, 4]


def test_compact_roundtrip_synthetic():
    payload = _cs_bytes(
        {ftrace.SWITCH_TS: [1000, 5, 7], ftrace.SWITCH_PREV_STATE: [0, 0, 0],
         ftrace.SWITCH_NEXT_PID: [1, 2, 3], ftrace.SWITCH_NEXT_PRIO: [120] * 3,
         ftrace.SWITCH_NEXT_COMM_INDEX: [0] * 3,
         ftrace.WAKING_TS: [500, 50], ftrace.WAKING_PID: [9, 10]},
        intern=[b"swapper", b"init"])
    cs = ftrace.CompactSched.decode(payload)
    assert cs.encode() == payload
    assert cs.intern_table() == [b"swapper", b"init"]
    assert cs.waking_timestamps() == [500, 550]


def test_compact_waking_accumulates_separately():
    payload = _cs_bytes({ftrace.SWITCH_TS: [10, 10],
                         ftrace.WAKING_TS: [3, 4, 5]})
    cs = ftrace.CompactSched.decode(payload)
    assert cs.switch_timestamps() == [10, 20]
    assert cs.waking_timestamps() == [3, 7, 12]


@pytest.mark.sample
def test_compact_roundtrip_byte_exact_on_sample(sample_trace):
    """decode -> encode must reproduce every bundle's compact_sched bytes
    EXACTLY on the sample trace."""
    n = 0
    for rec in iter_packets(sample_trace):
        if rec.field_no != fields.Trace.PACKET:
            continue
        for fno, wt, val, _s, _e in iter_fields(rec.payload):
            if fno != fields.TracePacket.FTRACE_EVENTS or wt != WT_LEN:
                continue
            bv = ftrace.parse_bundle(val)
            if bv.compact is None:
                continue
            n += 1
            cs = ftrace.CompactSched.decode(bv.compact)
            assert cs.encode() == bytes(bv.compact), \
                f"compact re-encode mismatch at offset {rec.offset}"
    assert n == 1095  # sample: 1095 bundles carry compact_sched


@pytest.mark.sample
def test_compact_event_count_matches_tp(sample_trace, sample_tp):
    from tp import query
    rows = query(sample_tp, "select count(*) as c from sched_slice")
    tp_slices = rows[0]["c"]
    total_switch = 0
    for rec in iter_packets(sample_trace):
        if rec.field_no != fields.Trace.PACKET:
            continue
        for fno, wt, val, _s, _e in iter_fields(rec.payload):
            if fno != fields.TracePacket.FTRACE_EVENTS or wt != WT_LEN:
                continue
            bv = ftrace.parse_bundle(val)
            full = sum(1 for ev in bv.events
                       if ftrace.event_meta(ev)[2] ==
                       fields.FtraceEvent.SCHED_SWITCH)
            if bv.compact is not None:
                cs = ftrace.CompactSched.decode(bv.compact)
                total_switch += cs.switch_event_count()
            total_switch += full
    # TP drops the first compact switch per cpu (8 cpus) -> sched_slice
    # count == our switch count - 8 (sample has no full sched_switch rows
    # dropped otherwise).
    assert total_switch - tp_slices <= 8
    assert total_switch - tp_slices >= 0
