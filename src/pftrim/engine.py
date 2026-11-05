"""Cut/split engine: one streaming pass, N windows (PLAN 3.2/3.3/3.4).

    run(path, windows, out_dir, options, progress) -> RunReport

A Window is a half-open [start_ns, end_ns) in BOOTTIME ns. Each window
owns a TraceWriter; every packet is classified (classify.py) and
dispatched to the windows it is relevant to:

  METADATA / UNKNOWN  -> verbatim to every output
  PROCESS_TREE        -> in-window verbatim + one synthesized merged
                         packet (latest per-pid/per-tid pre-window state)
  SNAPSHOT counters   -> in-window verbatim + last pre-window copy with
                         packet ts rewritten to window start
  TIMED               -> keep iff S <= packet_ts < E
  MULTI_EVENT         -> ftrace bundles filtered per event; android_log
                         LogEvents filtered; stats field kept
  HEAPPROFD           -> profile_packet groups assigned whole to the
                         window containing the group's first packet ts

Incremental-state sequences (interned_data / cleared flag / packet
defaults seen on the fly): out-of-window packets are emitted as stripped
head+state copies so interning still resolves.

ftrace carry-in state at S (per cpu, order-independent -- greatest ts <
S wins): last sched_switch (compact or full), cpu_frequency(-limits),
cpu_idle, gpu_frequency. Emitted as one synthetic carry-in bundle per
cpu per window once the cpu's stream is provably past S + reorder_window
(or EOF) -- appended in stream order (file-position independence
verified against TP v57: results identical whether carry-in packets are
placed first or at their finalization point).
"""

from __future__ import annotations

import bisect
import os
from dataclasses import dataclass, field

from . import Cancelled, classify, fields, ftrace, state
from .clock import ClockConverter
from .reader import iter_packets
from .wire import (WT_LEN, WT_VARINT, iter_fields, len_field, read_varint,
                   varint_field)
from .writer import TraceWriter

_TP = fields.TracePacket

# All tracker items go through the ReorderBuffer (global ts order) --
# verified: the utid-incarnation stack model in ts order reproduces
# TP's open slices on the sample exactly (scripts/diag_thread_stacks).


@dataclass
class Window:
    start_ns: int
    end_ns: int


@dataclass
class Options:
    keep_original_ts: bool = False
    reorder_window_ns: int = 2_000_000_000
    # how long past E the tracker keeps observing to fill real_end_ns in
    # boundary.csv for slices open at E (trace-time ns)
    boundary_lookahead_ns: int = 10_000_000_000


@dataclass
class OutputReport:
    path: str = ""
    start_ns: int = 0
    end_ns: int = 0
    bytes: int = 0
    packets: int = 0
    ftrace_events_kept: int = 0
    carryin_events: int = 0
    class_counts: dict = field(default_factory=dict)


@dataclass
class RunReport:
    input: str = ""
    outputs: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    bundles_decoded: int = 0   # for tail-mode verification


class _WinState:
    """Per-window mutable state."""

    __slots__ = (
        "w", "writer", "rep", "seq_incr_pending",
        "pt_procs", "pt_threads", "pt_ts", "pt_head", "ps_procs",
        "snapshots", "state_final_emitted", "heapprofd", "emitted_cpus",
        "s_done", "e_done", "done", "boundary_rows", "end_rows",
        "carryin_count", "closer_count",
    )

    def __init__(self, w: Window, writer, rep: OutputReport):
        self.w = w
        self.writer = writer
        self.rep = rep
        self.seq_incr_pending = []
        # process_tree merge state: pid/tid -> raw submessage bytes
        self.pt_procs: dict[int, bytes] = {}
        self.pt_threads: dict[int, bytes] = {}
        self.ps_procs: dict[int, bytes] = {}   # process_stats merge
        self.pt_ts = None          # latest collection_end_timestamp
        self.pt_head = None        # (seq, uid, pid) from a pt packet
        # snapshot carry-in: field_no -> (ts, packet_payload_bytes)
        self.snapshots: dict[int, tuple] = {}
        self.state_final_emitted = False
        # heapprofd group accumulation per seq: [packet payloads]
        self.heapprofd: dict = {}
        self.emitted_cpus: set = set()  # cpus with a bundle already emitted
        # boundary state (M4)
        self.s_done = False        # S-snapshot emitted
        self.e_done = False        # E-snapshot (closers) emitted
        self.done = False          # E + lookahead passed -> tail ok
        self.boundary_rows: list = []   # boundary.csv rows (mutable)
        self.end_rows: dict = {}        # (kind,key) -> [row idx] to fill
        self.carryin_count = 0
        self.closer_count = 0

    # ------------------------------------------------------------- emit
    def emit_raw(self, payload: bytes, cls_name: str):
        self.writer.write_packet(payload)
        r = self.rep
        r.packets += 1
        r.bytes += _top_len(payload)
        r.class_counts[cls_name] = r.class_counts.get(cls_name, 0) + 1


def _top_len(payload) -> int:
    return len(payload) + 8  # approx incl. tag+len


# ---------------------------------------------------------------- state
def _packet_head(payload):
    """(ts_raw, ts_clk, seq, uid, pid, seq_flags)."""
    ts = ts_clk = seq = uid = pid = flags = None
    for fno, wt, val, _s, _e in iter_fields(payload):
        if wt != WT_VARINT:
            continue
        if fno == _TP.TIMESTAMP:
            ts = val
        elif fno == _TP.TIMESTAMP_CLOCK_ID:
            ts_clk = val
        elif fno == _TP.TRUSTED_PACKET_SEQUENCE_ID:
            seq = val
        elif fno == _TP.TRUSTED_UID:
            uid = val
        elif fno == _TP.TRUSTED_PID:
            pid = val
        elif fno == _TP.SEQUENCE_FLAGS:
            flags = val
    return ts, ts_clk, seq, uid, pid, flags


def _rewrite_packet_ts(payload, ts) -> bytes:
    out = bytearray()
    wrote = False
    for fno, wt, _v, s, e in iter_fields(payload):
        if fno == _TP.TIMESTAMP and wt == WT_VARINT:
            out += varint_field(fno, ts)
            wrote = True
        else:
            out += bytes(memoryview(payload)[s:e])
    return bytes(out) if wrote else bytes(out) + varint_field(
        _TP.TIMESTAMP, ts)


def _inject_trusted(payload, seq, uid, pid) -> bytes:
    """Append outer trusted_* fields to an expanded inner packet that
    lacks them."""
    have_seq = have_uid = have_pid = False
    for fno, wt, _v, _s, _e in iter_fields(payload):
        if wt != WT_VARINT:
            continue
        if fno == _TP.TRUSTED_PACKET_SEQUENCE_ID:
            have_seq = True
        elif fno == _TP.TRUSTED_UID:
            have_uid = True
        elif fno == _TP.TRUSTED_PID:
            have_pid = True
    out = bytearray(bytes(payload))
    if seq is not None and not have_seq:
        out += varint_field(_TP.TRUSTED_PACKET_SEQUENCE_ID, seq)
    if uid is not None and not have_uid:
        out += varint_field(_TP.TRUSTED_UID, uid)
    if pid is not None and not have_pid:
        out += varint_field(_TP.TRUSTED_PID, pid)
    return bytes(out)


# -------------------------------------------------------- process_tree
def _pt_collect(win: _WinState, payload, pt_ts, head):
    """Merge Process/Thread submessages into per-window state."""
    if pt_ts is not None and (win.pt_ts is None or pt_ts > win.pt_ts):
        win.pt_ts = pt_ts
    if win.pt_head is None and head != (None, None, None):
        win.pt_head = head
    for fno, wt, val, _s, _e in iter_fields(payload):
        if wt != WT_LEN or fno not in (
                fields.ProcessTree.PROCESSES, fields.ProcessTree.THREADS):
            continue
        key = None
        for ifno, iwt, ival, _is, _ie in iter_fields(val):
            if iwt == WT_VARINT and ifno == 1:  # pid / tid
                key = ival
                break
        if key is None:
            continue
        if fno == fields.ProcessTree.PROCESSES:
            win.pt_procs[key] = bytes(val)
        else:
            win.pt_threads[key] = bytes(val)


def _pt_emit(win: _WinState, ts):
    """Synthesized merged process_tree packet payload."""
    out = bytearray()
    for p in win.pt_procs.values():
        out += len_field(fields.ProcessTree.PROCESSES, p)
    for t in win.pt_threads.values():
        out += len_field(fields.ProcessTree.THREADS, t)
    out += varint_field(fields.ProcessTree.COLLECTION_END_TIMESTAMP, ts)
    pkt = len_field(_TP.PROCESS_TREE, bytes(out))
    seq, uid, pid = win.pt_head or (None, None, None)
    head = bytearray()
    if seq is not None:
        head += varint_field(_TP.TRUSTED_PACKET_SEQUENCE_ID, seq)
    if uid is not None:
        head += varint_field(_TP.TRUSTED_UID, uid)
    if pid is not None:
        head += varint_field(_TP.TRUSTED_PID, pid)
    return bytes(head) + pkt


# ------------------------------------------------------------- ftrace
def _sched_switch_event(ts, pid, prev_comm, prev_pid, prev_prio,
                        prev_state, next_comm, next_pid, next_prio) -> bytes:
    """Full SchedSwitchFtraceEvent inside an FtraceEvent wrapper."""
    SS = fields.SchedSwitchFtraceEvent
    inner = (len_field(SS.PREV_COMM, prev_comm) +
             varint_field(SS.PREV_PID, prev_pid) +
             varint_field(SS.PREV_PRIO, prev_prio) +
             varint_field(SS.PREV_STATE, prev_state) +
             len_field(SS.NEXT_COMM, next_comm) +
             varint_field(SS.NEXT_PID, next_pid) +
             varint_field(SS.NEXT_PRIO, next_prio))
    return (varint_field(fields.FtraceEvent.TIMESTAMP, ts) +
            varint_field(fields.FtraceEvent.PID, next_pid) +
            len_field(fields.FtraceEvent.SCHED_SWITCH, inner))


def _print_event(ts, pid, buf: bytes) -> bytes:
    return (varint_field(fields.FtraceEvent.TIMESTAMP, ts) +
            varint_field(fields.FtraceEvent.PID, pid) +
            len_field(fields.FtraceEvent.PRINT,
                      len_field(fields.PrintFtraceEvent.BUF, buf)))


def _carryin_bundle_from_snap(snap_cpu, cpu, ts_out) -> bytes | None:
    """Build the per-cpu carry-in bundle from a tracker snapshot's cpu
    entry {switch:(ts,kind,info,seq,uid)}. Counters are emitted
    separately (single ordered bundle) -- see _snapshot_start."""
    events = []
    n = 0
    compact = None
    sw = snap_cpu.get("switch")
    if sw is not None:
        _ts, kind, info, _seq, _uid = sw
        if kind == "skip":
            # cpu's first compact switch: TP skips it identically, so
            # replay compact at S-1 (sorts before real events at S; a
            # skipped switch produces no rows -> bounds unaffected).
            prev_state, next_pid, next_prio, comm = info
            compact = ftrace.build_carryin_compact_sched(
                ts_out - 1, prev_state, next_pid, next_prio, comm)
            n += 1
        elif kind == "compact":
            _prev_state, next_pid, next_prio, comm = info
            # full sched_switch: compact first-switch-per-cpu is skipped
            # by TP and would never produce the [S,T) slice; prev=swapper
            # because the slice attributes the NEXT task anyway.
            events.append(_sched_switch_event(
                ts_out, next_pid, b"swapper", 0, 120, 0,
                comm, next_pid, next_prio))
            n += 1
        else:  # 'full'
            events.append(ftrace.rewrite_event_ts(info, ts_out))
            n += 1
    if n == 0:
        return None
    return ftrace.build_bundle(cpu, events, compact, prev_end_ts=ts_out)


def _carryin_packet(bundle_payload, seq, uid) -> bytes:
    head = bytearray()
    if seq is not None:
        head += varint_field(_TP.TRUSTED_PACKET_SEQUENCE_ID, seq)
    if uid is not None:
        head += varint_field(_TP.TRUSTED_UID, uid)
    return bytes(head) + len_field(_TP.FTRACE_EVENTS, bundle_payload)


# ------------------------------------------------- boundary snapshots
def _snapshot_start(win: _WinState, tracker, opts: Options, cross=None):
    """At the first released ts >= S: emit this window's carry-in."""
    if win.s_done:
        return
    win.s_done = True
    snap = tracker.snapshot()
    S = win.w.start_ns
    keep = opts.keep_original_ts
    # per-cpu sched/counter carry-in bundles
    cpu_evs: dict[int, list] = {}
    cpu_sequid: dict[int, tuple] = {}
    for cpu, (ts, kind, info, seq, uid) in snap["cpu_switch"].items():
        entry = {"switch": (ts, kind, info, seq, uid)}
        ts_out = ts if keep else S
        payload = _carryin_bundle_from_snap(entry, cpu, ts_out)
        if payload is not None:
            win.emit_raw(_carryin_packet(payload, seq, uid), "carryin")
            win.carryin_count += 1
            win.rep.carryin_events += 1
    # counters: ONE bundle across all cpus, sorted by original ts --
    # TP's "value in effect at S" is the last row by ts per track name,
    # and several tracks share names (cpufreq per cpu, Heap size per
    # process): emission order decides equal-ts ties, so it must match
    # the original's ts order across all tracks. Dedupe by counter key:
    # the same cpu_id's events can arrive on multiple bundle cpus --
    # TP's track is keyed by the event's cpu_id, so only the latest
    # entry per key should be replayed.
    ctr_last = {}
    for ctrs in snap["cpu_counters"].values():
        for key, (ts, ev, _seq, _uid) in ctrs.items():
            if key not in ctr_last or ts > ctr_last[key][0]:
                ctr_last[key] = (ts, ev)
    ctr_evs = sorted(ctr_last.values(), key=lambda x: x[0])
    if ctr_evs:
        win.carryin_count += len(ctr_evs)
        win.rep.carryin_events += len(ctr_evs)
        evs = [ftrace.rewrite_event_ts(ev, ts if keep else S)
               for ts, ev in ctr_evs]
        win.emit_raw(_carryin_packet(
            ftrace.build_bundle(0, evs), *(
                _sequid_for(win, 0, snap) if snap else (0, 0))),
            "carryin")
    # ---- unified slice-stack carry-in (TP thread_execution model) --
    # First: identity events. TP applies process_tree at file position
    # (too late -- in-window ftrace events may already be parsed), but
    # ftrace events sort by ts: emitting one `E|<tgid>` per alive
    # incarnation (oldest->newest per tid) at S-2 re-creates the
    # original's incarnation ordering before any in-window event.
    # E resolves via UpdateThread(tid,tgid) then End-noops on the
    # empty stack, so it carries no rows.
    id_evs = []
    # (a) tids with pending stacks: pin each utid's process association
    # before its replayed events land -- a replayed tx/rcv would
    # otherwise create an upid-None utid which in-window UpdateThread
    # events can claim/reorder differently than in the original.
    # (b) tids with >=2 alive incarnations: emit oldest->newest pairs
    # so goc()/bare-E resolution picks the same utid as the original.
    id_pairs = {}
    for u, stack in tracker.track_stack.items():
        if not stack:
            continue
        up = tracker.thread[u]["upid"]
        if up is not None:
            id_pairs.setdefault(tracker.thread[u]["tid"], []).append(
                tracker.procs[up]["pid"])
    for tid, ulist in tracker.tids.items():
        pairs = [u for u in ulist if tracker._alive(u)]
        if len(pairs) >= 2:
            # incarnation order matters: emit pairs oldest->newest
            seq = [tracker.procs[tracker.thread[u]["upid"]]["pid"]
                   for u in pairs
                   if tracker.thread[u]["upid"] is not None]
            id_pairs[tid] = seq
    plan = tracker.replay_plan(S)
    min_orig = min(
        [t for t, _e, _c in plan["groupA"] + plan["groupB"]] +
        [v[0] for v in tracker.async_open.values()] +
        [e[0] for lst in tracker.named_open.values() for e in lst],
        default=S)
    # base = earliest replay ts: under keep_ts events keep their
    # original (<S) timestamps, so identity/groupA must go before
    # min_orig, not before S.
    base = min_orig if keep else S
    for tid, pids in id_pairs.items():
        seen = set()
        for pid in pids:
            if pid in seen:
                continue
            seen.add(pid)
            id_evs.append(_print_event(base - 3, tid, b"E|%d" % pid))
    if id_evs:
        win.emit_raw(_carryin_packet(
            ftrace.build_bundle(0, id_evs), *(
                _sequid_for(win, 0, snap) if snap else (0, 0))),
            "carryin")
    # group A: outstanding is_reply tx at base-2; emitted FIRST (after
    # identity) so the End no-ops on empty stacks and only the reply
    # id registers.
    for ts, ev, cpu in plan["groupA"]:
        win.emit_raw(_carryin_packet(
            ftrace.build_bundle(
                cpu, [ftrace.rewrite_event_ts(ev, base - 2)]), None,
            None), "carryin")
        win.carryin_count += 1
        win.rep.carryin_events += 1
    # group B: opener events in global orig-ts order -- emitted in ONE
    # bundle so the equal-ts (S) ordering is by file position (per-cpu
    # partitioning would scramble the nesting order). cpu field is
    # cosmetic for atrace/binder events.
    gb_evs = []
    for ts, ev, cpu in plan["groupB"]:
        ts_out = ts if keep else S
        gb_evs.append(ftrace.rewrite_event_ts(ev, ts_out))
        win.carryin_count += 1
        win.rep.carryin_events += 1
    if gb_evs:
        gcpu = plan["groupB"][0][2] if plan["groupB"] else 0
        seq, uid = _sequid_for(win, gcpu, snap)
        win.emit_raw(_carryin_packet(
            ftrace.build_bundle(gcpu, gb_evs), seq, uid), "carryin")
    # boundary rows for pending stack entries (start side) -- stacks
    # keyed by incarnation (utid); entries carry their tid.
    for u, stack in tracker.track_stack.items():
        for e in stack:
            k = e[0]
            if k == "b":
                row = ["start", "sync", e[2], e[6], _name_b(e[1]),
                       e[3], "", ""]
            elif k == "btx":
                row = ["start", "binder", 0, e[5], "binder transaction",
                       e[2], "", ""]
            elif k == "brx":
                row = ["start", "binder", 0, e[5], "binder reply",
                       e[2], "", ""]
            elif k == "blw":
                row = ["start", "binder", 0, e[4], "binder lock waiting",
                       e[1], "", ""]
            elif k == "blh":
                row = ["start", "binder", 0, e[4], "binder lock held",
                       e[1], "", ""]
            else:
                continue
            win.boundary_rows.append(row)
            # keyed by slice identity so a pop fills start+end rows of
            # the same slice instance
            win.end_rows.setdefault(_entry_key(e), []).append(
                len(win.boundary_rows) - 1)
    for (tgid, name, cookie), (ts, ev, cpu, tid) \
            in tracker.async_open.items():
        ts_out = ts if keep else S
        cpu_evs.setdefault(cpu, []).append(
            ftrace.rewrite_event_ts(ev, ts_out))
        win.carryin_count += 1
        win.rep.carryin_events += 1
        win.boundary_rows.append(
            ["start", "async", tgid, tid, _name_b(name), ts, "", ""])
        win.end_rows.setdefault(("async", tgid, name, cookie), []).append(
            len(win.boundary_rows) - 1)
    for (tgid, track, cookie), lst in tracker.named_open.items():
        for ts, ev, cpu, tid, name in lst:
            ts_out = ts if keep else S
            cpu_evs.setdefault(cpu, []).append(
                ftrace.rewrite_event_ts(ev, ts_out))
            win.carryin_count += 1
            win.rep.carryin_events += 1
            win.boundary_rows.append(
                ["start", "named", tgid, tid, _name_b(name), ts, "", ""])
            win.end_rows.setdefault(
                ("named", tgid, track, cookie), []).append(
                len(win.boundary_rows) - 1)
    # atrace C counters: ONE bundle sorted by orig ts -- counter
    # tracks share names across processes; last-in-file wins at equal
    # ts so emission order must match the original's ts order.
    c_evs = sorted(
        ((ts, ev) for (tgid, name), (ts, val, ev, cpu)
         in snap["ctr"].items()), key=lambda x: x[0])
    if c_evs:
        evs = [ftrace.rewrite_event_ts(ev, ts if keep else S)
               for ts, ev in c_evs]
        seq, uid = _sequid_for(win, 0, snap)
        win.emit_raw(_carryin_packet(
            ftrace.build_bundle(0, evs), seq, uid), "carryin")
        win.carryin_count += len(c_evs)
        win.rep.carryin_events += len(c_evs)
    for cookie, (ts, pkt) in snap["frames"].items():
        ts_out = ts if keep else S
        win.emit_raw(_rewrite_packet_ts(pkt, ts_out), "carryin")
        win.carryin_count += 1
        win.rep.carryin_events += 1
        win.boundary_rows.append(
            ["start", "frame", 0, 0, "frame", ts, "", ""])
    # emit grouped atrace/binder carry-in bundles (per cpu, orig order)
    for cpu, evs in cpu_evs.items():
        seq, uid = _sequid_for(win, cpu, snap)
        payload = ftrace.build_bundle(cpu, evs)
        win.emit_raw(_carryin_packet(payload, seq, uid), "carryin")
    if plan["case_b"]:
        win.rep.class_counts["case_b_skipped"] = \
            win.rep.class_counts.get("case_b_skipped", 0) + plan["case_b"]
    if cross is not None and win.end_rows:
        cross.active.add(win)


def _snapshot_end(win: _WinState, tracker, opts: Options, cross=None):
    """At the first released ts >= E: emit closers for open slices."""
    if win.e_done:
        return
    win.e_done = True
    snap = tracker.snapshot_open()
    E = win.w.end_ns
    cpu_evs: dict[int, list] = {}
    # one E|<proc_pid> per pending entry on every incarnation's stack
    # (atrace AND binder): N pops close the whole stack in LIFO order.
    # The tgid field is required so TP's UpdateThread resolves the E to
    # the RIGHT incarnation on multi-utid tids (bare E -> GetThreadOrNull
    # -> newest alive, which would be the wrong stack).
    for u, stack in snap["track_stack"].items():
        upid = tracker.thread[u]["upid"]
        tpid = tracker.procs[upid]["pid"] if upid is not None else 0
        for e in stack:
            cpu = e[5] if e[0] == "b" else (e[4] if e[0] in
                                          ("btx", "brx") else e[3])
            tid = e[-1]
            cpu_evs.setdefault(cpu, []).append(
                _print_event(E - 1, tid, b"E|%d" % tpid))
            win.closer_count += 1
            if e[0] == "b":
                row = ["end", "sync", e[2], e[6], _name_b(e[1]), e[3],
                       "", ""]
            else:
                nm = {"btx": "binder transaction",
                      "brx": "binder reply",
                      "blw": "binder lock waiting",
                      "blh": "binder lock held"}[e[0]]
                row = ["end", "binder", 0, tid, nm,
                       e[2] if e[0] in ("btx", "brx") else e[1], "", ""]
            win.boundary_rows.append(row)
            win.end_rows.setdefault(_entry_key(e), []).append(
                len(win.boundary_rows) - 1)
    for (tgid, name, cookie), (ts, ev, cpu, tid) \
            in snap["async_open"].items():
        buf = b"F|%d|%s|%d" % (tgid, name, cookie)
        cpu_evs.setdefault(cpu, []).append(
            _print_event(E - 1, tgid, buf))
        win.closer_count += 1
        win.boundary_rows.append(
            ["end", "async", tgid, tid, _name_b(name), ts, "", ""])
        win.end_rows.setdefault(("async", tgid, name, cookie), []).append(
            len(win.boundary_rows) - 1)
    for (tgid, track, cookie), lst in snap["named_open"].items():
        for ts, ev, cpu, tid, name in lst:
            buf = b"H|%d|%s|%d" % (tgid, track, cookie)
            cpu_evs.setdefault(cpu, []).append(
                _print_event(E - 1, tid, buf))
            win.closer_count += 1
            win.boundary_rows.append(
                ["end", "named", tgid, tid, _name_b(name), ts, "", ""])
            win.end_rows.setdefault(
                ("named", tgid, track, cookie), []).append(
                len(win.boundary_rows) - 1)
    for cpu, evs in cpu_evs.items():
        win.emit_raw(
            _carryin_packet(ftrace.build_bundle(cpu, evs), None, None),
            "closer")
    if cross is not None and win.end_rows:
        cross.active.add(win)


def _frame_items(packet_payload, packet_ts):
    """FrameTimelineEvent packet -> tracker items ("frame", cookie,
    packet_bytes, is_start) per start/end sub-message with a cookie."""
    FT = fields.FrameTimelineEvent
    out = []
    for fno, wt, val, _s, _e in iter_fields(packet_payload):
        if fno != _TP.FRAME_TIMELINE_EVENT or wt != WT_LEN:
            continue
        for sfno, swt, sval, _ss, _se in iter_fields(val):
            is_start = sfno in (FT.EXPECTED_DISPLAY_FRAME_START,
                                FT.ACTUAL_DISPLAY_FRAME_START,
                                FT.EXPECTED_SURFACE_FRAME_START,
                                FT.ACTUAL_SURFACE_FRAME_START)
            is_end = sfno == FT.FRAME_END
            if swt != WT_LEN or not (is_start or is_end):
                continue
            cookie = None
            for cfno, cwt, cval, _cs, _ce in iter_fields(sval):
                if cfno == 1 and cwt == WT_VARINT:  # COOKIE=1 in all
                    cookie = cval                    # frame sub-msgs
            if cookie is not None:
                out.append((packet_ts, ("frame", cookie,
                                        bytes(packet_payload), is_start)))
    return out


def _name_b(name) -> str:
    try:
        return name.decode("utf-8", "replace")
    except AttributeError:
        return str(name)


def _sequid_for(win, cpu, snap):
    sw = snap["cpu_switch"].get(cpu)
    if sw is not None:
        return sw[3], sw[4]
    return None, None


def _write_boundary_csv(win: _WinState):
    if not win.boundary_rows:
        return
    import csv
    path = win.rep.path[:-len(".perfetto-trace")] + ".boundary.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["side", "kind", "tgid", "tid", "name",
                     "real_start_ns", "real_end_ns", "real_dur_ns"])
        wr.writerows(win.boundary_rows)


def _finalize_state(win: _WinState, opts: Options, tracker=None):
    """Emit synthesized process_tree + snapshot carry-ins. Idempotent."""
    if win.state_final_emitted:
        return
    win.state_final_emitted = True
    S = win.w.start_ns
    ts_out = win.pt_ts if opts.keep_original_ts and win.pt_ts else S
    if win.pt_procs or win.pt_threads:
        win.emit_raw(_pt_emit(win, ts_out), "process_tree_synth")
    for fno, (ts, payload) in win.snapshots.items():
        ts_use = ts if opts.keep_original_ts else S
        win.emit_raw(_rewrite_packet_ts(payload, ts_use), "snapshot")
    if win.ps_procs:
        body = bytearray()
        for sub in win.ps_procs.values():
            body += len_field(fields.ProcessStats.PROCESSES, sub)
        body += varint_field(
            fields.ProcessStats.COLLECTION_END_TIMESTAMP, ts_out)
        win.emit_raw(
            varint_field(_TP.TIMESTAMP, ts_out) +
            len_field(_TP.PROCESS_STATS, bytes(body)), "snapshot")


# ------------------------------------------------------------ engine
def run(path, windows: list[Window], out_dir: str,
        options: Options | None = None, progress=None,
        cancel=None) -> RunReport:
    opts = options or Options()
    rep = RunReport(input=os.path.abspath(path))
    wins: list[_WinState] = []
    conv = ClockConverter()
    incr_seqs: set[int] = set()      # sequences with incremental state

    os.makedirs(out_dir, exist_ok=True)
    stem = _stem(path)
    for w in sorted(windows, key=lambda x: x.start_ns):
        name = f"{stem}__{w.start_ns}-{w.end_ns}.perfetto-trace"
        outp = os.path.join(out_dir, name)
        wr = TraceWriter(outp)
        wr.__enter__()  # open now; closed/renamed in the finally-block
        wins.append(_WinState(w, wr,
                              OutputReport(path=os.path.abspath(outp),
                                           start_ns=w.start_ns,
                                           end_ns=w.end_ns)))

    tracker = state.BoundaryTracker(opts.reorder_window_ns)
    tail_mode = False
    Ss = [w.w.start_ns for w in wins]

    class _Cross:
        """Sorted pointers over windows for O(1) boundary releases."""
        __slots__ = ("s_order", "s_i", "e_i", "d_i", "e_order", "active",
                     "ndone")

        def __init__(self, wins):
            self.s_order = wins          # already sorted by S
            self.s_i = 0
            self.e_order = sorted(wins, key=lambda w: w.w.end_ns)
            self.e_i = 0
            self.d_i = 0
            self.active: set = set()     # wins with pending end_rows
            self.ndone = 0

    cross = _Cross(wins)
    cross.s_order = wins
    try:
        for rec in iter_packets(path, expand_compressed=True,
                                progress=progress, cancel=cancel):
            if rec.field_no != fields.Trace.PACKET:
                for ws in wins:
                    ws.writer.write_raw(bytes(rec.raw))
                continue
            payload = _inject_trusted(
                rec.payload, rec.trusted_packet_sequence_id,
                rec.trusted_uid, rec.trusted_pid) \
                if rec.compressed else rec.payload
            if tail_mode:
                # tail mode: top-level fields only, no decoding
                cls, _ = classify.classify_packet(payload)
                if cls in (classify.METADATA, classify.UNKNOWN):
                    for ws in wins:
                        ws.emit_raw(bytes(payload), "metadata")
                continue
            ts_raw, ts_clk, seq, uid, pid, flags = _packet_head(payload)
            conv.update(payload)  # register clock_snapshot packets
            if seq is not None and (
                    classify.marks_incremental(payload) or
                    (flags or 0) & fields.SEQ_NEEDS_INCREMENTAL_STATE):
                incr_seqs.add(seq)
            packet_ts = None
            if ts_raw is not None:
                clock_id = ts_clk if ts_clk is not None else \
                    conv.sequence_clock(seq)
                packet_ts = conv.to_boottime(clock_id, ts_raw)

            cls, data_fno = classify.classify_packet(payload)
            if cls == classify.MULTI_EVENT and \
                    data_fno == _TP.FTRACE_EVENTS:
                parsed = _parse_ftrace(payload, conv, seq, uid, rep)
                for ts, item in parsed["items"]:
                    for rts, ritem in tracker.push(ts, (ts, item)):
                        _cross_release(rts, ritem, tracker, cross,
                                       opts)
                if parsed["lo"] is not None:
                    for ws in _overlap(wins, Ss, parsed["lo"],
                                       parsed["hi"]):
                        _emit_ftrace(ws, parsed, payload, opts,
                                     incr_seqs, seq)
            elif cls == classify.MULTI_EVENT:  # android_log
                pl = _parse_log(payload, conv)
                for ws in wins:
                    _emit_log(ws, payload, pl, incr_seqs, seq)
            else:
                if cls == classify.PROCESS_TREE:
                    # process_tree applies at packet position; anchor to
                    # last ftrace ts so it interleaves correctly in the
                    # reordered stream (diag-validated semantics).
                    anchor = tracker.last_released or 0
                    for tid, tgid in _pt_pairs(payload):
                        for rts, ritem in tracker.push(
                                anchor, (anchor, ("pt", tid, tgid))):
                            _cross_release(rts, ritem, tracker, cross,
                                           opts)
                if data_fno == _TP.FRAME_TIMELINE_EVENT and \
                        packet_ts is not None:
                    for ts, item in _frame_items(payload, packet_ts):
                        for rts, ritem in tracker.push(ts, (ts, item)):
                            _cross_release(rts, ritem, tracker, cross,
                                           opts)
                rng = _range(cls, data_fno, payload, packet_ts)
                for ws in _overlap(wins, Ss, *rng):
                    _dispatch(ws, rec, payload, cls, data_fno,
                              packet_ts, seq, uid, pid, conv, opts,
                              incr_seqs)
            tail_mode = cross.ndone == len(wins) and \
                not any(w.heapprofd for w in wins)
        # drain tracker -> final releases -> remaining snapshots/closers
        for rts, ritem in tracker.drain():
            _cross_release(rts, ritem, tracker, cross, opts)
        for ws in wins:
            _snapshot_start(ws, tracker, opts)  # if stream ended pre-S
            _snapshot_end(ws, tracker, opts)
            _flush_heapprofd(ws, rep)
            _finalize_state(ws, opts, tracker)
            _write_boundary_csv(ws)
    except Cancelled:
        for ws in wins:
            ws.writer.abort()
        raise
    except BaseException:
        for ws in wins:
            ws.writer.abort()
        raise
    for ws in wins:
        ws.writer.__exit__(None, None, None)  # close + rename
        ws.rep.bytes = os.path.getsize(ws.rep.path)
        rep.outputs.append(ws.rep)
    if tracker.late_events:
        rep.warnings.append(
            f"reorder_late_events: {tracker.late_events}")
    if tracker.frame_cap_warn:
        rep.warnings.append("frame timeline pending 超过 10000，"
                            "最旧的被丢弃")
    rep.limitations = [
        "thread state of non-running threads at window start is not "
        "replayed (no sleep-transition fabrication)",
        "oom_score_adj counters (lmk B-tags / process_tree fields) "
        "are not replayed",
        "--keep-original-ts: a few binder reply slices near the "
        "window may remain unclosed",
    ]
    return rep


def _stem(path) -> str:
    base = os.path.basename(path)
    for suf in (".perfetto-trace", ".pftrace", ".trace", ".gz"):
        if base.endswith(suf):
            base = base[:-len(suf)]
    return base


# --------------------------------------------------------- dispatch
def _dispatch(win: _WinState, rec, payload, cls, data_fno, packet_ts,
              seq, uid, pid, conv, opts, incr_seqs):
    S, E = win.w.start_ns, win.w.end_ns
    if cls == classify.METADATA or cls == classify.UNKNOWN:
        win.emit_raw(bytes(payload), "metadata" if cls ==
                   classify.METADATA else "unknown")
        return
    if cls == classify.PROCESS_TREE:
        pt_ts = None
        for fno, wt, val, _s, _e in iter_fields(payload):
            if fno == _TP.PROCESS_TREE and wt == WT_LEN:
                for ifno, iwt, ival, _is, _ie in iter_fields(val):
                    if ifno == fields.ProcessTree.COLLECTION_END_TIMESTAMP \
                            and iwt == WT_VARINT:
                        pt_ts = ival
        _pt_collect(win, _pt_payload(payload), pt_ts, (seq, uid, pid))
        if pt_ts is None or S <= pt_ts < E:
            win.emit_raw(bytes(payload), "process_tree")
        else:
            _maybe_strip(win, payload, seq, incr_seqs)
        return
    if cls == classify.SNAPSHOT:
        if packet_ts is None:
            win.emit_raw(bytes(payload), "metadata")
        elif packet_ts < S and data_fno == _TP.PROCESS_STATS:
            # merge per-pid: a process absent from the latest snapshot
            # still has its counter rows in TP (they persist), so the
            # carry-in must contain the union of latest entries.
            for fno, wt, val, _s, _e in iter_fields(payload):
                if fno != _TP.PROCESS_STATS or wt != WT_LEN:
                    continue
                for f2, w2, v2, _s2, _e2 in iter_fields(val):
                    if f2 != fields.ProcessStats.PROCESSES or \
                            w2 != WT_LEN:
                        continue
                    for f3, w3, v3, _s3, _e3 in iter_fields(v2):
                        if f3 == fields.ProcessStats.Process.PID and \
                                w3 == WT_VARINT:
                            win.ps_procs[v3] = bytes(v2)
                            break
        elif packet_ts < S:
            # keep newest pre-window copy
            cur = win.snapshots.get(data_fno)
            if cur is None or packet_ts > cur[0]:
                win.snapshots[data_fno] = (packet_ts, bytes(payload))
        elif packet_ts < E:
            win.emit_raw(bytes(payload), "snapshot")
        else:
            _maybe_strip(win, payload, seq, incr_seqs)
        return
    if cls == classify.HEAPPROFD:
        _heapprofd(win, payload, packet_ts, seq)
        return
    # TIMED (and anything else with a timestamp)
    if packet_ts is None:
        win.emit_raw(bytes(payload), "metadata")
    elif S <= packet_ts < E:
        win.emit_raw(bytes(payload), "timed")
    else:
        _maybe_strip(win, payload, seq, incr_seqs)


def _pt_payload(payload):
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno == _TP.PROCESS_TREE and wt == WT_LEN:
            return val
    return b""


def _pt_pairs(payload):
    """yield (tid, tgid) from process_tree threads + (pid, pid) for
    each process entry (TP runs UpdateThread on both)."""
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno != _TP.PROCESS_TREE or wt != WT_LEN:
            continue
        for f2, w2, v2, _s2, _e2 in iter_fields(val):
            if f2 == fields.ProcessTree.THREADS and w2 == WT_LEN:
                tid = tgid = None
                for f3, w3, v3, _s3, _e3 in iter_fields(v2):
                    if f3 == fields.ProcessTree.Thread.TID and \
                            w3 == WT_VARINT:
                        tid = v3
                    elif f3 == fields.ProcessTree.Thread.TGID and \
                            w3 == WT_VARINT:
                        tgid = v3
                if tid is not None and tgid is not None:
                    yield tid, tgid
            elif f2 == fields.ProcessTree.PROCESSES and w2 == WT_LEN:
                for f3, w3, v3, _s3, _e3 in iter_fields(v2):
                    if f3 == fields.ProcessTree.Process.PID and \
                            w3 == WT_VARINT:
                        yield v3, v3
                        break


def _maybe_strip(win: _WinState, payload, seq, incr_seqs):
    if seq in incr_seqs:
        stripped = classify.strip_to_state(payload)
        if stripped:
            win.emit_raw(stripped, "state_strip")


def _ftrace_payload(packet_payload):
    for fno, wt, val, _s, _e in iter_fields(packet_payload):
        if fno == _TP.FTRACE_EVENTS and wt == WT_LEN:
            return val
    return b""


def _rebuild_packet(packet_payload, data_fno, new_data) -> bytes:
    """Rebuild the packet: every field verbatim except the replaced
    data field (appended at the end)."""
    out = bytearray()
    for fno, wt, _v, s, e in iter_fields(packet_payload):
        if fno == data_fno:
            continue
        out += bytes(memoryview(packet_payload)[s:e])
    out += len_field(data_fno, new_data)
    return bytes(out)


def _clamp_prev_end(bundle_payload, S) -> bytes:
    out = bytearray()
    for fno, wt, _v, s, e in iter_fields(bundle_payload):
        if fno == fields.FtraceEventBundle.PREVIOUS_BUNDLE_END_TIMESTAMP \
                and wt == WT_VARINT:
            out += varint_field(fno, S)  # always clamp to S (was < S)
        else:
            out += bytes(memoryview(bundle_payload)[s:e])
    return bytes(out)


# ---------------------------------------------------------- windows
def _overlap(wins, Ss, lo, hi):
    """Yield windows overlapping [lo,hi); lo/hi None-safe."""
    if lo is None:
        lo = -2**63
    if hi is None:
        hi = 2**63 - 1
    # candidates: windows with S < hi; walk back while E > lo
    i = bisect.bisect_left(Ss, hi) - 1
    while i >= 0:
        ws = wins[i]
        if ws.w.end_ns <= lo:
            break
        yield ws
        i -= 1


def _range(cls, data_fno, payload, packet_ts):
    """Time range a packet occupies (for window overlap dispatch)."""
    if cls == classify.HEAPPROFD or cls == classify.PROCESS_TREE:
        return None, None  # always dispatched (state machinery decides)
    if cls == classify.SNAPSHOT:
        return None, None
    if packet_ts is None:
        return None, None
    return packet_ts, packet_ts + 1


# ------------------------------------------------- tracker release
def _cross_release(rts, ritem, tracker, cross, opts):
    """Released (rts,item): take window snapshots at S/E crossings,
    fill boundary.csv lookahead rows, then apply to tracker."""
    s_order = cross.s_order
    while cross.s_i < len(s_order) and \
            s_order[cross.s_i].w.start_ns <= rts:
        _snapshot_start(s_order[cross.s_i], tracker, opts, cross)
        cross.s_i += 1
    e_order = cross.e_order
    while cross.e_i < len(e_order) and \
            e_order[cross.e_i].w.end_ns <= rts:
        _snapshot_end(e_order[cross.e_i], tracker, opts, cross)
        cross.e_i += 1
    # windows fully done (E + boundary lookahead passed)
    while cross.d_i < len(e_order) and \
            e_order[cross.d_i].w.end_ns + \
            opts.boundary_lookahead_ns < rts:
        ws = e_order[cross.d_i]
        if not ws.done:
            ws.done = True
            cross.ndone += 1
        cross.d_i += 1
    pop = tracker.apply(rts, ritem)
    # fill real_end rows for slices closing now (in-window + lookahead)
    if pop is not None:
        for ws in list(cross.active):
            _fill_end_row(ws, rts, pop)
            if not ws.end_rows:
                cross.active.discard(ws)


def _entry_key(e):
    """Slice-instance key for an open stack entry (identity by
    kind+name/txid+orig ts; entries also carry their tid)."""
    k = e[0]
    if k == "b":
        return ("e", k, e[6], e[1], e[3])    # tid, name, orig ts
    if k == "btx":
        return ("e", k, e[5], e[1], e[2])    # tid, txid, ts
    if k == "brx":
        return ("e", k, e[5], e[1], e[2])
    return ("e", k, e[4], e[1])              # blw/blh: tid, ts


def _fill_end_row(ws, rts, pop):
    """Fill real_end for boundary rows when the slice's closer arrives
    within the lookahead window. ``pop`` is tracker.apply's return:
    ("stk", tid, entry) | ("async", key) | ("named", key)."""
    kind = pop[0]
    if kind == "stk":
        # fill every boundary row of the popped slice instance
        idxs = ws.end_rows.get(_entry_key(pop[2])) if pop[2] else None
        if idxs:
            for i in idxs:
                row = ws.boundary_rows[i]
                if row[6] == "":
                    row[6] = rts
                    row[7] = rts - row[5]
            del ws.end_rows[_entry_key(pop[2])]
    elif kind == "async":
        key = ("async",) + tuple(pop[1])
        idxs = ws.end_rows.get(key)
        if idxs:
            for i in idxs:
                row = ws.boundary_rows[i]
                if row[6] == "":
                    row[6] = rts
                    row[7] = rts - row[5]
            del ws.end_rows[key]
    elif kind == "named":
        key = ("named",) + tuple(pop[1])
        idxs = ws.end_rows.get(key)
        if idxs:
            i = idxs.pop()   # named stacks pop LIFO
            row = ws.boundary_rows[i]
            if row[6] == "":
                row[6] = rts
                row[7] = rts - row[5]
            if not idxs:
                del ws.end_rows[key]


# ------------------------------------------------- ftrace parsing
def _parse_ftrace(packet_payload, conv, seq, uid, rep):
    """Parse a bundle ONCE; produce per-window-reusable masks and
    tracker items (order: as parsed)."""
    bv = ftrace.parse_bundle(_ftrace_payload(packet_payload))
    cpu = bv.cpu
    compact = ftrace.CompactSched.decode(bv.compact) \
        if bv.compact is not None else None

    def to_bt(t):
        return conv.ftrace_to_boottime(bv.ftrace_clock, seq, t)

    rep.bundles_decoded += 1
    sw_bts = wk_bts = []
    if compact is not None:
        sw_bts = [to_bt(t) for t in compact.switch_timestamps()]
        wk_bts = [to_bt(t) for t in compact.waking_timestamps()]
    ev_bts = []
    evs = []
    for ev in bv.events:
        ts, pid, etype, eval_ = ftrace.event_meta(ev)
        bt = to_bt(ts) if ts is not None else None
        ev_bts.append(bt)
        evs.append((bt, pid, etype, bytes(ev), eval_))

    items = []   # (bt_ts, tracker_item) in file order
    lo = hi = None
    if compact is not None:
        for i, bt in enumerate(sw_bts):
            if bt is not None:
                items.append((bt, ("sw", cpu, "compact",
                                   ftrace.compact_switch_row(compact, i),
                                   seq, uid)))
                lo = bt if lo is None else min(lo, bt)
                hi = bt if hi is None else max(hi, bt)
        for bt in wk_bts:
            if bt is not None:
                items.append((bt, ("tick", cpu, seq, uid)))
                lo = min(lo, bt) if lo is not None else bt
                hi = max(hi, bt) if hi is not None else bt
    for bt, pid, etype, ev_bytes, eval_ in evs:
        if bt is None:
            continue
        lo = bt if lo is None else min(lo, bt)
        hi = bt if hi is None else max(hi, bt)
        name = fields.FTRACE_EVENT_NAMES.get(etype, "")
        if etype == fields.FtraceEvent.SCHED_SWITCH:
            items.append((bt, ("sw", cpu, "full", ev_bytes, seq, uid)))
        elif etype == fields.FtraceEvent.PRINT:
            it = _atrace_item(bt, pid, eval_, cpu, ev_bytes)
            items.append((bt, it) if it else (bt, ("tick", cpu, seq,
                                                   uid)))
        elif etype == fields.FtraceEvent.BINDER_TRANSACTION:
            txid, is_reply, is_oneway, to_proc = _binder_tx(eval_)
            items.append((bt, ("btx", pid, txid, is_reply, is_oneway,
                               to_proc, ev_bytes, cpu)))
        elif etype == fields.FtraceEvent.BINDER_TRANSACTION_RECEIVED:
            txid = 0
            for f2, w2, v2, _s2, _e2 in iter_fields(eval_):
                if f2 == fields.BinderTransactionReceivedFtraceEvent. \
                        DEBUG_ID and w2 == WT_VARINT:
                    txid = v2
                    break
            items.append((bt, ("brx", pid, txid, ev_bytes, cpu)))
        elif etype == fields.FtraceEvent.BINDER_COMMAND:
            items.append((bt, ("bcmd", pid, _first_varint(eval_))))
        elif etype == fields.FtraceEvent.BINDER_RETURN:
            items.append((bt, ("bret", pid, _first_varint(eval_))))
        elif etype == fields.FtraceEvent.BINDER_LOCK:
            items.append((bt, ("block", pid, ev_bytes, cpu)))
        elif etype == fields.FtraceEvent.BINDER_LOCKED:
            items.append((bt, ("blocked", pid, ev_bytes, cpu)))
        elif etype == fields.FtraceEvent.BINDER_UNLOCK:
            items.append((bt, ("bunlock", pid, ev_bytes, cpu)))
        elif etype == fields.FtraceEvent.TASK_NEWTASK:
            ntid = flags = 0
            for f2, w2, v2, _s2, _e2 in iter_fields(eval_):
                if w2 != WT_VARINT:
                    continue
                if f2 == fields.TaskNewtaskFtraceEvent.PID:
                    ntid = v2
                elif f2 == fields.TaskNewtaskFtraceEvent.CLONE_FLAGS:
                    flags = v2
            items.append((bt, ("nt", pid, ntid, flags)))
        elif etype == fields.FtraceEvent.SCHED_PROCESS_FREE:
            fpid = 0
            for f2, w2, v2, _s2, _e2 in iter_fields(eval_):
                if w2 == WT_VARINT and f2 == 1:    # pid = field 1
                    fpid = v2
                    break
            items.append((bt, ("free", fpid)))
        else:
            key = ftrace.counter_key(etype, eval_)
            items.append((bt, ("ctr", cpu, key, ev_bytes, seq, uid)
                          if key is not None else
                          ("tick", cpu, seq, uid)))
    return {"bv": bv, "compact": compact, "cpu": cpu, "items": items,
            "lo": lo, "hi": (hi + 1 if hi is not None else None),
            "sw_bts": sw_bts, "wk_bts": wk_bts,
            "ev_bts": ev_bts, "evs": evs, "seq": seq, "uid": uid}


def _binder_tx(eval_):
    """(txid, is_reply, is_oneway, to_proc) from the tx submessage."""
    BT = fields.BinderTransactionFtraceEvent
    txid = reply = flags = to_proc = 0
    for fno, wt, val, _s, _e in iter_fields(eval_):
        if wt != WT_VARINT:
            continue
        if fno == BT.DEBUG_ID:
            txid = val
        elif fno == BT.REPLY:
            reply = val
        elif fno == BT.FLAGS:
            flags = val
        elif fno == BT.TO_PROC:
            to_proc = val
    return txid, bool(reply), bool(flags & 1), to_proc


def _first_varint(eval_):
    for fno, wt, val, _s, _e in iter_fields(eval_):
        if wt == WT_VARINT:
            return val
    return 0


def _atrace_item(bt, pid, eval_, cpu, ev_bytes):
    """Map a print event to a tracker item by buf tag. Formats (from
    TP systrace_trace_point + sample data):
      B|tgid|name  E|tgid  S|tgid|name|cookie  F|tgid|name|cookie
      C|tgid|name|value  I|tgid|name (instant)
      G|tgid|track|name|cookie  H|tgid|track|cookie  N|tgid|track|name
    """
    buf = ftrace.print_buf(eval_)
    if buf is None:
        return ("tick", cpu, 0, 0)
    parts = buf.split(b"|")
    tag = parts[0]
    tgid = pid
    if len(parts) > 1:
        # tgid field may carry a trailing \n -- int() strips it,
        # isdigit() does not (an E|967\n parsed as tgid=pid creates a
        # phantom utid per TP's UpdateThread rules).
        try:
            tgid = int(parts[1])
        except ValueError:
            tgid = pid
    if tag == b"B":
        return ("B", pid, tgid,
                parts[2] if len(parts) > 2 else b"", ev_bytes, cpu)
    if tag == b"E":
        # E| with empty tgid field -> tgid 0 -> GetThreadOrNull
        if len(parts) > 1 and not parts[1].strip():
            tgid = 0
        return ("E", pid, tgid, ev_bytes, cpu)
    if tag in (b"S", b"F"):
        name = parts[2] if len(parts) > 2 else b""
        cookie = 0
        if len(parts) > 3:
            try:
                cookie = int(parts[3])
            except ValueError:
                cookie = 0
        return ("async", pid, tgid, name, cookie, ev_bytes, cpu,
                tag == b"S")
    if tag in (b"G", b"H"):
        track = parts[2] if len(parts) > 2 else b""
        name = parts[3] if len(parts) > 3 else b""
        cookie = 0
        if tag == b"G" and len(parts) > 4:
            try:
                cookie = int(parts[4])
            except ValueError:
                cookie = 0
        elif tag == b"H" and len(parts) > 3:
            try:
                cookie = int(parts[3])
            except ValueError:
                cookie = 0
        return ("named", pid, tgid, track, name, cookie, ev_bytes, cpu,
                tag == b"G")
    if tag == b"C":
        name = parts[2] if len(parts) > 2 else b""
        # kill_one_process routes to an lmk instant slice, not a counter
        if name == b"kill_one_process":
            return ("res", pid, tgid)
        val = 0
        if len(parts) > 3:
            try:
                val = int(parts[3])
            except ValueError:
                pass
        return ("c", pid, tgid, name, val, ev_bytes, cpu)
    # I/N/T and unparseable bufs: Scoped instants or no-op, but they
    # still resolve thread identity via UpdateThread (systrace_parser).
    return ("res", pid, tgid)


def _emit_ftrace(win, parsed, payload, opts, incr_seqs, seq):
    """Emit the (possibly filtered) bundle to ONE overlapping window."""
    S, E = win.w.start_ns, win.w.end_ns
    rep = parsed
    sw_keep = [bt is not None and S <= bt < E for bt in rep["sw_bts"]]
    wk_keep = [bt is not None and S <= bt < E for bt in rep["wk_bts"]]
    ev_keep = [bt is not None and S <= bt < E for bt in rep["ev_bts"]]
    all_kept = all(sw_keep) and all(wk_keep) and all(ev_keep)
    if all_kept and (rep["sw_bts"] or rep["wk_bts"] or rep["ev_bts"]):
        new_payload = _ftrace_payload(payload)
        if rep["cpu"] not in win.emitted_cpus and \
                rep["bv"].previous_bundle_end_timestamp is not None:
            new_payload = _clamp_prev_end(new_payload, S)
            win.emitted_cpus.add(rep["cpu"])
        pkt = _rebuild_packet(payload, _TP.FTRACE_EVENTS, new_payload)
        win.emit_raw(pkt, "ftrace")
        return
    new_payload = ftrace.filter_bundle_mask(
        _ftrace_payload(payload), rep["compact"], ev_keep, sw_keep,
        wk_keep)
    if new_payload is None:
        _maybe_strip(win, payload, seq, incr_seqs)
        return
    if rep["cpu"] not in win.emitted_cpus and \
            rep["bv"].previous_bundle_end_timestamp is not None:
        new_payload = _clamp_prev_end(new_payload, S)
        win.emitted_cpus.add(rep["cpu"])
    win.emit_raw(_rebuild_packet(payload, _TP.FTRACE_EVENTS,
                                 new_payload), "ftrace")


# ------------------------------------------------------ android_log
# TP converts LogEvent.timestamp from CLOCK_REALTIME to BOOTTIME via the
# latest clock_snapshot (android_probes_module.cc); unconvertible events
# are dropped. We mirror that: REALTIME -> BOOTTIME, drop on failure.
def _parse_log(packet_payload, conv):
    """Parse an android_log packet ONCE: returns
    (head_bytes, inner_other_fields, [(bt_ts, raw_event_bytes)])."""
    head = bytearray()
    other = bytearray()
    events = []
    for fno, wt, val, s, e in iter_fields(packet_payload):
        if fno in classify._HEAD_FIELDS:
            head += bytes(memoryview(packet_payload)[s:e])
        elif fno == _TP.ANDROID_LOG and wt == WT_LEN:
            for lfno, lwt, lval, ls, le in iter_fields(val):
                if lfno == fields.AndroidLogPacket.EVENTS and \
                        lwt == WT_LEN:
                    ts = None
                    for ifno, iwt, ival, _is, _ie in iter_fields(lval):
                        if ifno == \
                                fields.AndroidLogPacket.LogEvent.TIMESTAMP \
                                and iwt == WT_VARINT:
                            ts = ival
                    bt = conv.to_boottime(fields.BUILTIN_CLOCK_REALTIME,
                                          ts) if ts is not None else None
                    if bt is not None:
                        events.append((bt, bytes(lval)))
                else:
                    other += bytes(memoryview(val)[ls:le])
    return bytes(head), bytes(other), events


def _emit_log(win: _WinState, payload, parsed_log, incr_seqs, seq):
    S, E = win.w.start_ns, win.w.end_ns
    head, other, events = parsed_log
    inner = bytearray(other)
    kept = 0
    for bt, raw in events:
        if S <= bt < E:
            inner += len_field(fields.AndroidLogPacket.EVENTS, raw)
            kept += 1
    if kept or other:
        win.emit_raw(
            head + len_field(_TP.ANDROID_LOG, bytes(inner)),
            "android_log")
    else:
        _maybe_strip(win, payload, seq, incr_seqs)


# --------------------------------------------------------- heapprofd
def _heapprofd(win: _WinState, payload, packet_ts, seq):
    S, E = win.w.start_ns, win.w.end_ns
    grp = win.heapprofd.setdefault(seq or 0, [])
    grp.append((packet_ts, bytes(payload)))
    continued = False
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno == _TP.PROFILE_PACKET and wt == WT_LEN:
            for ifno, iwt, ival, _is, _ie in iter_fields(val):
                if ifno == fields.ProfilePacket.CONTINUED \
                        and iwt == WT_VARINT and ival:
                    continued = True
    if continued:
        return
    # group complete: assign whole to window containing first ts
    first_ts = grp[0][0]
    if first_ts is not None and S <= first_ts < E:
        for _t, p in grp:
            win.emit_raw(p, "heapprofd")
    grp.clear()


def _flush_heapprofd(win: _WinState, rep):
    for seq, grp in win.heapprofd.items():
        if not grp:
            continue
        first_ts = grp[0][0]
        S, E = win.w.start_ns, win.w.end_ns
        if first_ts is not None and S <= first_ts < E:
            for _t, p in grp:
                win.emit_raw(p, "heapprofd")
        grp.clear()
