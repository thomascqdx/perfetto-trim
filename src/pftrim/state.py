"""Bounded reorder buffer for out-of-order timestamped events (stdlib only).

Traces interleave per-CPU ftrace bundles whose event timestamps are not
globally sorted. Processing that needs chronological order (TP sorts all
events by ts) uses this buffer: items are released in nondecreasing ts
order once they are older than ``max_pushed_ts - window_ns``. Items pushed
with a ts older than the last released ts can't be held back any more --
they are released immediately and counted in ``late_events``.

Memory is O(items within window_ns), independent of trace length.
Used by scan.py and reused by later boundary-state milestones (PLAN 3.3).
"""

from __future__ import annotations

import bisect


class ReorderBuffer:
    """Release semantics (per pushed item, in push order): an item older
    than the last released ts is released immediately (late); otherwise
    it is held, and every held item with ts < max_pushed_ts - window_ns
    is released in (ts, push-seq) order.

    Implementation: held items live in time buckets (ts >> bin_shift)
    and are released bucket-wise with C-level sorts instead of a
    per-item heap. Releases are materialized lazily -- at the end of
    each push/push_many call, and before any item older than the current
    limit (the only case where the late/not-late decision depends on
    the exact last released ts). The concatenated release stream is
    therefore identical to releasing after every single push: items
    released by consecutive per-item pushes are globally (ts, seq)
    ordered, except late items, which are emitted at their exact
    position.
    """

    __slots__ = ("window_ns", "bin_shift", "_buckets", "_lo_bin", "_n",
                 "_seq", "_max_ts", "_last", "late_events")

    def __init__(self, window_ns: int = 2_000_000_000, bin_shift: int = 23):
        self.window_ns = window_ns
        self.bin_shift = bin_shift     # 2**23 ns ~ 8.4 ms buckets
        self._buckets: dict = {}       # bin -> [(ts, seq, obj), ...]
        self._lo_bin: int | None = None  # no held item below this bin
        self._n = 0                    # held items
        self._seq: int = 0             # push counter -> stable for equal ts
        self._max_ts: int | None = None
        self._last: int | None = None  # last released ts
        self.late_events = 0

    def push(self, ts: int, item) -> list:
        """Push an item; returns a list of items released in ts order."""
        return self._run(((ts, item),), False)

    def push_many(self, items, unwrap: bool = False) -> list:
        """push(ts, pair) for each (ts, ...) pair in order; returns the
        released pairs (identical stream to per-item pushes). With
        unwrap=True it is push(ts, item) per (ts, item) pair instead:
        only the item is held and returned (less memory per item)."""
        return self._run(items, not unwrap)

    def _run(self, items, keep_pair: bool) -> list:
        out = []
        buckets = self._buckets
        shift = self.bin_shift
        win = self.window_ns
        seq = self._seq
        max_ts = self._max_ts
        limit = None if max_ts is None else max_ts - win
        lo_bin = self._lo_bin
        n_add = 0
        for pair in items:
            ts = pair[0]
            obj = pair if keep_pair else pair[1]
            if limit is not None and ts < limit:
                # old item: late iff older than the exact last release
                self._lo_bin = lo_bin
                self._n += n_add
                n_add = 0
                self._flush(limit, out)
                lo_bin = self._lo_bin
                if self._last is not None and ts < self._last:
                    self.late_events += 1
                    out.append(obj)
                    continue
            elif max_ts is None or ts > max_ts:
                max_ts = ts
                limit = ts - win
            b = ts >> shift
            lst = buckets.get(b)
            if lst is None:
                buckets[b] = [(ts, seq, obj)]
                if lo_bin is None or b < lo_bin:
                    lo_bin = b
            else:
                lst.append((ts, seq, obj))
            seq += 1
            n_add += 1
        self._seq = seq
        self._max_ts = max_ts
        self._lo_bin = lo_bin
        self._n += n_add
        if limit is not None:
            self._flush(limit, out)
        return out

    def _flush(self, limit: int, out: list) -> None:
        """Release every held item with ts < limit, in (ts, seq) order."""
        lo = self._lo_bin
        if lo is None or not self._n:
            return
        buckets = self._buckets
        hb = limit >> self.bin_shift
        if hb < lo:
            return
        if hb - lo <= 4 * len(buckets) + 16:
            bins = range(lo, hb)
        else:   # sparse (e.g. after a far jump): walk existing bins only
            bins = sorted(b for b in buckets if b < hb)
        last = self._last
        n = self._n
        for b in bins:
            lst = buckets.pop(b, None)
            if lst:
                lst.sort()
                out.extend([e[2] for e in lst])
                last = lst[-1][0]
                n -= len(lst)
        lst = buckets.get(hb)
        if lst:
            lst.sort()
            i = bisect.bisect_left(lst, (limit,))
            if i:
                out.extend([e[2] for e in lst[:i]])
                last = lst[i - 1][0]
                n -= i
                if i == len(lst):
                    del buckets[hb]
                else:
                    del lst[:i]
        self._last = last
        self._n = n
        self._lo_bin = hb if buckets else None

    def drain(self) -> list:
        """Release all remaining items in ts order (call at EOF)."""
        out = []
        buckets = self._buckets
        for b in sorted(buckets):
            lst = buckets[b]
            lst.sort()
            out.extend([e[2] for e in lst])
            self._last = lst[-1][0]
        buckets.clear()
        self._n = 0
        self._lo_bin = None
        return out

    @property
    def pending(self) -> int:
        return self._n

    @property
    def last_released(self) -> int | None:
        return self._last


# ------------------------------------------------------------------
# Boundary tracker (PLAN 3.3): per-CPU + per-thread state at window
# boundaries, fed events in global ts order through a ReorderBuffer.
#
# Slice model mirrors TP v57 exactly (single pending-slice stack per
# thread_execution track, shared by atrace B/E and binder):
#   slice_tracker.cc  End(null name) closes TOPMOST PENDING slice;
#                     empty stack / no pending -> silent no-op.
#   systrace_parser.cc  B pushes on track of FtraceEvent.pid (tid),
#                     E = End on that track; S/F async on
#                     atrace_async_slice tracks keyed (upid,name,cookie)
#                     via BeginLegacyUnnestable (first open S wins);
#                     G/H on atrace_async_slice_for_track keyed
#                     (upid,track_name,cookie), nestable stack;
#                     I/N = Scoped instants (no lasting state);
#                     C = counter on atrace counter track (upid,name).
#   binder_tracker.cc   Transaction: every tx registers
#                     outstanding_transactions_[id] = {is_reply,
#                     is_oneway} (even if slice insert no-ops);
#                     !reply && !oneway -> Begin "binder transaction"
#                     on sender's track; reply -> End on replier's
#                     track; oneway -> Scoped "binder transaction
#                     async" (dur 0). TransactionReceived: unknown id
#                     ignored entirely; found id erased; reply -> End
#                     on receiver's track; !reply&&!oneway -> Begin
#                     "binder reply" on receiver's track + flow;
#                     oneway -> Scoped "binder async rcv" + flow.
#                     Lock -> Begin "binder lock waiting";
#                     Locked -> End(top) + Begin "binder lock held";
#                     Unlock -> End(name="binder lock held").
#                     TxnFrame state machine for binder_command /
#                     binder_return ported verbatim (states below).
# ------------------------------------------------------------------
# Item kinds pushed into the buffer (tuples):
#   ("sw", cpu, kind, info, seq, uid)        sched_switch
#     kind: "compact" | "full" | "skip" (cpu's first compact switch)
#   ("ctr", cpu, key, ev_bytes, seq, uid)    counter-like ftrace event
#   ("tick", cpu, seq, uid)                  any ftrace event
#   ("B", pid, tgid, name, ev, cpu)          atrace B push
#   ("E", pid, tgid, ev, cpu)                atrace E (tgid 0 -> GTON)
#   ("res", pid, tgid)                       identity-only UpdateThread
#                                           (I/N/T + unparseable bufs)
#   ("async", pid, tgid, name, cookie, ev, cpu, is_begin)   S/F
#   ("named", pid, tgid, track, name, cookie, ev, cpu, is_begin) G/H
#   ("c", pid, tgid, name, value, ev, cpu)   atrace C counter
#   ("btx", pid, txid, is_reply, is_oneway, to_proc, ev, cpu)
#   ("brx", pid, txid, ev, cpu)              binder_transaction_received
#   ("bcmd", pid, cmd)                       binder_command
#   ("bret", pid, cmd)                       binder_return
#   ("block"/"blocked"/"bunlock", pid, ev, cpu)
#   ("nt", src_tid, new_tid, clone_flags)    task_newtask
#   ("free", pid)                            sched_process_free
#   ("pt", tid, tgid)                        process_tree thread pair
#   ("frame", cookie, packet_bytes, is_start)
#
# Thread identity (process_tracker.cc): stacks and thread-track keys
# are per *incarnation* (utid), not per tid. GetThreadOrNull scans the
# tid's utids newest->oldest, skipping dead (end_ts, dead process, pid
# replaced); UpdateThread picks the first alive utid with matching
# process pid or unknown upid, else StartNewThread; every new process
# also runs UpdateThread(pid, pid) so tid==pid gets a main utid.
# Diag-validated: scripts/diag_thread_stacks.py reproduces TP's 114
# open slices on the sample exactly.
#
# track_stack entries (tuples), keyed by incarnation id:
#   ("b",  name, tgid, ts, ev, cpu, tid)                    atrace B
#   ("btx", txid, ts, ev, cpu, tid)                         "binder transaction"
#   ("brx", txid, ts, ev, cpu, tid, tx_ev, tx_cpu)          "binder reply"
#   ("blw"/"blh", ts, ev, cpu, tid)                         binder lock w/h
_FRAME_CAP = 10_000
_OUTSTANDING_CAP = 200_000

# binder ioctl commands (binder_tracker.h)
_BC_TRANSACTION = 0x40406300
_BC_REPLY = 0x40406301
_BC_TRANSACTION_SG = 0x40486311
_BC_REPLY_SG = 0x40486312
_BR_TRANSACTION_SEC_CTX = 0x80487202
_BR_TRANSACTION = 0x80407202
_BR_REPLY = 0x80407203
_BR_DEAD_REPLY = 0x7205
_BR_TRANSACTION_COMPLETE = 0x7206
_BR_FAILED_REPLY = 0x7211
_BR_FROZEN_REPLY = 0x7212
_BR_TRANSACTION_PENDING_FROZEN = 0x7214
_BR_ONEWAY_SPAM_SUSPECT = 0x7213

# TxnFrame states (binder_tracker.cc TxnFrame::State)
_TF_SND_AFTER_BC_TX = 0        # kSndAfterBC_TRANSACTION
_TF_RCV_AFTER_BC_REPLY = 1     # kRcvAfterBC_REPLY
_TF_SND_AFTER_TX = 2           # kSndAfterTransaction
_TF_RCV_AFTER_TX = 3           # kRcvAfterTransaction
_TF_SND_AFTER_BR_TX_COMPLETE = 4  # kSndAfterBR_TRANSACTION_COMPLETE
_TF_SND_AFTER_TX_RECEIVED = 5  # kSndAfterTransactionReceived
_TF_RCV_AFTER_TX_RECEIVED = 6  # kRcvAfterTransactionReceived
_TF_RCV_AFTER_BR_TX = 7        # kRcvAfterBR_TRANSACTION


class BoundaryTracker:
    """Global per-CPU/per-thread state, ordered via ReorderBuffer.

    Usage: engine pushes every ftrace/log-derived event through
    ``push(ts, item)``; released items are applied via ``apply``.
    ``replay_plan()`` / ``snapshot_open()`` capture the state at
    release boundary S / E -- call when a released ts first crosses
    them.
    """

    __slots__ = ("buf", "cpu_switch", "cpu_seen_compact",
                 "cpu_counters", "cpu_last_ts", "track_stack",
                 "outstanding", "async_open", "named_open", "ctr",
                 "frames", "frame_cap_warn", "txn_frames",
                 "lock_pending", "lock_held", "out_cap_warn",
                 "tids", "thread", "procs", "pids", "nu", "np")

    def __init__(self, window_ns: int = 2_000_000_000):
        self.buf = ReorderBuffer(window_ns)
        self.cpu_switch = {}       # cpu -> (ts, kind, info, seq, uid)
        self.cpu_seen_compact = {}  # cpu -> count of compact switches
        self.cpu_counters = {}     # cpu -> {key: (ts, ev_bytes, seq, uid)}
        self.cpu_last_ts = {}      # cpu -> max applied ftrace ts
        # thread identity (per-incarnation, mirroring process_tracker)
        self.tids = {}             # tid -> [utid] oldest..newest
        self.thread = {}           # utid -> {"tid","upid","end"}
        self.procs = {}            # upid -> {"pid","end","main"}
        self.pids = {}             # pid -> upid
        self.nu = self.np = 0
        self.track_stack = {}      # utid -> [entry tuples] pending
        self.outstanding = {}      # txid -> (is_reply, is_oneway, ts, ev, cpu, tid)
        self.async_open = {}       # (tgid, name, cookie) -> (ts, ev, cpu, tid)
        self.named_open = {}       # (tgid, track, cookie) -> [(ts, ev, cpu, tid, name)]
        self.ctr = {}              # (tgid, name) -> (ts, val, ev, cpu)
        self.frames = {}           # cookie -> (ts, packet_bytes)
        self.frame_cap_warn = False
        self.txn_frames = {}       # tid -> [ [state, is_oneway, is_reply] ]
        self.lock_pending = {}     # utid -> ts  (attempt_lock_)
        self.lock_held = {}        # utid -> ts  (lock_acquired_)
        self.out_cap_warn = False

    # --------------------------------------- thread identity (TP rules)
    def _new_proc(self, pid, main_utid=None):
        self.np += 1
        upid = self.np
        self.procs[upid] = {"pid": pid, "end": None, "main": main_utid}
        self.pids[pid] = upid
        return upid

    def _new_thread(self, tid, upid=None, main=False):
        self.nu += 1
        utid = self.nu
        self.thread[utid] = {"tid": tid, "upid": upid, "end": None}
        if upid is not None and main:
            self.procs[upid]["main"] = utid
        self.tids.setdefault(tid, []).append(utid)
        return utid

    def _alive(self, utid):
        t = self.thread[utid]
        if t["end"] is not None:
            return False
        up = t["upid"]
        if up is None:
            return True
        p = self.procs.get(up)
        if p is None or p["end"] is not None:
            return False
        return self.pids.get(p["pid"]) == up

    def _gton(self, tid, pid=None):
        """GetThreadOrNull: newest alive utid for tid matching pid (or
        unknown-upid wildcard, or any pid when pid is None)."""
        for utid in reversed(self.tids.get(tid, ())):
            if not self._alive(utid):
                continue
            up = self.thread[utid]["upid"]
            if up is None:
                return utid
            if pid is None or self.procs[up]["pid"] == pid:
                return utid
        return None

    def _goc(self, tid):
        """GetOrCreateThread(tid): newest alive utid, else new."""
        u = self._gton(tid)
        return u if u is not None else self._new_thread(tid)

    def _update_thread(self, tid, pid):
        """UpdateThread(tid, tgid): gton by process pid, else new
        thread; associate upid when unknown. New processes also run
        UpdateThread(pid, pid) (GetOrCreateProcessInternal) so every
        pid gets a main-thread utid for tid==pid."""
        upid = self.pids.get(pid)
        if upid is None:
            upid = self._new_proc(pid)
            self._update_thread(pid, pid)
        u = self._gton(tid, pid)
        if u is None:
            u = self._new_thread(tid)
        if self.thread[u]["upid"] is None:
            self.thread[u]["upid"] = upid
            if tid == pid:
                self.procs[upid]["main"] = u
        return u

    def _end_thread(self, ts, tid):
        u = self._gton(tid)
        if u is None:
            return
        self.thread[u]["end"] = ts
        self.tids[tid].remove(u)
        up = self.thread[u]["upid"]
        if up is not None and self.procs[up]["main"] == u:
            self.procs[up]["end"] = ts

    def _start_new_process(self, ts, pid):
        old = self.pids.pop(pid, None)
        if old is not None:
            self.procs[old]["end"] = ts
        self.tids.pop(pid, None)
        u = self._new_thread(pid)
        upid = self._new_proc(pid, u)
        self.thread[u]["upid"] = upid

    def push(self, ts: int, item) -> list:
        return self.buf.push(ts, item)

    def push_many(self, items) -> list:
        return self.buf.push_many(items)

    @property
    def late_events(self) -> int:
        return self.buf.late_events

    def drain(self) -> list:
        return self.buf.drain()

    @property
    def pending(self) -> int:
        return self.buf.pending

    @property
    def last_released(self):
        return self.buf.last_released

    # -------------------------------------------------- slice helpers
    def _pop_top(self, u):
        """TP SliceTracker::End(null name): pop topmost pending slice."""
        stack = self.track_stack.get(u)
        if stack:
            return stack.pop()
        return None

    def _pop_named(self, u, kind):
        """TP End(name): pop topmost pending slice of a given kind."""
        stack = self.track_stack.get(u)
        if not stack:
            return None
        for i in range(len(stack) - 1, -1, -1):
            if stack[i][0] == kind:
                return stack.pop(i)
        return None

    def _frame_top(self, tid):
        st = self.txn_frames.get(tid)
        return st[-1] if st else None

    # ---------------------------------------------------------- apply
    def apply(self, ts: int, item):
        """Apply one released (ts, item); returns pop info used by the
        engine to fill boundary.csv real_end values:
            ("stk", tid, popped_entry) | ("async", key) |
            ("named", key) | None
        """
        kind = item[0]
        if kind == "tick":
            _t, cpu, seq, uid = item
            if ts > self.cpu_last_ts.get(cpu, -1):
                self.cpu_last_ts[cpu] = ts
            return None
        if kind == "sw":
            _t, cpu, k, info, seq, uid = item
            if k == "compact":
                n = self.cpu_seen_compact.get(cpu, 0)
                # cpu's FIRST compact switch is skipped by TP (only sets
                # pending state) -- marked 'skip' so the carry-in replay
                # reproduces the identical semantics at trace start.
                if n == 0:
                    k = "skip"
                self.cpu_seen_compact[cpu] = n + 1
            self.cpu_switch[cpu] = (ts, k,
                                    bytes(info) if k == "full" else info,
                                    seq, uid)
            if ts > self.cpu_last_ts.get(cpu, -1):
                self.cpu_last_ts[cpu] = ts
            return None
        if kind == "ctr":
            _t, cpu, key, ev, seq, uid = item
            self.cpu_counters.setdefault(cpu, {})[key] = \
                (ts, bytes(ev), seq, uid)
            return None
        if kind == "B":
            _t, pid, tgid, name, ev, cpu = item
            u = self._update_thread(pid, tgid)
            self.track_stack.setdefault(u, []).append(
                ("b", name, tgid, ts, bytes(ev), cpu, pid))
            return None
        if kind == "E":
            _t, pid, tgid, ev, cpu = item
            u = self._update_thread(pid, tgid) if tgid \
                else self._gton(pid)
            if u is None:
                return None
            popped = self._pop_top(u)
            return ("stk", u, popped) if popped else None
        if kind == "res":
            _t, pid, tgid = item
            self._update_thread(pid, tgid)
            return None
        if kind == "async":
            _t, pid, tgid, name, cookie, ev, cpu, is_begin = item
            self._update_thread(pid, tgid)
            key = (tgid, name, cookie)
            if is_begin:
                # BeginLegacyUnnestable: only the first open S is
                # tracked; further S events are ignored.
                self.async_open.setdefault(key, (ts, bytes(ev), cpu, pid))
            else:
                if self.async_open.pop(key, None) is not None:
                    return ("async", key)
            return None
        if kind == "named":
            _t, pid, tgid, track, name, cookie, ev, cpu, is_begin = item
            self._update_thread(pid, tgid)
            key = (tgid, track, cookie)
            if is_begin:
                self.named_open.setdefault(key, []).append(
                    (ts, bytes(ev), cpu, pid, name))
            else:
                lst = self.named_open.get(key)
                if lst:
                    lst.pop()
                    if not lst:
                        del self.named_open[key]
                    return ("named", key)
            return None
        if kind == "c":
            _t, pid, tgid, name, val, ev, cpu = item
            self._update_thread(pid, tgid)
            self.ctr[(tgid, name)] = (ts, val, bytes(ev), cpu)
            return None
        if kind == "nt":
            _t, src, ntid, flags = item
            if flags & 0x10000:   # CLONE_THREAD
                su = self._goc(src)
                nu = self._new_thread(ntid)
                up = self.thread[su]["upid"]
                if up is not None:
                    self.thread[nu]["upid"] = up
            else:
                self._start_new_process(ts, ntid)
            return None
        if kind == "free":
            self._end_thread(ts, item[1])
            return None
        if kind == "pt":
            _t, tid, tgid = item
            self._update_thread(tid, tgid)
            return None
        if kind == "btx":
            return self._apply_btx(ts, item)
        if kind == "brx":
            return self._apply_brx(ts, item)
        if kind == "bcmd":
            self._apply_bcmd(item)
            return None
        if kind == "bret":
            return self._apply_bret(ts, item)
        if kind == "block":
            _t, pid, ev, cpu = item
            u = self._goc(pid)
            self.lock_pending[u] = ts
            self.track_stack.setdefault(u, []).append(
                ("blw", ts, bytes(ev), cpu, pid))
            return None
        if kind == "blocked":
            _t, pid, ev, cpu = item
            u = self._goc(pid)
            if u not in self.lock_pending:
                return None
            del self.lock_pending[u]
            popped = self._pop_top(u)       # End(top) -- lock waiting
            self.lock_held[u] = ts
            self.track_stack.setdefault(u, []).append(
                ("blh", ts, bytes(ev), cpu, pid))
            return ("stk", u, popped) if popped else None
        if kind == "bunlock":
            _t, pid, ev, cpu = item
            u = self._goc(pid)
            if u not in self.lock_held:
                return None
            del self.lock_held[u]
            popped = self._pop_named(u, "blh")   # End("binder lock held")
            return ("stk", u, popped) if popped else None
        if kind == "frame":
            _t, cookie, pkt, is_start = item
            if is_start:
                if len(self.frames) >= _FRAME_CAP:
                    self.frame_cap_warn = True
                    self.frames.pop(next(iter(self.frames)))
                self.frames[cookie] = (ts, pkt)
            else:
                self.frames.pop(cookie, None)
            return None
        return None

    # ------------------------------------------------------ binder tx
    def _apply_btx(self, ts, item):
        """binder_tracker.cc BinderTracker::Transaction."""
        _t, tid, txid, is_reply, is_oneway, to_proc, ev, cpu = item
        u = self._goc(tid)
        # insert_slice(): reply -> End on replier's track; oneway ->
        # Scoped instant; regular -> Begin "binder transaction".
        popped = None
        if is_reply:
            popped = self._pop_top(u)
        elif not is_oneway:
            self.track_stack.setdefault(u, []).append(
                ("btx", txid, ts, bytes(ev), cpu, tid))
        # outstanding_transactions_[id] set for EVERY tx, even when the
        # slice insert was a no-op.
        if len(self.outstanding) >= _OUTSTANDING_CAP:
            self.out_cap_warn = True
            self.outstanding.pop(next(iter(self.outstanding)))
        self.outstanding[txid] = (is_reply, is_oneway, ts, bytes(ev),
                                  cpu, tid)
        # TxnFrame update (binder_tracker.cc:307-317)
        frame = self._frame_top(tid)
        if frame is not None:
            if frame[0] == _TF_SND_AFTER_BC_TX:
                frame[0] = _TF_SND_AFTER_TX
                frame[1], frame[2] = is_oneway, is_reply
            elif frame[0] == _TF_RCV_AFTER_BC_REPLY:
                frame[0] = _TF_RCV_AFTER_TX
                frame[1], frame[2] = is_oneway, is_reply
            elif frame[0] == _TF_RCV_AFTER_TX_RECEIVED:
                # command tracking probably disabled -- remove frame
                self.txn_frames[tid].pop()
        return ("stk", u, popped) if popped else None

    def _apply_brx(self, ts, item):
        """binder_tracker.cc BinderTracker::TransactionReceived."""
        _t, tid, txid, ev, cpu = item
        tx = self.outstanding.pop(txid, None)
        if tx is None:
            return None            # unknown id -> ignored entirely
        is_reply, is_oneway, tx_ts, tx_ev, tx_cpu, tx_tid = tx
        u = self._goc(tid)
        # TxnFrame update first (source order):
        if not is_oneway:
            if not is_reply:
                self.txn_frames.setdefault(tid, []).append(
                    [_TF_RCV_AFTER_TX_RECEIVED, is_oneway, is_reply])
            else:
                frame = self._frame_top(tid)
                if frame is not None and \
                        frame[0] == _TF_SND_AFTER_BR_TX_COMPLETE:
                    frame[0] = _TF_SND_AFTER_TX_RECEIVED
        popped = None
        if is_reply:
            popped = self._pop_top(u)       # End on receiver's track
        elif not is_oneway:
            self.track_stack.setdefault(u, []).append(
                ("brx", txid, ts, bytes(ev), cpu, tid, tx_ev, tx_cpu))
        # oneway -> Scoped "binder async rcv" instant + flow (no state)
        return ("stk", u, popped) if popped else None

    def _apply_bcmd(self, item):
        """binder_tracker.cc BinderTracker::CommandToKernel."""
        _t, tid, cmd = item
        if cmd in (_BC_TRANSACTION, _BC_TRANSACTION_SG):
            self.txn_frames.setdefault(tid, []).append(
                [_TF_SND_AFTER_BC_TX, None, None])
        elif cmd in (_BC_REPLY, _BC_REPLY_SG):
            frame = self._frame_top(tid)
            if frame is not None and frame[0] == _TF_RCV_AFTER_BR_TX:
                frame[0] = _TF_RCV_AFTER_BC_REPLY

    def _apply_bret(self, ts, item):
        """binder_tracker.cc BinderTracker::ReturnFromKernel."""
        _t, tid, cmd = item
        frame = self._frame_top(tid)
        if frame is None:
            return None
        if cmd in (_BR_DEAD_REPLY, _BR_FAILED_REPLY, _BR_FROZEN_REPLY,
                   _BR_TRANSACTION_PENDING_FROZEN):
            st = frame[0]
            if st == _TF_SND_AFTER_BC_TX:
                self.txn_frames[tid].pop()   # no slice opened
            elif st in (_TF_RCV_AFTER_BC_REPLY, _TF_SND_AFTER_TX,
                        _TF_RCV_AFTER_TX, _TF_SND_AFTER_BR_TX_COMPLETE):
                popped = None
                if frame[1] is not None and not frame[1] and \
                        not frame[2]:
                    popped = self._pop_top(tid)   # End on tid's track
                self.txn_frames[tid].pop()
                return ("stk", tid, popped) if popped else None
            # kSndAfterTransactionReceived / kRcvAfterTransactionReceived
            # / kRcvAfterBR_TRANSACTION -> no action
        elif cmd in (_BR_TRANSACTION_COMPLETE, _BR_ONEWAY_SPAM_SUSPECT):
            st = frame[0]
            if st in (_TF_RCV_AFTER_TX, _TF_SND_AFTER_BC_TX):
                self.txn_frames[tid].pop()
            elif st == _TF_SND_AFTER_TX:
                if frame[1] is not None and not frame[1]:
                    frame[0] = _TF_SND_AFTER_BR_TX_COMPLETE
                else:
                    self.txn_frames[tid].pop()   # oneway: last event
        elif cmd == _BR_REPLY:
            if frame[0] == _TF_SND_AFTER_TX_RECEIVED:
                self.txn_frames[tid].pop()
        elif cmd in (_BR_TRANSACTION, _BR_TRANSACTION_SEC_CTX):
            if frame[0] == _TF_RCV_AFTER_TX_RECEIVED:
                frame[0] = _TF_RCV_AFTER_BR_TX
        return None

    # --------------------------------------------------- snapshots
    def replay_plan(self, S=None):
        """Carry-in replay plan at boundary S (call when all events
        with ts < S are applied). ``S`` filters out entries opened
        in-window (orig ts >= S -- emitted verbatim, not replayed).
        Returns dict:
            groupA   [(ts, ev, cpu)] outstanding is_reply tx events --
                     replayed FIRST (at min-1 / S) so the reply id is
                     registered before any in-window reply-received.
            groupB   [(ts, ev, cpu)] union of stack-opening events +
                     receiver-side tx events + outstanding oneway tx,
                     sorted by original ts (stable).
            a_extra  [tid]           replayed outstanding oneway senders
                                     (each yields a "binder transaction
                                     async" instant -- documented
                                     exception (a)).
            case_b   int             reply entries skipped because the
                                     sender's "binder transaction" is
                                     no longer pending (exception (b)).
        """
        # sender-side "binder transaction" txids still pending pre-S
        pending_btx = set()
        for stack in self.track_stack.values():
            for e in stack:
                if e[0] == "btx" and (S is None or e[2] < S):
                    pending_btx.add(e[1])
        groupA = []
        groupA = []
        groupB = []
        a_extra = []
        case_b = 0
        # outstanding is_reply tx -> group A (registers reply id; the
        # End no-ops on the still-empty replayed stack)
        for txid, (is_reply, is_oneway, ts, ev, cpu, tid) in \
                self.outstanding.items():
            if is_reply:
                groupA.append((ts, ev, cpu))
            elif is_oneway:
                # replay so in-window "binder async rcv" + flow resolve;
                # produces one extra instant on the sender (except. (a))
                groupB.append((ts, ev, cpu))
                a_extra.append(tid)
            # regular outstanding tx: only replayed when its send slice
            # is still pending (covered by the btx stack entry, below);
            # otherwise skipping it is documented exception (b).
        for u, stack in self.track_stack.items():
            for e in stack:
                k = e[0]
                if k == "b":
                    if S is None or e[3] < S:
                        groupB.append((e[3], e[4], e[5]))
                elif k == "btx":
                    if S is None or e[2] < S:
                        groupB.append((e[2], e[3], e[4]))
                elif k in ("blw", "blh"):
                    if S is None or e[1] < S:
                        groupB.append((e[1], e[2], e[3]))
                elif k == "brx":
                    if S is not None and e[2] >= S:
                        continue  # received in-window, emitted verbatim
                    if e[1] in pending_btx:
                        # sender's own btx entry covers the registering
                        # tx (dedup); only the received event is added.
                        groupB.append((e[2], e[3], e[4]))
                    else:
                        # registering tx can't be replayed without
                        # creating a phantom sender slice (except. (b))
                        case_b += 1
        groupB.sort(key=lambda x: x[0])
        return {"groupA": groupA, "groupB": groupB,
                "a_extra": a_extra, "case_b": case_b}

    def snapshot(self):
        """Full state copy at boundary S (cpu carry state etc.)."""
        return {
            "cpu_switch": dict(self.cpu_switch),
            "cpu_counters": {c: dict(m)
                             for c, m in self.cpu_counters.items()},
            "ctr": dict(self.ctr),
            "frames": dict(self.frames),
        }

    def snapshot_open(self):
        """Open slices only -- for closers emitted at window end."""
        return {
            "track_stack": {t: list(s)
                            for t, s in self.track_stack.items() if s},
            "async_open": dict(self.async_open),
            "named_open": {k: list(v)
                           for k, v in self.named_open.items()},
        }


