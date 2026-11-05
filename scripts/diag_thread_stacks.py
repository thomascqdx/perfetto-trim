"""Stage-1 diagnostic: simulate TP's thread-identity + slice-stack model
over the sample in global ts order; compare open slices vs TP.

TP rules (process_tracker.cc v57):
  GetThreadOrNull(tid,pid): scan tids_[tid] newest->oldest, skip dead,
    first alive utid whose process pid==pid or upid unknown.
  IsThreadAlive: no end_ts; if upid set: process not ended and
    pids_[proc.pid]==utid's upid (not replaced).
  UpdateThread(tid,tgid)=GetOrCreateWithParent: GTON(tid, tgid) else
    StartNewThread; associate to process tgid if upid unknown.
  GetOrCreateThread(tid)=GTON(tid,any) else StartNewThread.
  StartNewProcess(pid): pids_.erase(pid)+tids_.erase(pid) then new
    process+main utid.
  EndThread(tid): GTON(tid,any)->set end_ts, remove from tids_; if it
    was the process's main thread, end process too.
  task_newtask !CLONE_THREAD -> StartNewProcess(new_tid); CLONE_THREAD
    -> StartNewThread + AssociateThreads (same process).
  sched_process_free -> EndThread(evt.pid).
  atrace B / E|tgid!=0 -> UpdateThread(pid,tgid); E tgid==0 ->
    GetThreadOrNull(pid) (ignore if none).
  binder tx/rx -> GetOrCreateThread(pid).
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
sys.path.insert(0, os.path.dirname(__file__))
from pftrim import fields, ftrace
from pftrim.reader import iter_packets
from pftrim.clock import ClockConverter
from pftrim.wire import iter_fields
import pftrim.engine as eng

SAMPLE = sys.argv[1] if len(sys.argv) > 1 else \
    r"testdata\sample_tecno_kn8.perfetto-trace"

# ---- TP identity model ------------------------------------------------
class Sim:
    def __init__(self):
        self.tids = {}          # tid -> [utid] oldest..newest
        self.thread = {}        # utid -> {"tid","upid","end"}
        self.procs = {}         # upid -> {"pid","end","main"}
        self.pids = {}          # pid -> upid
        self.stacks = {}        # utid -> [ (name, ts) ]
        self.outst = {}         # txid -> (is_reply, is_oneway)
        self.nu = self.np = 0

    def new_proc(self, pid, main_utid=None):
        self.np += 1
        upid = self.np
        self.procs[upid] = {"pid": pid, "end": None,
                            "main": main_utid}
        self.pids[pid] = upid
        return upid

    def new_thread(self, tid, ts, upid=None, main=False):
        self.nu += 1
        utid = self.nu
        if upid is not None and upid not in self.procs:
            pid_ = None
            upid = self.new_proc(tid if main else 0)
            self.procs[upid]["main"] = utid
        self.thread[utid] = {"tid": tid, "upid": upid,
                             "end": None}
        if upid is not None and main:
            self.procs[upid]["main"] = utid
        self.tids.setdefault(tid, []).append(utid)
        return utid

    def alive(self, utid):
        t = self.thread[utid]
        if t["end"] is not None:
            return False
        up = t["upid"]
        if up is None:
            return True
        p = self.procs.get(up)
        if p is None:
            return True
        if p["end"] is not None:
            return False
        return self.pids.get(p["pid"]) == up

    def gton(self, tid, pid=None):
        for utid in reversed(self.tids.get(tid, ())):
            if not self.alive(utid):
                continue
            up = self.thread[utid]["upid"]
            if up is None:
                return utid
            if pid is None or self.procs[up]["pid"] == pid:
                return utid
        return None

    def goc(self, tid):
        u = self.gton(tid)
        return u if u is not None else self.new_thread(tid, None)

    def update_thread(self, tid, pid):
        upid = self.pids.get(pid)
        if upid is None:
            upid = self.new_proc(pid)
            # TP GetOrCreateProcessInternal also calls
            # UpdateThread(pid, pid): every new process gets a
            # main-thread utid for tid==pid (recursion-safe: pids[pid]
            # now exists).
            self.update_thread(pid, pid)
        u = self.gton(tid, pid)
        if u is None:
            u = self.new_thread(tid, None)
        if self.thread[u]["upid"] is None:
            self.thread[u]["upid"] = upid
            if tid == pid:
                self.procs[upid]["main"] = u
        return u

    def end_thread(self, ts, tid):
        u = self.gton(tid)
        if u is None:
            return
        self.thread[u]["end"] = ts
        self.tids[tid].remove(u)
        up = self.thread[u]["upid"]
        if up is not None and self.procs[up]["main"] == u:
            self.procs[up]["end"] = ts

    def start_new_process(self, ts, pid):
        old = self.pids.pop(pid, None)
        if old is not None:
            self.procs[old]["end"] = ts
        self.tids.pop(pid, None)
        u = self.new_thread(pid, ts)
        upid = self.new_proc(pid, u)
        self.thread[u]["upid"] = upid

    def associate(self, u):
        # AssociateThreads: give upid-less thread the process of some
        # existing thread we can't track cheaply -- approximation:
        # give it the process of tid's main (handled by caller)
        pass

    # ---- slice ops ----------------------------------------------------
    def push(self, utid, name, ts):
        self.stacks.setdefault(utid, []).append((name, ts))

    def pop(self, utid):
        st = self.stacks.get(utid)
        if st:
            return st.pop()
        return None


def varints(eval_, want=(1,)):
    out = {}
    for f2, w2, v2, _s2, _e2 in iter_fields(eval_):
        if w2 == 0 and f2 in want:
            out[f2] = v2
    return out


def process_tree_threads(payload):
    """yield (tid, tgid) from a process_tree packet."""
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno != fields.TracePacket.PROCESS_TREE or wt != 2:
            continue
        for f2, w2, v2, _s2, _e2 in iter_fields(val):
            if f2 != fields.ProcessTree.THREADS or w2 != 2:
                continue
            tid = tgid = None
            for f3, w3, v3, _s3, _e3 in iter_fields(v2):
                if f3 == fields.ProcessTree.Thread.TID and w3 == 0:
                    tid = v3
                elif f3 == fields.ProcessTree.Thread.TGID and w3 == 0:
                    tgid = v3
            if tid is not None and tgid is not None:
                yield tid, tgid
        for f2, w2, v2, _s2, _e2 in iter_fields(val):
            if f2 != fields.ProcessTree.PROCESSES or w2 != 2:
                continue
            pid = None
            for f3, w3, v3, _s3, _e3 in iter_fields(v2):
                if f3 == fields.ProcessTree.Process.PID and w3 == 0:
                    pid = v3
                    break
            # each process entry maps its main thread: UpdateThread(pid,pid)
            if pid is not None:
                yield pid, pid


def main():
    sim = Sim()
    conv = ClockConverter()
    events = []   # (ts, order, item)  ts-order stable by file order
    order = 0
    cur_ts = 0
    for rec in iter_packets(SAMPLE, expand_compressed=True):
        if rec.field_no != fields.Trace.PACKET:
            continue
        payload = rec.payload
        conv.update(payload)
        # process_tree applies at packet position: anchor it to the
        # current ftrace ts so mid-trace refreshes create new utids at
        # the right point.
        for tid, tgid in process_tree_threads(payload):
            order += 1
            events.append((cur_ts, order, ("pt", tid, tgid)))
        ftr = None
        for fno, wt, val, _s, _e in iter_fields(payload):
            if fno == fields.TracePacket.FTRACE_EVENTS:
                ftr = val
                break
        if ftr is None:
            continue
        bv = ftrace.parse_bundle(ftr)
        def to_bt(t):
            return conv.ftrace_to_boottime(bv.ftrace_clock, 0, t)
        for ev in bv.events:
            ts, pid, et, eval_ = ftrace.event_meta(ev)
            bt = to_bt(ts) if ts is not None else None
            if bt is None:
                continue
            cur_ts = bt
            order += 1
            if et == fields.FtraceEvent.PRINT:
                buf = ftrace.print_buf(eval_)
                if buf is None:
                    continue
                parts = buf.split(b"|")
                tag = parts[0]
                tgid = pid
                if len(parts) > 1:
                    try:
                        tgid = int(parts[1])
                    except ValueError:
                        tgid = pid
                if tag == b"B":
                    events.append((bt, order,
                                   ("B", pid, tgid, buf)))
                elif tag == b"E":
                    if len(parts) > 1 and not parts[1].strip():
                        tgid = 0
                    events.append((bt, order,
                                   ("E", pid, tgid, buf)))
                elif tag in (b"C", b"I", b"S", b"F", b"G", b"H",
                             b"N", b"T"):
                    # all atrace tags resolve identity via
                    # UpdateThread(pid, tgid) in systrace_parser
                    events.append((bt, order,
                                   ("pt", pid, tgid)))
            elif et == fields.FtraceEvent.BINDER_TRANSACTION:
                txid, r, o, tp = eng._binder_tx(eval_)
                events.append((bt, order,
                               ("tx", pid, txid, r, o)))
            elif et == fields.FtraceEvent. \
                    BINDER_TRANSACTION_RECEIVED:
                txid = varints(eval_, (1,)).get(1, 0)
                events.append((bt, order, ("rx", pid, txid)))
            elif et == fields.FtraceEvent.TASK_NEWTASK:
                v = varints(eval_, (1, 3))
                events.append((bt, order,
                               ("newtask", pid, v.get(1, 0),
                                v.get(3, 0))))
            elif et == fields.FtraceEvent.SCHED_PROCESS_FREE:
                v = varints(eval_, (1,))
                events.append((bt, order, ("free", v.get(1, 0))))
    events.sort(key=lambda x: (x[0], x[1]))
    checkpoints = [0.2, 0.4, 0.6, 0.8, 0.95]
    t_end = events[-1][0]
    open_at = {}
    ci = 0
    for ts, _o, it in events:
        while ci < len(checkpoints) and \
                ts >= t_end * checkpoints[ci]:
            open_at[checkpoints[ci]] = dict(sim.stacks)
            ci += 1
        k = it[0]
        if k == "pt":
            sim.update_thread(it[1], it[2])
        elif k == "B":
            u = sim.update_thread(it[1], it[2])
            sim.push(u, it[3], ts)
        elif k == "E":
            u = sim.update_thread(it[1], it[2]) if it[2] \
                else sim.gton(it[1])
            if u is not None:
                sim.pop(u)
        elif k == "tx":
            _t, pid, txid, r, o = it
            u = sim.goc(pid)
            if r:
                sim.pop(u)
            elif not o:
                sim.push(u, b"binder transaction", ts)
            sim.outst[txid] = (r, o)
        elif k == "rx":
            _t, pid, txid = it
            tx = sim.outst.pop(txid, None)
            if tx is None:
                continue
            u = sim.goc(pid)
            r, o = tx
            if r:
                sim.pop(u)
            elif not o:
                sim.push(u, b"binder reply", ts)
        elif k == "newtask":
            _t, src, ntid, flags = it
            if flags & 0x10000:
                su = sim.goc(src)
                nu = sim.new_thread(ntid, ts)
                su_up = sim.thread[su]["upid"]
                if su_up is not None:
                    sim.thread[nu]["upid"] = su_up
            else:
                sim.start_new_process(ts, ntid)
        elif k == "free":
            sim.end_thread(ts, it[1])
    open_end = {u: st for u, st in sim.stacks.items() if st}
    n_rows = sum(len(st) for st in open_end.values())
    print(f"SIM open slices at end: {n_rows} on "
          f"{len(open_end)} utids")
    by_tid = {}
    for u, st in open_end.items():
        by_tid[sim.thread[u]["tid"]] = by_tid.get(
            sim.thread[u]["tid"], 0) + len(st)
    print("SIM by tid:", sorted(by_tid.items()))
    # TP comparison
    from tp import open_tp, query
    tp = open_tp(SAMPLE)
    rows = query(tp, "select t.tid, s.name, s.ts from slice s join "
                     "thread_track tt on s.track_id=tt.id join thread t "
                     "on tt.utid=t.utid where s.dur=-1")
    print(f"TP open slices: {len(rows)}")
    tp_tids = {}
    for r in rows:
        tp_tids[r["tid"]] = tp_tids.get(r["tid"], 0) + 1
    print("TP by tid:", sorted(tp_tids.items()))
    # (tid,name) multiset diff
    from collections import Counter
    sim_c = Counter()
    for u, st in open_end.items():
        for nm, _t in st:
            sim_c[(sim.thread[u]["tid"], nm)] += 1
    tp_c = Counter((r["tid"], r["name"]) for r in rows)
    print("missing (in TP not sim):",
          dict((tp_c - sim_c).most_common(10)))
    print("extra (in sim not TP):",
          dict((sim_c - tp_c).most_common(10)))
    tp.close()


if __name__ == "__main__":
    main()
