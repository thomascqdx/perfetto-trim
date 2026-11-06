"""TP v57.2 semantics: systrace parse/identity (systrace_parser.h/.cc,
process_tracker.cc), process_tree at packet ts (system_probes_parser),
statsd per-atom ts (statsd_module.cc), tail-mode dispatch, and the
pre-pass that feeds lagging pt/frame items in ts order."""
import pytest

from pftrim import engine, fields
from pftrim.engine import Options, Window, run
from pftrim.state import BoundaryTracker
from pftrim.wire import WT_LEN, WT_VARINT, len_field, varint_field
from tests.synthetic import builder as sb

TP = fields.TracePacket


def _ev(buf):
    return len_field(fields.PrintFtraceEvent.BUF, buf)


def _at(buf, pid=973):
    return engine._atrace_item(None, pid, _ev(buf), 0, b"e")


# ------------------------------------------------------- buf parsing
def test_b_requires_tgid():
    assert _at(b"B|notdigits")[0] == "tick"     # field1 not a number
    it = _at(b"B|0|name")
    assert it[0] == "B" and it[2] == 0          # tgid 0 -> GOC path
    it = _at(b"B|42|some slice")
    assert it[0] == "B" and it[2] == 42 and it[3] == b"some slice"


def test_e_variants_always_parse():
    assert _at(b"E")[0] == "E"                  # bare E
    assert _at(b"E|")[0] == "E"                 # E| empty tgid -> 0
    it = _at(b"E|777")
    assert it[0] == "E" and it[2] == 777
    it = _at(b"E|777\n")                        # trailing \n stripped
    assert it[2] == 777


def test_sf_require_cookie():
    assert _at(b"S|5|job")[0] == "tick"         # no cookie field
    assert _at(b"S|5|job|abc")[0] == "tick"     # bad cookie
    assert _at(b"S||job|1")[0] == "tick"        # no tgid
    it = _at(b"S|5|job|42")
    assert it[0] == "async" and it[4] == 42 and it[7] is True
    it = _at(b"F|5|job|42")
    assert it[0] == "async" and it[7] is False


def test_c_and_kill_one():
    it = _at(b"C|8252|force_ctrl|99")
    assert it[0] == "c" and it[3] == b"force_ctrl" and it[4] == 99
    assert _at(b"C|8252|badval|xx")[0] == "tick"
    # kill_one_process stays "c" -- the value-as-pid special case lives
    # in BoundaryTracker.apply (GetOrCreateProcess(value)).
    it = _at(b"C|7|kill_one_process|1234")
    assert it[0] == "c" and it[4] == 1234


def test_other_phases_are_noops():
    assert _at(b"trace_event_clock_sync: foo")[0] == "tick"
    assert _at(b"|1|x")[0] == "tick"            # empty field 0
    assert _at(b"Z|1|x")[0] == "tick"


def test_i_and_n_items():
    assert _at(b"I|5|instant")[0] == "res"
    assert _at(b"I||instant")[0] == "tick"      # I needs tgid
    assert _at(b"N|5|track|name")[0] == "np"
    assert _at(b"N|5|track")[0] == "tick"       # N needs name too


# ------------------------------------------------------- identity
def test_pid_zero_preregistered_swapper():
    tr = BoundaryTracker()
    assert tr.pids[0] == 0
    assert tr.tids[0] == [0]
    assert tr.procs[0]["pid"] == 0


def test_c_zero_tgid_creates_nothing():
    tr = BoundaryTracker()
    # C|0|cluster0 ceiling_freq emitted from tid 973: GOCProc(0) hits
    # the swapper, GetThreadOrNull(973) must NOT create a utid.
    tr.apply(100, ("c", 973, 0, b"cluster0 ceiling_freq", 5, b"e", 0))
    assert 973 not in tr.tids
    assert dict(tr.procs) == {0: tr.procs[0]}      # only swapper


def test_c_nonzero_creates_process_and_main_only():
    tr = BoundaryTracker()
    tr.apply(100, ("c", 973, 8252, b"force_ctrl", 1, b"e", 0))
    upid = tr.pids[8252]
    assert tr.procs[upid]["main"] is not None      # UpdateThread(8252,8252)
    assert 8252 in tr.tids                          # main utid
    assert 973 not in tr.tids                       # GTON, no create


def test_sf_create_process_only():
    tr = BoundaryTracker()
    tr.apply(100, ("async", 500, 777, b"job", 42, b"e", 0, True))
    assert 777 in tr.pids
    assert 500 not in tr.tids                       # NO thread call


def test_named_creates_proc_and_thread():
    tr = BoundaryTracker()
    tr.apply(100, ("named", 500, 777, b"trk", b"nm", 9, b"e", 0, True))
    assert 777 in tr.pids
    assert 500 in tr.tids                           # GetOrCreateThread


def test_kill_one_process_registers_target():
    tr = BoundaryTracker()
    tr.apply(100, ("c", 700, 800, b"kill_one_process", 4242, b"e", 0))
    assert 4242 in tr.pids                          # GOCProc(value)
    assert 800 in tr.pids                           # GOCProc(tgid)
    assert 700 not in tr.tids                       # GTON, no create


def test_bare_e_uses_gton_no_create():
    tr = BoundaryTracker()
    tr.apply(100, ("E", 999, 0, b"e", 0))
    assert 999 not in tr.tids


def test_pt_reparent_starts_new_process():
    tr = BoundaryTracker()
    tr.apply(100, ("pt", [(100, 1, True, False)], []))
    up1 = tr.pids[100]
    tr.apply(200, ("pt", [(100, 2, True, False)], []))
    up2 = tr.pids[100]
    assert up1 != up2                                # new incarnation
    assert tr.procs[up1]["end"] is not None          # old one ended


def test_pt_processes_before_threads_ordering():
    """G1 regression: pt applied at PACKET ts reorders incarnations.

    pt@100 declares tid 3885 under pid 3514; C|3885 from tid 210 at
    ts=200 creates proc 3885 (+ its main utid for tid 3885). Pushed in
    file order (200 first, 100 second) the buffer still releases by
    ts, so a bare E@300 pops the NEWER utid (proc 3885) -- TP leaks the
    systemui slice the same way."""
    tr = BoundaryTracker()
    rel = tr.push(200, (200, ("c", 210, 3885, b"queue_fps", 1, b"e", 0)))
    rel += tr.push(100, (100, ("pt", [(3514, 1, True, False)],
                              [(3885, 3514)])))
    rel += tr.push(250, (250, ("B", 3885, 3514, b"Draw", b"e", 0)))
    rel += tr.push(300, (300, ("E", 3885, 0, b"e", 0)))
    rel += tr.drain()
    for rts, ritem in rel:
        tr.apply(rts, ritem)
    # utid1: proc3514's thread 3885 still has "Draw" pending (leaked);
    # the bare E popped utid2's (empty) stack, exactly like TP.
    u1 = tr.tids[3885][0]
    u2 = tr.tids[3885][1]
    assert tr.procs[tr.thread[u1]["upid"]]["pid"] == 3514
    assert tr.procs[tr.thread[u2]["upid"]]["pid"] == 3885
    assert [e[1] for e in tr.track_stack[u1]] == [b"Draw"]
    assert not tr.track_stack.get(u2)


# ------------------------------------------------------- pre-pass
def _pt_packet_bytes(ts):
    procs = len_field(fields.ProcessTree.PROCESSES,
                      varint_field(fields.ProcessTree.Process.PID, 55)
                      + varint_field(fields.ProcessTree.Process.PPID, 1)
                      + len_field(fields.ProcessTree.Process.CMDLINE,
                                  b"/system/bin/x"))
    inner = procs
    return varint_field(TP.TIMESTAMP, ts) + len_field(TP.PROCESS_TREE,
                                                      inner)


def _frame_packet_bytes(ts, cookie, end=False):
    sub = 5 if end else 1  # FRAME_END / EXPECTED_DISPLAY_FRAME_START
    inner = len_field(sub, varint_field(1, cookie))
    return varint_field(TP.TIMESTAMP, ts) + \
        len_field(TP.FRAME_TIMELINE_EVENT, inner)


def test_prepass_collects_pt_and_frame_by_packet_ts(tmp_path):
    # ftrace FIRST in file, pt/frame packets AFTER them but with
    # earlier packet ts -> pre-pass must still return them queued by ts.
    evs = [sb.print_event(200, 1, "B|1|x")]
    path = sb.write_trace(tmp_path / "t.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)),
        sb.packet_field(_pt_packet_bytes(100)),
        sb.packet_field(_frame_packet_bytes(150, 7)),
    ])
    q, ps = engine._prepass(str(path), None)
    kinds = [it[2][0] for it in q]
    assert kinds == ["pt", "frame"]
    assert [it[0] for it in q] == [100, 150]          # sorted by ts
    assert q[0][2][1][0][0] == 55                      # proc pid
    assert q[1][2][1] == 7                             # frame cookie
    assert ps == []


# ------------------------------------------------------- statsd split
def _statsd_packet_bytes(packet_ts, atoms):
    """atoms: [(atom_bytes, inner_ts_or_None)]."""
    inner = b""
    n_ts = 0
    for a, t in atoms:
        if t is not None:
            inner += len_field(1, a)
    for a, t in atoms:
        if t is None:
            inner += len_field(1, a)
    for a, t in atoms:
        if t is not None:
            inner += varint_field(2, t)
    return varint_field(TP.TIMESTAMP, packet_ts) + \
        len_field(TP.STATSD_ATOM, inner)


def _atoms_in(path):
    out = []
    from pftrim.reader import iter_packets
    for rec in iter_packets(str(path), expand_compressed=True):
        if rec.field_no != fields.Trace.PACKET:
            continue
        for fno, wt, val, _s, _e in engine.iter_fields(rec.payload):
            if fno == TP.STATSD_ATOM and wt == WT_LEN:
                out += engine._statsd_atom_ts(val, None)
    return out


def test_statsd_per_atom_window_split(tmp_path):
    pkt = _statsd_packet_bytes(
        200, [(b"atomA", 100), (b"atomB", 200), (b"atomC", 300)])
    path = sb.write_trace(tmp_path / "t.perfetto-trace",
                          [sb.packet_field(pkt)])
    rep = run(str(path), [Window(0, 150), Window(150, 400)],
              str(tmp_path / "o"), Options())
    a1 = _atoms_in(rep.outputs[0].path)
    a2 = _atoms_in(rep.outputs[1].path)
    assert [x[0] for x in a1] == [100]
    assert [x[0] for x in a2] == [200, 300]


def test_tail_mode_still_dispatches_timed(tmp_path):
    """Lagging timed packet (file position past window end) must still
    be emitted -- tail mode skips only ftrace bundles."""
    evs = [sb.print_event(10_000, 1, "B|1|x")]  # ts past E+lookahead
    stat = _statsd_packet_bytes(500, [(b"atomA", 500)])
    path = sb.write_trace(tmp_path / "t.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)),
        sb.packet_field(stat),
    ])
    rep = run(str(path), [Window(0, 1_000)], str(tmp_path / "o"),
              Options())
    assert [x[0] for x in _atoms_in(rep.outputs[0].path)] == [500]


def test_lagging_frame_carried_in(tmp_path):
    """frame packet at FILE END with ts BEFORE the window: pre-pass
    queues it, tracker sees it open at S -> verbatim carry-in."""
    evs = [sb.print_event(8_000, 1, "B|1|x"),
           sb.print_event(9_000, 1, "E|1")]
    fpkt = _frame_packet_bytes(5_000, 7)
    path = sb.write_trace(tmp_path / "t.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)),
        sb.packet_field(fpkt),
    ])
    rep = run(str(path), [Window(6_000, 9_500)], str(tmp_path / "o"),
              Options())
    out = open(rep.outputs[0].path, "rb").read()
    assert fpkt[len(varint_field(TP.TIMESTAMP, 5_000)):] in out or \
        fpkt in out
import pytest

from pftrim.state import BoundaryTracker
from pftrim import engine


# -------------------------------------------- strtoul / strtoll rules
def test_tgid_strtoul_syntax():
    # strtoul: leading ws ok, +/- ok, whole field must be digits
    assert _at(b"B| 12|x")[2] == 12
    assert _at(b"B|+5|x")[2] == 5
    assert _at(b"B|-100|x")[2] == (2**32 - 100) % 2**32  # 4294967196
    assert _at(b"B|12 |x")[0] == "tick"      # trailing junk -> no tgid
    assert _at(b"B|12a|x")[0] == "tick"
    assert _at(b"B||x")[0] == "tick"         # empty -> no tgid


def test_tgid_saturation():
    it = _at(b"B|99999999999|x")             # > UINT32_MAX -> saturate
    assert it[2] == 0xFFFFFFFF
    it = _at(b"B|-99999999999|x")
    assert it[2] == (2**32 - 0xFFFFFFFF) % 2**32 == 1


def test_int64_syntax_and_saturation():
    assert _at(b"C|1|n|+42")[4] == 42
    assert _at(b"C|1|n| 42")[4] == 42
    assert _at(b"C|1|n|42 ")[0] == "tick"    # trailing junk
    assert _at(b"C|1|n|9223372036854775808")[4] == 2**63 - 1
    assert _at(b"C|1|n|-9223372036854775809")[4] == -(2**63)


def test_nul_separator_and_b_rest_name():
    # fields split on | OR \0; B name = REST of buf after field 1,
    # verbatim (interior \0 preserved, str.substr semantics)
    it = _at(b"B|7|name|with|pipes")
    assert it[3] == b"name|with|pipes"
    it = _at(b"C|7|nm\x0042")                 # \0 separates fields
    assert it[0] == "c" and it[4] == 42
    it = _at(b"B|7|nm\x00rest")
    assert it[3] == b"nm\x00rest"             # name keeps raw bytes


def test_h_cookie_field4_or_3():
    # H: cookie = field4 if non-empty else field3
    it = _at(b"H|9|trk|nm|11|22")
    assert it[0] == "named" and it[5] == 11   # field4 wins
    it = _at(b"H|9|trk||33")
    assert it[0] == "named" and it[5] == 33   # f3 empty -> f4
    assert _at(b"H|9|trk|nm||22")[0] == "tick"  # f4 empty, f3 bad


# --------------------------------------------------------- rss tracker
def _rss(pid, member, size, curr=None, mm_id=None):
    return ("rss", pid, member, size, curr, mm_id, b"e", 0)


def test_rss_goc_without_mm():
    tr = BoundaryTracker()
    tr.apply(100, _rss(500, 1, 1000))        # no curr/mm_id -> GOC
    u = tr.tids[500][-1]
    assert tr.rss_last[(u, 1)] == (100, 1000, None, None)


def test_rss_mm_map_set_use_erase():
    tr = BoundaryTracker()
    tr.apply(100, _rss(500, 1, 100, curr=1, mm_id=9))
    u1 = tr.tids[500][-1]
    assert tr.mm_map[9] == u1                 # curr=1 sets the map
    tr.apply(200, _rss(500, 1, 200, curr=0, mm_id=9))
    assert tr.rss_last[(u1, 1)][0] == 200     # curr=0 resolves via map
    # kill owner -> dead owner erased, no row
    tr.apply(300, ("free", 500))
    tr.apply(400, _rss(500, 1, 300, curr=0, mm_id=9))
    assert 9 not in tr.mm_map
    assert tr.rss_last[(u1, 1)][0] == 200     # stale row untouched
    # unmapped mm_id with curr=0 -> no row at all
    tr.apply(500, _rss(500, 1, 999, curr=0, mm_id=77))
    assert not any(k[1] == 1 and v[1] == 999
                   for k, v in tr.rss_last.items())


def test_rss_negative_size_no_identity():
    tr = BoundaryTracker()
    tr.apply(100, _rss(600, 1, -5, curr=1, mm_id=3))
    assert 600 not in tr.tids                 # NO identity effect
    assert tr.rss_last == {}


# ------------------------------------------------------ carry-in emit
def test_rss_event_builder_mm_id():
    ev = engine._rss_event(500, 1, 1000, 9)
    # FtraceEvent: ts(1) pid(2) rss_stat(313){member1,size2,curr3,mm4}
    assert engine.varint_field(2, 500) in ev
    ev2 = engine._rss_event(500, 1, 1000, None)
    assert len(ev2) < len(ev)                 # no curr/mm_id fields


# ---------------------------------------------------- ps/rss dedupe
def _ps_pkt(ts, pid, **kw):
    """process_stats packet: one Process entry with given counters."""
    PS = fields.ProcessStats
    sub = varint_field(PS.Process.PID, pid)
    for name, val in kw.items():
        sub += varint_field(getattr(PS.Process, name), val)
    inner = len_field(PS.PROCESSES, sub) + \
        varint_field(PS.COLLECTION_END_TIMESTAMP, ts)
    return varint_field(TP.TIMESTAMP, ts) + \
        len_field(TP.PROCESS_STATS, inner)


def _rss_ev(ts, pid, size=500):
    """pb2 RSS_STAT ftrace event (member=rss.anon, curr=1, mm_id=7)."""
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb
    return pb.FtraceEvent(
        timestamp=ts, pid=pid,
        rss_stat=pb.RssStatFtraceEvent(
            member=1, size=size, curr=1, mm_id=7))


def _pt_pkt(ts, pid):
    """process_tree packet declaring process pid (with cmdline)."""
    PT = fields.ProcessTree
    inner = len_field(PT.PROCESSES,
                      varint_field(PT.Process.PID, pid)
                      + varint_field(PT.Process.PPID, 1)
                      + len_field(PT.Process.CMDLINE, b"/x"))
    return varint_field(TP.TIMESTAMP, ts) + \
        len_field(TP.PROCESS_TREE, inner)


def test_ps_rss_dedupe_rss_newer_strips_ps(tmp_path):
    # ps@100 anon=999, rss@300 size=500 (pid500 has a process via pt)
    # -> rss newer -> ps field stripped from the merged carry-in.
    evs = [_rss_ev(300, 500)]
    path = sb.write_trace(tmp_path / "a.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)),
        sb.packet_field(_pt_pkt(50, 500)),
        sb.packet_field(_ps_pkt(100, 500, RSS_ANON_KB=999,
                                VM_SWAP_KB=42)),
    ])
    rep = run(str(path), [Window(450, 2000)], str(tmp_path / "o"),
              Options())
    data = open(rep.outputs[0].path, "rb").read()
    PS = fields.ProcessStats
    assert varint_field(PS.Process.RSS_ANON_KB, 999) not in data
    assert varint_field(PS.Process.VM_SWAP_KB, 42) in data  # kept


def test_ps_rss_dedupe_ps_newer_drops_rss(tmp_path):
    # rss@100 without curr/mm_id (GetOrCreateThread path, no mm mapping
    # to replay), ps@300 anon=999 -> ps newer -> ps field kept, no rss row
    from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb
    evs = [pb.FtraceEvent(timestamp=100, pid=500, rss_stat=pb.RssStatFtraceEvent(
        member=1, size=500))]
    path = sb.write_trace(tmp_path / "a.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)),
        sb.packet_field(_pt_pkt(50, 500)),
        sb.packet_field(_ps_pkt(300, 500, RSS_ANON_KB=999)),
    ])
    rep = run(str(path), [Window(450, 2000)], str(tmp_path / "o"),
              Options())
    data = open(rep.outputs[0].path, "rb").read()
    PS = fields.ProcessStats
    assert varint_field(PS.Process.RSS_ANON_KB, 999) in data


def test_ps_rss_dedupe_ps_newer_with_mapping_carries_ps_value(tmp_path):
    # rss@100 curr=1 mm_id=7 (live mapping), ps@300 anon=999 -> the ps
    # value wins but the mapping must be replayed: ONE rss row carrying
    # 999 KiB with curr+mm_id, and the ps field stripped.
    evs = [_rss_ev(100, 500)]
    path = sb.write_trace(tmp_path / "a.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs)),
        sb.packet_field(_pt_pkt(50, 500)),
        sb.packet_field(_ps_pkt(300, 500, RSS_ANON_KB=999)),
    ])
    rep = run(str(path), [Window(450, 2000)], str(tmp_path / "o"),
              Options())
    data = open(rep.outputs[0].path, "rb").read()
    PS = fields.ProcessStats
    assert varint_field(PS.Process.RSS_ANON_KB, 999) not in data
    # RssStatFtraceEvent: size = field 2, mm_id = field 4
    assert varint_field(2, 999 * 1024) in data
    assert varint_field(4, 7) in data

# --------------------------------------------- adaptive reorder window
def test_scan_ftrace_max_lag(tmp_path):
    """A bundle whose earliest event lags earlier-seen ts by L -> lag L."""
    from pftrim.scan import scan, ScanResult
    evs_a = [sb.print_event(10_000, 1, "B|1|x")]
    evs_b = [sb.print_event(100, 1, "B|1|y")]   # arrives later in file
    path = sb.write_trace(tmp_path / "t.perfetto-trace", [
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs_a)),
        sb.packet_field(sb.ftrace_packet(cpu=0, events=evs_b)),
    ])
    res = scan(str(path))
    # M=10000 after bundle A; bundle B lo=100 -> lag = 10000-100
    assert res.ftrace_max_lag_ns == 9_900
    # dict round-trip + old dict without the field
    d = res.to_dict()
    assert d["ftrace_max_lag_ns"] == 9_900
    del d["ftrace_max_lag_ns"]
    assert ScanResult.from_dict(d).ftrace_max_lag_ns == 0


def test_resolve_reorder_ns_clamps():
    class _S:
        ftrace_max_lag_ns = 0
    s = _S()
    s.ftrace_max_lag_ns = 1_000_000_000
    assert engine.resolve_reorder_ns(s) == (2_000_000_000, 1_000_000_000)
    s.ftrace_max_lag_ns = 5_000_000_000
    assert engine.resolve_reorder_ns(s) == (5_250_000_000, 5_000_000_000)
    s.ftrace_max_lag_ns = 40_000_000_000
    assert engine.resolve_reorder_ns(s) == (30_000_000_000,
                                            40_000_000_000)


def test_options_none_falls_back_to_2s(tmp_path):
    tr = BoundaryTracker()
    assert tr.buf is not None   # sanity
    opts = engine.Options()
    assert opts.reorder_window_ns is None

def test_end_thread_pid_rule():
    """TP EndThread: proc ends iff freed tid == process.pid; pids_
    erased so a later GetOrCreateProcess makes a NEW process."""
    tr = BoundaryTracker()
    tr.apply(100, ("pt", [(500, 1, True, False)], []))
    up1 = tr.pids[500]
    tr._update_thread(500, 500)     # 2nd incarnation, tid still == pid
    tr.apply(200, ("free", 500))
    assert tr.procs[up1]["end"] == 200
    assert 500 not in tr.pids       # pids_ erased
    tr._goc_proc(500)
    assert tr.pids[500] != up1      # NEW process
    # freeing a non-pid thread of a process does NOT end it
    tr.apply(300, ("pt", [(700, 1, True, False)], []))
    tr.apply(400, ("free", 701))    # tid 701 not a pid
    assert tr.pids[700] is not None
    assert tr.procs[tr.pids[700]]["end"] is None


def test_free_event_pid_field():
    """sched_process_free is {comm=1, pid=2}: engine_bundle must end
    the pid's thread, NOT tid 0 (the old field-1 read produced
    ("free", 0) which killed the swapper)."""
    from perfetto.protos.perfetto.trace import (
        perfetto_trace_pb2 as pb)
    ev = pb.FtraceEvent(timestamp=100, pid=999)
    ev.sched_process_free.comm = "deadproc"
    ev.sched_process_free.pid = 500
    bundle = pb.FtraceEventBundle(cpu=0)
    bundle.event.append(ev)
    cpu_, items, *_ = engine.engine_bundle(
        bundle.SerializeToString(), 1, 1, [])
    assert (100, ("free", 500)) in items, items
    # apply through tracker: pid 500's proc ends, swapper untouched
    tr = BoundaryTracker()
    tr.apply(50, ("pt", [(500, 1, True, False)], []))
    for ts, item in items:
        if ts is not None:
            tr.apply(ts, item)
    assert 0 in tr.pids               # swapper still alive
    assert tr.ended_pids == {500}
    assert 500 not in tr.pids
