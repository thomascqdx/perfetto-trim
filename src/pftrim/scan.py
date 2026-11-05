"""First-pass streaming scan of a trace: bounds, stats, histogram, markers.

trace_bounds parity (mirrors trace_processor v57
TraceStorage::GetTraceTimestampBoundsNs / trace_processor_impl.cc):
bounds are min/max over the *timestamps that land in ts-bearing tables*,
i.e.

  - every ftrace event timestamp (full events + compact_sched switch and
    waking), converted to BOOTTIME via the bundle's ftrace_clock rule
    (FtraceTokenizer::HandleFtraceClockSnapshot) -- this covers
    sched_slice, slice and the raw ftrace_event table;
  - every android_log LogEvent.timestamp;
  - the packet timestamp for "timed data" packets (counters, slices,
    samples: sys_stats, process_stats, battery, power_rails, perf_sample,
    track_event, frame timeline, gpu events, profile/heapprofd packets,
    statsd atoms, kernel wakelocks, chrome/etw events, ...);
  - NOT metadata packets (clock_snapshot, trace_config, process_tree,
    system_info, packages_list, service_event, ftrace_stats, trace_stats,
    trace_packet_defaults, interned_data, track_descriptor, cpu_info,
    inode_file_map, synchronization_marker, triggers, uuid/machine_id,
    translation/symbol tables, user/game lists, ...), which fill tables
    with no timestamp column.

Event-level rules replicated from TP v57 (verified by tests):
  - events are processed in global ts order (TraceSorter); the first
    sched_switch per cpu is discarded but establishes sched state
    (compact_sched_switch_skipped), and compact wakings before the
    first switch per cpu are dropped (compact_sched_waking_skipped);
  - end bound = max(ts+dur): a state row still open at trace end has
    dur=-1, contributing ts-1 -- modeled by tracking open rows per
    entity (cpu slice / thread state / atrace B & S slices);
  - sched_wakeup (field 17) is not dispatched by TP's FtraceParser at
    all; task_newtask/task_rename produce thread rows, not ts rows
    (task_newtask DOES create an R thread_state row -> counts);
  - metadata packets never contribute, even with a packet timestamp;
  - no "drop before tracing_started" rule exists for bounds.

Density histogram: 10 ms bins on an absolute grid (bin = ts // 10ms),
accumulated in a dict and emitted as dense lists starting at
``hist_origin_ns = floor(start_ns / 10ms)`` -- O(bins) memory. Ftrace
bundle / android_log packet bytes are split evenly across their events,
other timed packets attribute their full bytes.

Memory: O(cpus + threads/slice keys + histogram bins + reorder window),
independent of trace length. Events whose bounds contribution depends
on global ts order flow through a bounded ReorderBuffer (state.py).
"""

from __future__ import annotations

import os
import time as _time
from . import fields, ftpar, ftrace
from .clock import ClockConverter
from .reader import iter_packets
from .state import ReorderBuffer
from .wire import WT_LEN, WT_VARINT, iter_fields

SCAN_FORMAT_VERSION = 2  # histogram rebased onto absolute 10 ms grid

HIST_BIN_NS = 10_000_000  # 10 ms
MAX_MARKERS = 5000

_TP = fields.TracePacket

# TracePacket field numbers that never contribute their packet timestamp
# to trace bounds (metadata / bookkeeping tables without a ts column).
META_FIELDS = frozenset({
    _TP.PROCESS_TREE, _TP.INODE_FILE_MAP, _TP.CLOCK_SNAPSHOT,
    _TP.TRACE_CONFIG, _TP.SYSTEM_INFO, _TP.PACKAGES_LIST,
    _TP.SERVICE_EVENT, _TP.FTRACE_STATS, _TP.TRACE_STATS,
    _TP.TRACE_PACKET_DEFAULTS, _TP.INTERNED_DATA, _TP.TRACK_DESCRIPTOR,
    _TP.MODULE_SYMBOLS, _TP.DEOBFUSCATION_MAPPING, _TP.CPU_INFO,
    _TP.EXTENSION_DESCRIPTOR, _TP.TRANSLATION_TABLE, _TP.TRACE_PROVENANCE,
    _TP.TRACE_ATTRIBUTES, _TP.SYNCHRONIZATION_MARKER, _TP.MACHINE_ID,
    _TP.TRACE_UUID, _TP.REMOTE_CLOCK_SYNC, _TP.CLONE_SNAPSHOT_TRIGGER,
    _TP.TRIGGER, _TP.CHROME_METADATA, _TP.CHROME_BENCHMARK_METADATA,
    _TP.PERFETTO_METATRACE, _TP.INITIAL_DISPLAY_STATE,
    _TP.PIXEL_MODEM_TOKEN_DATABASE, _TP.PROTOVMS, _TP.USER_LIST,
    _TP.GENERIC_KERNEL_PROCESS_TREE, _TP.ANDROID_SYSTEM_PROPERTY,
    _TP.ANDROID_GAME_INTERVENTION_LIST, _TP.ANDROID_AFLAGS,
})

_FLAG_FIELDS = {
    _TP.ANDROID_LOG: "has_logcat",
    _TP.TRACK_EVENT: "has_track_event",
    _TP.TRACK_DESCRIPTOR: "has_track_event",
    _TP.GRAPHICS_FRAME_EVENT: "has_frame_timeline",
    _TP.FRAME_TIMELINE_EVENT: "has_frame_timeline",
    _TP.PROFILE_PACKET: "has_heapprofd",
    _TP.STREAMING_PROFILE_PACKET: "has_heapprofd",
    _TP.PERF_SAMPLE: "has_perf",
    _TP.BATTERY: "has_battery",
    _TP.POWER_RAILS: "has_power_rails",
}

# TracePacket head/bookkeeping fields -- never "data types", never
# contribute packet timestamps to bounds.
_HEAD_FIELDS = frozenset({
    _TP.TIMESTAMP, _TP.TIMESTAMP_CLOCK_ID, _TP.TRUSTED_UID,
    _TP.TRUSTED_PACKET_SEQUENCE_ID, _TP.TRUSTED_PID, _TP.SEQUENCE_FLAGS,
    _TP.INCREMENTAL_STATE_CLEARED, _TP.PREVIOUS_PACKET_DROPPED,
    _TP.FIRST_PACKET_ON_SEQUENCE, _TP.TRACE_UUID, _TP.MACHINE_ID,
    _TP.TRACE_PACKET_DEFAULTS, _TP.CLOCK_SNAPSHOT, _TP.COMPRESSED_PACKETS,
})

# Ftrace event names that produce ts-bearing rows in trace_processor
# (sched_slice / thread_state / slice / counter / instant) and therefore
# contribute to trace_bounds. Unparsed events (e.g. sched_wakeup -- not
# dispatched by TP v57's FtraceParser) and metadata-only events
# (task_newtask/task_rename -> thread name rows, no ts column) do NOT
# contribute. This allowlist covers the events that dominate Android
# traces; exotic events may make TP bounds slightly wider than ours.
_BOUNDS_FTRACE_NAMES = frozenset({
    "sched_switch", "sched_waking", "task_newtask",
    "cpu_frequency", "cpu_frequency_limits", "cpu_idle",
    "print",
    "rss_stat", "rss_stat_throttled",
    "thermal_temperature", "cdev_update",
    "devfreq_frequency", "gpu_frequency", "kgsl_gpu_frequency",
    "ion_heap_grow", "ion_heap_shrink", "ion_stat",
    "dma_heap_stat", "dmabuf_rss_stat",
    "mm_event_record", "oom_score_adj_update", "mark_victim",
    "signal_generate", "signal_deliver",
    "sys_enter", "sys_exit",
    "workqueue_execute_start", "workqueue_execute_end",
    "irq_handler_entry", "irq_handler_exit",
    "softirq_entry", "softirq_exit",
    "local_timer_entry", "local_timer_exit",
    "wakeup_source_activate", "wakeup_source_deactivate",
    "suspend_resume", "suspend_resume_minimal",
    "tracing_mark_write",
    "gpu_work_period", "gpu_power_state", "mali_gpu_power_state",
    "fwtp_perfetto_counter", "fwtp_perfetto_slice",
    "block_io_start", "block_io_done",
    "drm_vblank_event", "drm_vblank_event_delivered",
    "hrtimer_expire_entry", "hrtimer_expire_exit",
    "cpuhp_enter", "cpuhp_exit", "cpuhp_pause", "cpuhp_multi_enter",
    "netif_receive_skb", "net_dev_xmit", "inet_sock_set_state",
    "tcp_retransmit_skb", "napi_gro_receive_entry", "napi_gro_receive_exit",
    "kfree_skb",
})




class TypeStats:
    __slots__ = ("count", "bytes", "min_ts", "max_ts")

    def __init__(self):
        self.count = 0
        self.bytes = 0
        self.min_ts = None
        self.max_ts = None

    def add(self, nbytes: int, ts) -> None:
        self.count += 1
        self.bytes += nbytes
        if ts is not None:
            if self.min_ts is None or ts < self.min_ts:
                self.min_ts = ts
            if self.max_ts is None or ts > self.max_ts:
                self.max_ts = ts

    def to_dict(self):
        return {"count": self.count, "bytes": self.bytes,
                "min_ts": self.min_ts, "max_ts": self.max_ts}

    @classmethod
    def from_dict(cls, d):
        s = cls()
        s.count, s.bytes, s.min_ts, s.max_ts = (
            d["count"], d["bytes"], d.get("min_ts"), d.get("max_ts"))
        return s


class CpuStats:
    __slots__ = ("events", "first_ts", "last_ts")

    def __init__(self):
        self.events = 0
        self.first_ts = None
        self.last_ts = None

    def to_dict(self):
        return {"events": self.events, "first_ts": self.first_ts,
                "last_ts": self.last_ts}

    @classmethod
    def from_dict(cls, d):
        s = cls()
        s.events, s.first_ts, s.last_ts = \
            d["events"], d.get("first_ts"), d.get("last_ts")
        return s


class SeqStats:
    __slots__ = ("packets", "incremental", "incremental_resets", "data_types")

    def __init__(self):
        self.packets = 0
        self.incremental = False
        self.incremental_resets = 0
        self.data_types = set()

    def to_dict(self):
        return {"packets": self.packets, "incremental": self.incremental,
                "incremental_resets": self.incremental_resets,
                "data_types": sorted(self.data_types)}

    @classmethod
    def from_dict(cls, d):
        s = cls()
        s.packets = d["packets"]
        s.incremental = d["incremental"]
        s.incremental_resets = d["incremental_resets"]
        s.data_types = set(d["data_types"])
        return s


class ScanResult:
    def __init__(self):
        self.path = ""
        self.file_size = 0
        self.file_mtime_ns = 0
        self.gzip = False
        self.had_compressed_packets = False
        self.packet_count = 0
        self.start_ns = None
        self.end_ns = None
        self.per_type: dict[str, TypeStats] = {}
        self.ftrace = {
            "bundles": 0,
            "lost_events": 0,
            "event_counts": {},          # name -> count (incl. compact)
            "compact_switch_events": 0,
            "compact_waking_events": 0,
            "per_cpu": {},               # cpu -> CpuStats
        }
        self.hist_bin_ns = HIST_BIN_NS
        self.hist_origin_ns = 0  # bins cover [origin, origin+n*bin_ns)
        self.hist_bin_bytes: list[int] = []
        self.hist_bin_events: list[int] = []
        self.untimed_bytes = 0
        self.untimed_packets = 0
        self.sequences: dict[int, SeqStats] = {}
        self.markers: list[dict] = []
        self.markers_truncated = False
        self.flags: dict[str, bool] = {}
        self.warnings: dict[str, int] = {}
        self.trace_config = None
        self.scan_time_s = 0.0
        self.cache_hit = False

    @property
    def duration_ns(self):
        if self.start_ns is None or self.end_ns is None:
            return 0
        return self.end_ns - self.start_ns

    def to_dict(self) -> dict:
        return {
            "version": SCAN_FORMAT_VERSION,
            "path": self.path,
            "file_size": self.file_size,
            "file_mtime_ns": self.file_mtime_ns,
            "gzip": self.gzip,
            "had_compressed_packets": self.had_compressed_packets,
            "packet_count": self.packet_count,
            "start_ns": self.start_ns,
            "end_ns": self.end_ns,
            "per_type": {k: v.to_dict() for k, v in self.per_type.items()},
            "ftrace": {
                **{k: v for k, v in self.ftrace.items() if k != "per_cpu"},
                "per_cpu": {str(k): v.to_dict()
                            for k, v in self.ftrace["per_cpu"].items()},
            },
            "hist_bin_ns": self.hist_bin_ns,
            "hist_origin_ns": self.hist_origin_ns,
            "hist_bin_bytes": self.hist_bin_bytes,
            "hist_bin_events": self.hist_bin_events,
            "untimed_bytes": self.untimed_bytes,
            "untimed_packets": self.untimed_packets,
            "sequences": {str(k): v.to_dict()
                          for k, v in self.sequences.items()},
            "markers": self.markers,
            "markers_truncated": self.markers_truncated,
            "flags": self.flags,
            "warnings": self.warnings,
            "trace_config": self.trace_config,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        r = cls()
        for k in ("path", "file_size", "file_mtime_ns", "gzip",
                  "had_compressed_packets", "packet_count", "start_ns",
                  "end_ns", "hist_bin_ns", "hist_origin_ns",
                  "hist_bin_bytes",
                  "hist_bin_events", "untimed_bytes", "untimed_packets",
                  "markers", "markers_truncated", "flags", "warnings",
                  "trace_config"):
            setattr(r, k, d[k])
        r.per_type = {k: TypeStats.from_dict(v)
                      for k, v in d["per_type"].items()}
        ft = d["ftrace"]
        r.ftrace = {k: v for k, v in ft.items() if k != "per_cpu"}
        r.ftrace["per_cpu"] = {int(k): CpuStats.from_dict(v)
                               for k, v in ft["per_cpu"].items()}
        r.sequences = {int(k): SeqStats.from_dict(v)
                       for k, v in d["sequences"].items()}
        return r


def _iter_log_timestamps(payload):
    """Yield each AndroidLogPacket.LogEvent.timestamp."""
    le = fields.AndroidLogPacket.LogEvent
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno == fields.AndroidLogPacket.EVENTS and wt == WT_LEN:
            for efno, ewt, eval_, _es, _ee in iter_fields(val):
                if efno == le.TIMESTAMP and ewt == WT_VARINT:
                    yield eval_


def _parse_trace_config(payload) -> dict:
    tc = fields.TraceConfig
    out = {"duration_ms": None, "buffer_size_kb": [], "data_sources": []}
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno == tc.DURATION_MS and wt == WT_VARINT:
            out["duration_ms"] = val
        elif fno == tc.BUFFERS and wt == WT_LEN:
            for bfno, bwt, bval, _bs, _be in iter_fields(val):
                if bfno == tc.BufferConfig.SIZE_KB and bwt == WT_VARINT:
                    out["buffer_size_kb"].append(bval)
        elif fno == tc.DATA_SOURCES and wt == WT_LEN:
            for dfno, dwt, dval, _ds, _de in iter_fields(val):
                if dfno == tc.DataSource.CONFIG and dwt == WT_LEN:
                    for cfno, cwt, cval, _cs, _ce in iter_fields(dval):
                        if cfno == fields.DataSourceConfig.NAME \
                                and cwt == WT_LEN:
                            out["data_sources"].append(
                                bytes(cval).decode("utf-8", "replace"))
    return out


class _Bounds:
    """trace_bounds contribution tracker.

    Mirrors TP's end-bound rule (max ts+dur over ts-bearing tables):
      - point(ts): instant rows (counters, instants, packet-ts, log rows);
      - transition(key, ts): a sched/thread/slice state change -- closes
        any previous open row for `key` at ts (contributes ts), opens a
        new one;
      - close(key, ts): closes an open row (contributes ts);
      - an open row left at trace end has dur=-1 and contributes ts-1.

    start = min over all contribution ts; end = max(closed ts, open ts-1).
    """

    __slots__ = ("min_ts", "closed_max", "open_state")

    def __init__(self):
        self.min_ts = None
        self.closed_max = None
        self.open_state: dict = {}

    def point(self, ts):
        if self.min_ts is None or ts < self.min_ts:
            self.min_ts = ts
        if self.closed_max is None or ts > self.closed_max:
            self.closed_max = ts

    def transition(self, key, ts):
        if self.min_ts is None or ts < self.min_ts:
            self.min_ts = ts
        if key in self.open_state:
            if self.closed_max is None or ts > self.closed_max:
                self.closed_max = ts
        self.open_state[key] = ts

    def close(self, key, ts):
        if key not in self.open_state:
            return False
        del self.open_state[key]
        if self.min_ts is None or ts < self.min_ts:
            self.min_ts = ts
        if self.closed_max is None or ts > self.closed_max:
            self.closed_max = ts
        return True

    def bounds(self):
        if self.min_ts is None:
            return (None, None)
        end = self.closed_max
        if self.open_state:
            om = max(self.open_state.values()) - 1
            end = om if end is None else max(end, om)
        if end is None:
            end = self.min_ts  # unreachable in practice
        if end == self.min_ts:
            end += 1  # TP pins a collapsed interval to start+1
        return (self.min_ts, end)


def _varint_field(payload, want):
    for fno, wt, val, _s, _e in iter_fields(payload):
        if fno == want and wt == WT_VARINT:
            return val
    return None


class _NeedsClock(Exception):
    """A bundle needs the main-process ClockConverter: rerun serially."""


def scan(path, *, progress=None, jobs=None, cancel=None) -> ScanResult:
    """One streaming pass over `path`; returns a ScanResult.

    jobs > 1 decodes ftrace bundles in worker processes (results are
    folded in file order, so the result is identical to jobs=1).
    """
    path = os.fspath(path)
    jobs = ftpar.resolve_jobs(jobs)
    if ftpar.use_pool(jobs, os.path.getsize(path)):
        try:
            return _scan(path, progress, cancel, jobs)
        except _NeedsClock:
            pass  # rare non-identity ftrace clock: exact serial rerun
    return _scan(path, progress, cancel, 1)


def _scan(path, progress, cancel, jobs) -> ScanResult:
    t0 = _time.perf_counter()
    res = ScanResult()
    res.path = os.path.abspath(path)
    res.file_size = os.path.getsize(path)
    res.file_mtime_ns = os.stat(path).st_mtime_ns
    with open(path, "rb") as f:
        res.gzip = f.read(2) == b"\x1f\x8b"

    conv = ClockConverter()
    bnd = _Bounds()
    # density histogram on an absolute 10 ms grid (bin = ts // HIST_BIN_NS)
    # -- O(bins), not O(events). Emitted as dense lists at the end.
    hist: dict[int, list] = {}
    warnings: dict[str, int] = {}
    pending_launches: dict[tuple, int] = {}
    markers: list[dict] = []
    truncated = [False]

    def hist_add(ts, nbytes):
        ent = hist.get(ts // HIST_BIN_NS)
        if ent is None:
            hist[ts // HIST_BIN_NS] = [nbytes, 1]
        else:
            ent[0] += nbytes
            ent[1] += 1

    def add_marker(ts_start, ts_end, label):
        if len(markers) >= MAX_MARKERS:
            truncated[0] = True
            return
        markers.append({"ts": ts_start, "end_ts": ts_end,
                        "kind": "app_launch", "label": label})

    ft = res.ftrace
    cpu_stats: dict[int, CpuStats] = ft["per_cpu"]
    event_counts: dict[str, int] = ft["event_counts"]
    last_ts_per_cpu: dict[int, int] = {}
    # Events whose bounds contribution depends on global ts order (TP
    # sorts events via TraceSorter) flow through a bounded reorder
    # buffer -- O(events within the window) instead of O(events).
    # Item shapes:
    #   ("s", kind, cpu, prev_pid|None, pid|None, share_bytes)
    #     kind: 'fs'/'cs'/'cw'/'fw'/'nt' -- sched & thread-state events
    #   ("p", op, key, share_bytes, ts) -- atrace print events, op/key
    #     pre-classified by _print_op (transition/close/point/none)
    rb = ReorderBuffer()
    seen_cpus: set[int] = set()
    last_next_pid: dict[int, int] = {}

    def handle_released(released):
        """Apply released items in order -- _Bounds.transition / close /
        point and hist_add inlined (hot serial path)."""
        mn = bnd.min_ts
        cmax = bnd.closed_max
        open_ = bnd.open_state
        untimed = 0
        bin_ns = HIST_BIN_NS
        for item in released:
            if item[0] == "p":
                _p, op, key, nbytes, ts = item
                if op == 1:                       # transition
                    if mn is None or ts < mn:
                        mn = ts
                    if key in open_ and (cmax is None or ts > cmax):
                        cmax = ts
                    open_[key] = ts
                elif op == 2:                     # close
                    if key not in open_:
                        untimed += nbytes
                        continue
                    del open_[key]
                    if mn is None or ts < mn:
                        mn = ts
                    if cmax is None or ts > cmax:
                        cmax = ts
                elif op == 3:                     # point
                    if mn is None or ts < mn:
                        mn = ts
                    if cmax is None or ts > cmax:
                        cmax = ts
                else:
                    untimed += nbytes
                    continue
            else:
                _s, ts, s_kind, cpu, prev_pid, pid, nbytes = item
                if s_kind == "cs":
                    countable = cpu in seen_cpus
                    seen_cpus.add(cpu)
                elif s_kind == "cw":
                    countable = cpu in seen_cpus
                else:
                    countable = True
                    if s_kind == "fs":
                        seen_cpus.add(cpu)
                if not countable:
                    untimed += nbytes
                    if s_kind == "cs" and pid is not None:
                        last_next_pid[cpu] = pid  # skipped switch sets state
                    continue
                if s_kind == "fs" or s_kind == "cs":
                    if mn is None or ts < mn:
                        mn = ts
                    keys = [("cpu", cpu)]
                    prev = prev_pid if prev_pid is not None else \
                        last_next_pid.get(cpu)
                    if prev is not None:
                        keys.append(("thr", prev))
                    if pid is not None:
                        keys.append(("thr", pid))
                        last_next_pid[cpu] = pid
                    for key in keys:
                        if key in open_ and (cmax is None or ts > cmax):
                            cmax = ts
                        open_[key] = ts
                elif pid is not None:  # 'cw', 'fw', 'nt'
                    if mn is None or ts < mn:
                        mn = ts
                    key = ("thr", pid)
                    if key in open_ and (cmax is None or ts > cmax):
                        cmax = ts
                    open_[key] = ts
            ent = hist.get(ts // bin_ns)
            if ent is None:
                hist[ts // bin_ns] = [nbytes, 1]
            else:
                ent[0] += nbytes
                ent[1] += 1
        bnd.min_ts = mn
        bnd.closed_max = cmax
        res.untimed_bytes += untimed

    def apply(r, raw_len):
        _apply_bundle(r, raw_len, res, bnd, hist, cpu_stats, event_counts,
                      last_ts_per_cpu, warnings, pending_launches,
                      add_marker, rb, handle_released)

    pool = ftpar.OrderedPool(scan_batch, jobs) if jobs > 1 else None
    try:
        _scan_packets(path, progress, cancel, res, conv, bnd, hist_add,
                      apply, pool)
    finally:
        if pool is not None:
            pool.close()

    # drain the reorder buffer in ts order; count events that arrived
    # later than the window allowed them to be held back.
    handle_released(rb.drain())
    if rb.late_events:
        warnings["reorder_late_events"] = rb.late_events

    return _finish(res, bnd, hist, pending_launches, add_marker, conv,
                   warnings, markers, truncated, ft, t0)


def _scan_packets(path, progress, cancel, res, conv, bnd, hist_add, apply,
                  pool):
    def fold(done):
        for raw_len, r in done:
            if r is None:
                raise _NeedsClock()
            apply(r, raw_len)

    for rec in iter_packets(path, expand_compressed=True, progress=progress,
                            cancel=cancel):
        res.packet_count += 1
        if rec.compressed:
            res.had_compressed_packets = True
        if rec.field_no != fields.Trace.PACKET:
            continue
        raw_len = len(rec.raw)
        seq = rec.trusted_packet_sequence_id

        # --- pass over packet fields: collect head + data fields --------
        ts_raw = ts_clk = None
        seq_flags = 0
        incremental = False
        inc_resets = 0
        datas = []
        defaults_mv = None
        snapshot_mv = None
        for fno, wt, val, _s, _e in iter_fields(rec.payload):
            if fno == _TP.TIMESTAMP and wt == WT_VARINT:
                ts_raw = val
            elif fno == _TP.TIMESTAMP_CLOCK_ID and wt == WT_VARINT:
                ts_clk = val
            elif fno == _TP.SEQUENCE_FLAGS and wt == WT_VARINT:
                seq_flags = val
            elif fno == _TP.INCREMENTAL_STATE_CLEARED and wt == WT_VARINT:
                inc_resets += 1
            elif fno == _TP.INTERNED_DATA and wt == WT_LEN:
                incremental = True
            elif fno == _TP.TRACE_PACKET_DEFAULTS and wt == WT_LEN:
                defaults_mv = val
            elif fno == _TP.CLOCK_SNAPSHOT and wt == WT_LEN:
                snapshot_mv = val
            elif fno in _HEAD_FIELDS:
                pass  # bookkeeping fields: not data types
            else:
                datas.append((fno, wt, val))

        if snapshot_mv is not None:
            conv.update_snapshot(snapshot_mv)
        if defaults_mv is not None and seq is not None:
            conv.update_packet_defaults(seq, defaults_mv)

        if seq is not None:
            sst = res.sequences.get(seq)
            if sst is None:
                sst = res.sequences[seq] = SeqStats()
            sst.packets += 1
            if incremental or (seq_flags & fields.SEQ_NEEDS_INCREMENTAL_STATE):
                sst.incremental = True
            sst.incremental_resets += inc_resets + (
                1 if seq_flags & fields.SEQ_INCREMENTAL_STATE_CLEARED else 0)

        if ts_raw is None:
            packet_ts = None
        else:
            clock_id = ts_clk if ts_clk is not None else \
                conv.sequence_clock(seq)
            packet_ts = conv.to_boottime(clock_id, ts_raw)

        # --- data fields ------------------------------------------------
        attributed = False
        for fno, wt, val in datas:
            name = fields.TRACE_PACKET_FIELD_NAMES.get(fno) or \
                f"unknown_{fno}"
            if seq is not None:
                res.sequences[seq].data_types.add(name)
            flag = _FLAG_FIELDS.get(fno)
            if flag:
                res.flags[flag] = True

            if fno == _TP.FTRACE_EVENTS and wt == WT_LEN:
                # keep per_type insertion order identical to inline mode
                res.per_type.setdefault(name, TypeStats())
                if pool is None:
                    apply(scan_bundle(val, raw_len, seq, conv), raw_len)
                else:
                    fold(pool.add((bytes(val), raw_len), len(val),
                                  raw_len))
                attributed = True
            elif fno == _TP.ANDROID_LOG and wt == WT_LEN:
                st = res.per_type.setdefault(name, TypeStats())
                st.count += 1
                st.bytes += raw_len
                # TP converts LogEvent.timestamp REALTIME -> BOOTTIME;
                # unconvertible events are dropped (A1 fix).
                ts_list = [bt for bt in
                           (conv.to_boottime(
                               fields.BUILTIN_CLOCK_REALTIME, lts)
                            for lts in _iter_log_timestamps(val))
                           if bt is not None]
                n = len(ts_list)
                share = raw_len // n if n else 0
                rem = raw_len - share * n
                for i, lts in enumerate(ts_list):
                    bnd.point(lts)
                    hist_add(lts, share + (1 if i < rem else 0))
                    if st.min_ts is None or lts < st.min_ts:
                        st.min_ts = lts
                    if st.max_ts is None or lts > st.max_ts:
                        st.max_ts = lts
                attributed = True
            elif fno == _TP.TRACE_CONFIG and wt == WT_LEN:
                res.trace_config = _parse_trace_config(val)
                res.per_type.setdefault(name, TypeStats()).add(raw_len, None)
            elif fno in META_FIELDS:
                res.per_type.setdefault(name, TypeStats()).add(raw_len, None)
            elif packet_ts is not None:
                res.per_type.setdefault(name, TypeStats()).add(
                    raw_len, packet_ts)
                bnd.point(packet_ts)
                hist_add(packet_ts, raw_len)
                attributed = True
            else:
                res.per_type.setdefault(name, TypeStats()).add(raw_len, None)

        if not attributed:
            res.untimed_bytes += raw_len
            res.untimed_packets += 1
    if pool is not None:
        fold(pool.finish())


def _finish(res, bnd, hist, pending_launches, add_marker, conv, warnings,
            markers, truncated, ft, t0) -> ScanResult:
    # finalize bounds & emit dense histogram bins on the absolute grid
    res.start_ns, res.end_ns = bnd.bounds()
    if res.start_ns is not None and res.end_ns is not None:
        origin_bin = res.start_ns // HIST_BIN_NS
        n_bins = max(1, res.end_ns // HIST_BIN_NS - origin_bin + 1)
        res.hist_origin_ns = origin_bin * HIST_BIN_NS
        res.hist_bin_bytes = [0] * n_bins
        res.hist_bin_events = [0] * n_bins
        for bidx, (nb, nev) in hist.items():
            idx = bidx - origin_bin
            if 0 <= idx < n_bins:
                res.hist_bin_bytes[idx] += nb
                res.hist_bin_events[idx] += nev
        # events outside [start,end] can't happen by construction, but
        # keep conservation honest regardless.
        res.untimed_bytes += res.file_size - res.file_size  # no-op

    for (name, _cookie), ts in pending_launches.items():
        add_marker(ts, None, _label(name))

    warnings["unknown_clock"] = conv.unknown_clock_warnings
    if ft["lost_events"]:
        warnings["ftrace_lost_events"] = ft["lost_events"]
    res.warnings = {k: v for k, v in warnings.items() if v}
    res.markers = markers
    res.markers_truncated = truncated[0]
    res.scan_time_s = _time.perf_counter() - t0
    return res


def scan_bundle(payload, raw_len, seq=None, conv=None):
    """Pure per-bundle scan work (runs in worker processes).

    Returns a tuple of order-independent deltas plus the ordered
    reorder-buffer items and marker candidates (applied by
    `_apply_bundle` in file order), or None when the bundle's
    ftrace_clock needs the main process' ClockConverter (conv is None
    in workers; the main process then reruns with conv).
    """
    bv = ftrace.parse_bundle(payload)
    cpu = bv.cpu
    clk = bv.ftrace_clock
    identity = clk is None or clk == fields.FTRACE_CLOCK_UNSPECIFIED
    if conv is None:
        if not identity:
            return None
    elif (clk in (fields.FTRACE_CLOCK_GLOBAL, fields.FTRACE_CLOCK_LOCAL)
            and bv.ftrace_timestamp is not None
            and bv.boot_timestamp is not None and seq is not None):
        # sequence-scoped clock snapshot pair (GLOBAL/LOCAL), TP-style.
        conv.register_ftrace_snapshot(seq, bv.ftrace_timestamp,
                                      bv.boot_timestamp)

    # Collect (raw_ts, name, kind, aux) for all events.
    # kind: 'cs'/'cw' compact switch/waking (aux = aligned pid column),
    #       'fs'/'fw'/'nt'/'other' (aux = event payload mv for inner
    #       field parsing / print buf).
    ev_ts = []
    n_cs = n_cw = 0
    if bv.compact is not None:
        compact = ftrace.CompactSched.decode(bv.compact)
        sw_pids = compact.column(ftrace.SWITCH_NEXT_PID)
        wk_pids = compact.column(ftrace.WAKING_PID)
        nsw = len(sw_pids)
        for i, ts in enumerate(compact.switch_timestamps()):
            ev_ts.append((ts, ftrace.COMPACT_SWITCH_NAME, "cs",
                          sw_pids[i] if i < nsw else None))
        n_cs = len(ev_ts)
        nwk = len(wk_pids)
        for i, ts in enumerate(compact.waking_timestamps()):
            ev_ts.append((ts, ftrace.COMPACT_WAKING_NAME, "cw",
                          wk_pids[i] if i < nwk else None))
        n_cw = len(ev_ts) - n_cs
    names = fields.FTRACE_EVENT_NAMES
    event_meta = ftrace.event_meta
    for ev in bv.events:
        ts, _pid, etype, eval_ = event_meta(ev)
        name = names.get(etype) or f"unknown_{etype}"
        if name == "sched_switch":
            kind = "fs"
        elif name == "sched_waking":
            kind = "fw"
        elif name == "task_newtask":
            kind = "nt"
        else:
            kind = "other"
        ev_ts.append((ts, name, kind, eval_))

    counts: dict = {}
    hist: dict = {}
    items: list = []
    marks: list = []
    n_timed = ooo = untimed = 0
    tmin = tmax = first = last = pmin = pmax = None
    n = len(ev_ts)
    if n:
        share = raw_len // n
        rem = raw_len - share * n
        bin_ns = HIST_BIN_NS
        print_buf = ftrace.print_buf
        bounds_names = _BOUNDS_FTRACE_NAMES
        i = 0
        for ts_raw, name, kind, aux in ev_ts:
            i += 1
            counts[name] = counts.get(name, 0) + 1
            nbytes = share + (1 if i <= rem else 0)
            if ts_raw is None:
                untimed += nbytes
                continue
            ts = ts_raw if identity else \
                conv.ftrace_to_boottime(clk, seq, ts_raw)
            if ts is None:
                untimed += nbytes
                continue
            n_timed += 1
            if first is None:
                first = tmin = tmax = ts
            else:
                if ts < last:
                    ooo += 1
                if ts < tmin:
                    tmin = ts
                elif ts > tmax:
                    tmax = ts
            last = ts

            if kind == "cs" or kind == "cw":
                items.append((ts, ("s", ts, kind, cpu, None, aux, nbytes)))
                continue
            if kind == "fs":
                items.append((ts, ("s", ts, "fs", cpu,
                                   _varint_field(
                                       aux,
                                       fields.SchedSwitchFtraceEvent.PREV_PID),
                                   _varint_field(
                                       aux,
                                       fields.SchedSwitchFtraceEvent.NEXT_PID),
                                   nbytes)))
                continue
            if kind == "fw":
                items.append((ts, ("s", ts, "fw", cpu, None,
                                   _varint_field(
                                       aux, fields.SchedWakingFtraceEvent.PID),
                                   nbytes)))
                continue
            if kind == "nt":
                items.append((ts, ("s", ts, "nt", cpu, None,
                                   _varint_field(
                                       aux, fields.TaskNewtaskFtraceEvent.PID),
                                   nbytes)))
                continue
            # 'other'
            if name == "print":
                buf = print_buf(aux) if aux is not None else None
                # push every print through the buffer: B/E/S/F ordering
                # decides whether it contributes at all.
                if buf is not None:
                    if buf[:2] == b"S|" or buf[:2] == b"F|":
                        marks.append((buf, ts))   # _handle_print_marker
                    op, key = _print_op(buf)
                    if op == 1 or op == 2:   # B/E/S/F: order-dependent
                        items.append((ts, ("p", op, key, nbytes, ts)))
                        continue
                    if op == 0:              # no ts-bearing row
                        untimed += nbytes
                        continue
                    # op 3 (C/I/N): order-independent point -> below
                else:
                    untimed += nbytes
                    continue
            if name in bounds_names:
                if pmin is None:
                    pmin = pmax = ts
                elif ts < pmin:
                    pmin = ts
                elif ts > pmax:
                    pmax = ts
                ent = hist.get(ts // bin_ns)
                if ent is None:
                    hist[ts // bin_ns] = [nbytes, 1]
                else:
                    ent[0] += nbytes
                    ent[1] += 1
            else:
                untimed += nbytes
    return (cpu, bv.lost_events, bool(bv.error), n_cs, n_cw, counts,
            n_timed, tmin, tmax, first, last, ooo, untimed, hist,
            pmin, pmax, items, marks)


def scan_batch(tasks):
    """Worker entry: [(payload, raw_len), ...] -> [scan_bundle(...)]."""
    return [scan_bundle(p, n) for p, n in tasks]


def _apply_bundle(r, raw_len, res, bnd, hist, cpu_stats, event_counts,
                  last_ts_per_cpu, warnings, pending_launches, add_marker,
                  rb, emit):
    """Fold one scan_bundle result into the main scan state, in file
    order (identical to processing the bundle inline)."""
    (cpu, lost, error, n_cs, n_cw, counts, n_timed, tmin, tmax, first,
     last, ooo, untimed, bhist, pmin, pmax, items, marks) = r
    ft = res.ftrace
    ft["bundles"] += 1
    ft["lost_events"] += lost
    if error:
        warnings["ftrace_errors"] = warnings.get("ftrace_errors", 0) + 1
    cs = cpu_stats.get(cpu)
    if cs is None:
        cs = cpu_stats[cpu] = CpuStats()
    ft["compact_switch_events"] += n_cs
    ft["compact_waking_events"] += n_cw
    st = res.per_type.setdefault("ftrace_events", TypeStats())
    st.count += 1
    st.bytes += raw_len
    for name, c in counts.items():
        event_counts[name] = event_counts.get(name, 0) + c
    res.untimed_bytes += untimed
    if first is not None:
        cs.events += n_timed
        if cs.first_ts is None or tmin < cs.first_ts:
            cs.first_ts = tmin
        if cs.last_ts is None or tmax > cs.last_ts:
            cs.last_ts = tmax
        prev = last_ts_per_cpu.get(cpu)
        if prev is not None and first < prev:
            ooo += 1
        if ooo:
            warnings["ftrace_out_of_order_events"] = \
                warnings.get("ftrace_out_of_order_events", 0) + ooo
        last_ts_per_cpu[cpu] = last
        if st.min_ts is None or tmin < st.min_ts:
            st.min_ts = tmin
        if st.max_ts is None or tmax > st.max_ts:
            st.max_ts = tmax
    if pmin is not None:
        bnd.point(pmin)
        bnd.point(pmax)
    for b, (nb, nev) in bhist.items():
        ent = hist.get(b)
        if ent is None:
            hist[b] = [nb, nev]
        else:
            ent[0] += nb
            ent[1] += nev
    for buf, ts in marks:
        _handle_print_marker(buf, ts, pending_launches, add_marker)
    if items:
        emit(rb.push_many(items, unwrap=True))


def _print_op(buf: bytes):
    """Classify an atrace print buf for the bounds model (pure; runs in
    workers) -> (op, key): 1 = transition(key) [B, S], 2 = close(key)
    [E, F; contributes only if key is open], 3 = point [C, I, N],
    0 = no ts-bearing row in TP."""
    i1 = buf.find(b"|")
    if i1 != 1:
        return 0, None
    c = buf[0]
    i2 = buf.find(b"|", 2)
    p1 = buf[2:] if i2 < 0 else buf[2:i2]
    if c == 66:                       # B
        return 1, ("B", p1)
    if c == 69:                       # E
        return 2, ("B", p1)
    if c == 83 or c == 70:            # S / F: need parts[1], parts[2]
        if i2 < 0:
            return 0, None
        i3 = buf.find(b"|", i2 + 1)
        p2 = buf[i2 + 1:] if i3 < 0 else buf[i2 + 1:i3]
        return (1 if c == 83 else 2), ("S", p1, p2)
    if c in b"CIN":
        return 3, None
    return 0, None


def _label(name: bytes) -> str:
    s = name.decode("utf-8", "replace")
    return s[len("launching: "):] if s.startswith("launching: ") else s


def _handle_print_marker(buf: bytes, ts, pending_launches: dict, add_marker):
    # atrace format: "S|<tid>|<name>|<cookie>" start /
    #                "F|<tid>|<name>|<cookie>" end
    if buf[:2] == b"S|" and b"launching: " in buf:
        parts = buf.split(b"|")
        if len(parts) >= 4:
            pending_launches[(parts[2], parts[3])] = ts
    elif buf[:2] == b"F|" and pending_launches:
        parts = buf.split(b"|")
        if len(parts) >= 4:
            start = pending_launches.pop((parts[2], parts[3]), None)
            if start is not None:
                add_marker(start, ts, _label(parts[2]))

