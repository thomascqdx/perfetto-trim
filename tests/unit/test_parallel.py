"""jobs>1 (worker processes) must give results identical to jobs=1."""

import multiprocessing
import threading

import pytest
from perfetto.protos.perfetto.trace import perfetto_trace_pb2 as pb

from pftrim import Cancelled
from pftrim.engine import Options, Window, run
from pftrim.scan import scan
from synthetic import builder as B


@pytest.fixture(autouse=True)
def _force_pool(monkeypatch):
    # small test inputs would otherwise stay in-process
    monkeypatch.setenv("PFTRIM_PAR_MIN_BYTES", "0")


@pytest.mark.sample
def test_scan_jobs_identical_sample(sample_trace):
    assert scan(sample_trace, jobs=2).to_dict() == \
        scan(sample_trace, jobs=1).to_dict()
    assert multiprocessing.active_children() == []


def _bundle(cpu, base, n, **bundle_kw):
    evs = [B.print_event(base + i * 1000, 101, f"B|100|s{i}")
           for i in range(n)]
    evs += [B.print_event(base + i * 1000 + 500, 101, "E|100")
            for i in range(n)]
    return B.packet_field(B.ftrace_packet(
        cpu=cpu, events=evs, bundle_kw=bundle_kw or None,
        trusted_packet_sequence_id=7))


def test_scan_non_identity_ftrace_clock_falls_back(tmp_path):
    """Identity-clock bundles first (handled by workers), then GLOBAL
    clock bundles that need the main-process clock state."""
    fields_ = [B.packet_field(B.clock_snapshot_packet({6: 10_000_000}))]
    fields_ += [_bundle(c % 2, 20_000_000 + c * 100_000, 5)
                for c in range(6)]
    fields_ += [_bundle(c % 2, 5_000 + c * 100_000, 5,
                        ftrace_clock=pb.FTRACE_CLOCK_GLOBAL,
                        ftrace_timestamp=1_000,
                        boot_timestamp=30_000_000)
                for c in range(6)]
    path = B.write_trace(tmp_path / "glob.perfetto-trace", fields_)
    r1 = scan(path, jobs=1).to_dict()
    r2 = scan(path, jobs=2).to_dict()
    assert r1 == r2
    # GLOBAL bundles were converted: 5_000 - 1_000 + 30_000_000
    assert r1["end_ns"] > 30_000_000
    assert multiprocessing.active_children() == []


def _run_outputs(trace, windows, out_dir, jobs, **kw):
    rep = run(trace, windows, str(out_dir), Options(jobs=jobs), **kw)
    files = {}
    for p in sorted(out_dir.iterdir()):
        files[p.name] = p.read_bytes()
    return rep, files


@pytest.mark.sample
@pytest.mark.parametrize("nwin", [1, 3])
def test_engine_jobs_identical_sample(sample_trace, tmp_path, nwin):
    """cut (1 window) and split-like (3 windows, overlapping) outputs and
    boundary.csv files are byte-identical for jobs=1 and jobs=2."""
    sc = scan(sample_trace, jobs=1)
    span = sc.end_ns - sc.start_ns
    if nwin == 1:
        wins = [Window(sc.start_ns + span // 3, sc.start_ns + span // 2)]
    else:
        step = span // 3
        wins = [Window(sc.start_ns + i * step - (200_000_000 if i else 0),
                       sc.start_ns + (i + 1) * step) for i in range(3)]
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    rep1, f1 = _run_outputs(sample_trace, wins, tmp_path / "a", 1)
    rep2, f2 = _run_outputs(sample_trace, wins, tmp_path / "b", 2)
    assert f1.keys() == f2.keys() and len(f1) >= nwin
    for name in f1:
        assert f1[name] == f2[name], name
    assert rep1.bundles_decoded == rep2.bundles_decoded
    assert multiprocessing.active_children() == []


@pytest.mark.sample
def test_engine_cancel_parallel_leaves_no_workers(sample_trace, tmp_path):
    sc = scan(sample_trace, jobs=1)
    ev = threading.Event()
    with pytest.raises(Cancelled):
        run(sample_trace, [Window(sc.start_ns, sc.end_ns)], str(tmp_path),
            Options(jobs=2), cancel=ev,
            progress=lambda done, total: ev.set())
    assert list(tmp_path.iterdir()) == []
    assert multiprocessing.active_children() == []


@pytest.mark.sample
def test_scan_cancel_parallel_leaves_no_workers(sample_trace):
    ev = threading.Event()
    with pytest.raises(Cancelled):
        scan(sample_trace, jobs=2, cancel=ev,
             progress=lambda done, total: ev.set())
    assert multiprocessing.active_children() == []
