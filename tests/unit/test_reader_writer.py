import gzip
import io
import tracemalloc
import zlib

import pytest

from pftrim import fields, reader, wire
from pftrim.reader import PacketRecord, iter_packets
from pftrim.writer import TraceWriter

import builder as sb


def _write(tmp_path, top_fields, name="t.perfetto-trace"):
    p = tmp_path / name
    sb.write_trace(p, top_fields)
    return p


def _simple_trace(tmp_path):
    packets = [
        sb.clock_snapshot_packet({6: 1_000_000, 3: 500_000}, primary=6),
        sb.ftrace_packet(cpu=0, events=[sb.print_event(100, 1, "B|x"),
                                        sb.sched_switch_event(
                                            200, 1, "a", 1, "b", 2)]),
        sb.process_tree_packet(),
        sb.android_log_packet([(150, "tag", "hello")]),
    ]
    return _write(tmp_path, [sb.packet_field(p) for p in packets]), packets


def test_iter_packets_basic(tmp_path):
    path, packets = _simple_trace(tmp_path)
    recs = list(iter_packets(path))
    assert len(recs) == len(packets)
    for rec, payload in zip(recs, packets):
        assert rec.field_no == fields.Trace.PACKET
        assert bytes(rec.payload) == payload
        assert rec.raw == sb.packet_field(payload)
    # offsets cover the whole stream contiguously
    off = 0
    for rec in recs:
        assert rec.offset == off
        off += len(rec.raw)
    assert off == path.stat().st_size


def test_iter_packets_spans_chunks(tmp_path):
    # many small packets + one big packet crossing the 8MB read chunk
    tops = [sb.packet_field(
        sb.ftrace_packet(cpu=0, events=[
            sb.print_event(i, 1, f"B|{i}") for i in range(3)]))
        for _ in range(50)]
    big_payload = sb.unknown_packet(payload=b"\xff" * (9 * 1024 * 1024))
    tops.append(sb.packet_field(big_payload))
    path = _write(tmp_path, tops)
    recs = list(iter_packets(path))
    assert len(recs) == 51
    assert bytes(recs[-1].payload) == big_payload


def test_passthrough_roundtrip(tmp_path):
    path, _ = _simple_trace(tmp_path)
    out = tmp_path / "out.perfetto-trace"
    with TraceWriter(out) as w:
        for rec in iter_packets(path):
            w.write_raw(rec.raw)
    assert out.read_bytes() == path.read_bytes()


def test_unknown_toplevel_field_passthrough(tmp_path):
    tops = [
        sb.packet_field(sb.ftrace_packet(events=[sb.print_event(1, 1, "x")])),
        sb.len_field(5, b"weird-unknown-toplevel"),   # unknown field 5
        sb.top_field(7, sb.varint(12345), wire_type=sb.WT_VARINT),
        sb.packet_field(sb.process_tree_packet()),
    ]
    path = _write(tmp_path, tops)
    recs = list(iter_packets(path))
    assert [r.field_no for r in recs] == [1, 5, 7, 1]
    assert b"".join(r.raw for r in recs) == path.read_bytes()


def test_unknown_packet_field_passthrough(tmp_path):
    pkt = sb.unknown_packet(field_no=9999, payload=b"\x01\x02\x03")
    path = _write(tmp_path, [sb.packet_field(pkt)])
    recs = list(iter_packets(path))
    assert bytes(recs[0].payload) == pkt


def test_gzip_input(tmp_path):
    path, packets = _simple_trace(tmp_path)
    gz_path = tmp_path / "t.perfetto-trace.gz"
    gz_path.write_bytes(gzip.compress(path.read_bytes()))
    seen = []
    reports = []
    recs = list(iter_packets(gz_path, progress=lambda d, t: reports.append((d, t))))
    assert b"".join(r.raw for r in recs) == path.read_bytes()
    assert reports and reports[-1] == (gz_path.stat().st_size,
                                       gz_path.stat().st_size)


def test_compressed_packets_passthrough(tmp_path):
    inner = [
        sb.ftrace_packet(cpu=3, events=[sb.print_event(7, 8, "inner")]),
        sb.process_tree_packet(),
    ]
    outer = sb.compressed_packet(inner, trusted_packet_sequence_id=5)
    path = _write(tmp_path, [sb.packet_field(outer)])
    # expand_compressed=False: outer packet passes through verbatim
    recs = list(iter_packets(path, expand_compressed=False))
    assert len(recs) == 1
    assert recs[0].raw == sb.packet_field(outer)


def test_compressed_packets_expand(tmp_path):
    inner = [
        sb.ftrace_packet(cpu=3, events=[sb.print_event(7, 8, "inner")]),
        sb.process_tree_packet(),
    ]
    outer = sb.compressed_packet(inner, trusted_packet_sequence_id=5)
    path = _write(tmp_path, [sb.packet_field(outer)])
    recs = list(iter_packets(path, expand_compressed=True))
    assert len(recs) == 2
    assert all(r.compressed for r in recs)
    assert [bytes(r.payload) for r in recs] == inner
    # trusted fields: inner packets lack them -> inherit outer's
    assert all(r.trusted_packet_sequence_id == 5 for r in recs)


def test_compressed_packets_inner_keeps_own_trusted(tmp_path):
    inner_with_seq = sb.ftrace_packet(
        cpu=0, trusted_packet_sequence_id=9,
        events=[sb.print_event(1, 1, "x")])
    inner_without = sb.ftrace_packet(cpu=1,
                                     events=[sb.print_event(2, 1, "y")])
    outer = sb.compressed_packet([inner_with_seq, inner_without],
                                 trusted_packet_sequence_id=5,
                                 trusted_uid=1000, trusted_pid=42)
    path = _write(tmp_path, [sb.packet_field(outer)])
    recs = list(iter_packets(path, expand_compressed=True))
    assert recs[0].trusted_packet_sequence_id == 9   # own wins
    assert recs[1].trusted_packet_sequence_id == 5   # inherited
    assert all(r.trusted_uid == 1000 and r.trusted_pid == 42 for r in recs)


def test_progress_plain(tmp_path):
    path, _ = _simple_trace(tmp_path)
    reports = []
    list(iter_packets(path, progress=lambda d, t: reports.append((d, t))))
    total = path.stat().st_size
    assert reports[-1] == (total, total)


# ---- sample-trace tests -------------------------------------------------

@pytest.mark.sample
def test_sample_passthrough_byte_identical(sample_trace, tmp_path):
    out = tmp_path / "out.perfetto-trace"
    n = 0
    with TraceWriter(out) as w:
        for rec in iter_packets(sample_trace):
            w.write_raw(rec.raw)
            n += 1
    assert out.read_bytes() == sample_trace.read_bytes()
    assert n > 0


@pytest.mark.sample
def test_sample_gz_passthrough(sample_trace, tmp_path):
    gz_path = tmp_path / "sample.gz"
    with gzip.open(gz_path, "wb") as g:
        g.write(sample_trace.read_bytes())
    digest = 0
    n = 0
    for rec in iter_packets(gz_path):
        digest ^= hash(rec.raw)
        n += 1
    digest2 = 0
    m = 0
    for rec in iter_packets(sample_trace):
        digest2 ^= hash(rec.raw)
        m += 1
    assert n == m
    assert digest == digest2


@pytest.mark.sample
def test_sample_packet_count(sample_trace):
    pb = pytest.importorskip(
        "perfetto.protos.perfetto.trace.perfetto_trace_pb2")
    trace = pb.Trace()
    trace.ParseFromString(sample_trace.read_bytes())
    n = sum(1 for _ in iter_packets(sample_trace))
    assert n == len(trace.packet)


@pytest.mark.sample
def test_sample_streaming_memory(sample_trace, tmp_path):
    # stream ~4x sample (~128MB) and assert peak python allocs stay far
    # below the file size and roughly flat vs 1x
    big = tmp_path / "big.perfetto-trace"
    with open(big, "wb") as f:
        data = sample_trace.read_bytes()
        for _ in range(4):
            f.write(data)

    def peak(path):
        tracemalloc.start()
        n = 0
        for _rec in iter_packets(path):
            n += 1
        _cur, pk = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return pk, n

    peak1, n1 = peak(sample_trace)
    peak4, n4 = peak(big)
    assert n4 == 4 * n1
    assert peak4 < 64 * 1024 * 1024
    assert peak4 < max(peak1 * 4, 16 * 1024 * 1024)
