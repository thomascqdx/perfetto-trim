import os

import pytest

from pftrim.writer import TraceWriter

import builder as sb


def test_write_packet_and_raw(tmp_path):
    out = tmp_path / "o.perfetto-trace"
    p1 = sb.ftrace_packet(events=[sb.print_event(1, 1, "x")])
    raw_field = sb.len_field(5, b"verbatim")
    with TraceWriter(out) as w:
        w.write_packet(p1)
        w.write_raw(raw_field)
        assert w.bytes_written == len(sb.packet_field(p1)) + len(raw_field)
    assert out.read_bytes() == sb.packet_field(p1) + raw_field


def test_part_renamed_on_success(tmp_path):
    out = tmp_path / "o.perfetto-trace"
    part = tmp_path / "o.perfetto-trace.part"
    with TraceWriter(out) as w:
        w.write_packet(b"\x08\x01")
        assert part.exists()
    assert not part.exists()
    assert out.exists()


def test_part_deleted_on_exception(tmp_path):
    out = tmp_path / "o.perfetto-trace"
    part = tmp_path / "o.perfetto-trace.part"
    with pytest.raises(RuntimeError):
        with TraceWriter(out) as w:
            w.write_packet(b"\x08\x01")
            assert part.exists()
            raise RuntimeError("boom")
    assert not part.exists()
    assert not out.exists()


def test_multiple_writers_simultaneous(tmp_path):
    outs = [tmp_path / f"o{i}.perfetto-trace" for i in range(3)]
    writers = [TraceWriter(p) for p in outs]
    payloads = [sb.ftrace_packet(events=[sb.print_event(i, 1, "x")])
                for i in range(3)]
    for w in writers:
        w.__enter__()
    try:
        for i, (w, p) in enumerate(zip(writers, payloads)):
            w.write_packet(p)
            w.write_packet(p)
    finally:
        for w in writers:
            w.__exit__(None, None, None)
    for out, p in zip(outs, payloads):
        assert out.read_bytes() == sb.packet_field(p) + sb.packet_field(p)


def test_writer_not_started_write_fails(tmp_path):
    w = TraceWriter(tmp_path / "x")
    with pytest.raises((AttributeError, TypeError)):
        w.write_packet(b"x")
