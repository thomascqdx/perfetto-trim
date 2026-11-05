import pytest

from pftrim import wire


def test_varint_known_vectors():
    assert wire.read_varint(b"\x01", 0) == (1, 1)
    assert wire.read_varint(b"\xac\x02", 0) == (300, 2)  # 300 = 0b1_0101100
    assert wire.read_varint(b"\x7f", 0) == (127, 1)
    assert wire.read_varint(b"\x80\x01", 0) == (128, 2)
    # max uint64 -> 10 bytes
    enc = bytes([0xFF] * 9 + [0x01])
    assert wire.read_varint(enc, 0) == ((1 << 64) - 1, 10)


def test_varint_roundtrip():
    for v in [0, 1, 127, 128, 300, 16383, 16384, 2**32, 2**63 - 1]:
        enc = wire.encode_varint(v)
        assert wire.read_varint(enc, 0) == (v, len(enc))


def test_varint_negative_encodes_as_uint64():
    # int32/int64 -1 encodes as 10-byte varint
    enc = wire.encode_varint(-1)
    assert enc == bytes([0xFF] * 9 + [0x01])
    val, _ = wire.read_varint(enc, 0)
    assert val == (1 << 64) - 1


def test_varint_truncated_and_overlong():
    with pytest.raises(wire.WireError):
        wire.read_varint(b"", 0)
    with pytest.raises(wire.WireError):
        wire.read_varint(b"\x80", 0)
    with pytest.raises(wire.WireError):
        wire.read_varint(b"\x80" * 11, 0)


def test_zigzag():
    for enc, dec in [(0, 0), (1, -1), (2, 1), (3, -2),
                     (4294967294, 2147483647), (4294967295, -2147483648)]:
        assert wire.zigzag_decode(enc) == dec
        assert wire.zigzag_encode(dec) == enc


def test_packed_varints():
    vals = [0, 1, 300, 2**40, 127]
    packed = wire.encode_packed_varints(vals)
    assert packed == b"".join(wire.encode_varint(v) for v in vals)
    assert wire.decode_packed_varints(packed) == vals


def test_iter_fields_all_wire_types():
    # field 1 varint=150, field 2 len "abc", field 3 fixed64, field 4 fixed32
    data = (
        wire.varint_field(1, 150)
        + wire.len_field(2, b"abc")
        + wire.fixed64_field(3, 0x1122334455667788)
        + wire.fixed32_field(4, 0xDEADBEEF)
    )
    got = list(wire.iter_fields(data))
    assert [g[0] for g in got] == [1, 2, 3, 4]
    assert [g[1] for g in got] == [wire.WT_VARINT, wire.WT_LEN,
                                   wire.WT_FIXED64, wire.WT_FIXED32]
    assert got[0][2] == 150
    assert bytes(got[1][2]) == b"abc"
    assert got[2][2] == 0x1122334455667788
    assert got[3][2] == 0xDEADBEEF
    # start/end cover whole field; concatenated slices rebuild input
    assert b"".join(bytes(data[s:e]) for _f, _w, _v, s, e in got) == data


def test_iter_fields_rejects_groups():
    data = wire.encode_tag(1, wire.WT_SGROUP) + b"\x00"
    with pytest.raises(wire.WireError):
        list(wire.iter_fields(data))
    data = wire.encode_tag(1, wire.WT_EGROUP)
    with pytest.raises(wire.WireError):
        list(wire.iter_fields(data))


def test_iter_fields_truncated_len():
    data = wire.encode_tag(2, wire.WT_LEN) + wire.encode_varint(10) + b"ab"
    with pytest.raises(wire.WireError):
        list(wire.iter_fields(data))


def test_iter_fields_field_zero():
    with pytest.raises(wire.WireError):
        list(wire.iter_fields(b"\x00\x01"))


def test_iter_fields_matches_protobuf_encoding():
    pb = pytest.importorskip(
        "perfetto.protos.perfetto.trace.perfetto_trace_pb2")
    pkt = pb.TracePacket(
        timestamp=123456789,
        trusted_packet_sequence_id=42,
        trusted_uid=1000,
        sequence_flags=2,
    )
    data = pkt.SerializeToString()
    got = {f: (wt, v) for f, wt, v, _s, _e in wire.iter_fields(data)}
    assert got[8] == (wire.WT_VARINT, 123456789)
    assert got[10] == (wire.WT_VARINT, 42)
    assert got[3] == (wire.WT_VARINT, 1000)
    assert got[13] == (wire.WT_VARINT, 2)
    # verbatim field slices rebuild the message
    assert b"".join(bytes(data[s:e])
                    for _f, _w, _v, s, e in wire.iter_fields(data)) == data
