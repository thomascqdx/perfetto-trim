"""Minimal protobuf wire-format codec (stdlib only).

Buffers are accessed as memoryview-compatible sequences; field values of
wire type 2 (length-delimited) are returned as memoryview slices so no copy
is made. start/end offsets cover the whole field including the tag, so
callers can copy unchanged fields verbatim.
"""

from __future__ import annotations

WT_VARINT = 0
WT_FIXED64 = 1
WT_LEN = 2
WT_SGROUP = 3
WT_EGROUP = 4
WT_FIXED32 = 5

_UINT64_MASK = (1 << 64) - 1


class WireError(Exception):
    """Malformed wire data (bad varint, unsupported wire type, truncation)."""


def read_varint(buf, pos: int) -> tuple[int, int]:
    """Decode a varint at buf[pos]; returns (value, new_pos).

    buf must support integer indexing returning ints (bytes/memoryview).
    """
    result = 0
    shift = 0
    while True:
        try:
            b = buf[pos]
        except IndexError:
            raise WireError(f"truncated varint at offset {pos}") from None
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise WireError(f"varint too long at offset {pos}")


def zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def zigzag_encode(value: int) -> int:
    return (value << 1) ^ (value >> 63)


def iter_fields(buf, start: int = 0, end: int | None = None):
    """Iterate protobuf fields over buf[start:end].

    Yields (field_no, wire_type, value, field_start, field_end):
      - value is int for varint/fixed32/fixed64 fields,
        memoryview for length-delimited fields.
      - field_start/field_end are byte offsets of the whole field
        (tag included), so buf[field_start:field_end] copies the field
        verbatim.
    Raises WireError on group wire types (3/4) or truncation.
    """
    mv = memoryview(buf)
    if end is None:
        end = len(mv)
    pos = start
    while pos < end:
        field_start = pos
        tag_val, pos = read_varint(mv, pos)
        field_no = tag_val >> 3
        wt = tag_val & 7
        if field_no == 0:
            raise WireError(f"invalid field number 0 at offset {field_start}")
        if wt == WT_VARINT:
            value, pos = read_varint(mv, pos)
        elif wt == WT_FIXED64:
            if pos + 8 > end:
                raise WireError(f"truncated fixed64 at offset {pos}")
            value = int.from_bytes(mv[pos:pos + 8], "little")
            pos += 8
        elif wt == WT_LEN:
            length, pos = read_varint(mv, pos)
            if pos + length > end:
                raise WireError(
                    f"truncated length-delimited field at offset {pos} "
                    f"(len={length}, end={end})")
            value = mv[pos:pos + length]
            pos += length
        elif wt == WT_FIXED32:
            if pos + 4 > end:
                raise WireError(f"truncated fixed32 at offset {pos}")
            value = int.from_bytes(mv[pos:pos + 4], "little")
            pos += 4
        else:
            raise WireError(
                f"unsupported wire type {wt} (group) at offset {field_start}")
        yield field_no, wt, value, field_start, pos


def decode_packed_varints(buf) -> list[int]:
    """Decode a packed-varint payload (contents of a LEN field)."""
    out = []
    pos = 0
    n = len(buf)
    while pos < n:
        v, pos = read_varint(buf, pos)
        out.append(v)
    return out


def encode_varint(value: int) -> bytes:
    """Encode an int as varint. Negative ints use 64-bit two's complement
    (matching protobuf int32/int64 encoding)."""
    value &= _UINT64_MASK
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_packed_varints(values) -> bytes:
    out = bytearray()
    for v in values:
        out += encode_varint(v)
    return bytes(out)


def encode_tag(field_no: int, wire_type: int) -> bytes:
    return encode_varint((field_no << 3) | wire_type)


def varint_field(field_no: int, value: int) -> bytes:
    return encode_tag(field_no, WT_VARINT) + encode_varint(value)


def len_field(field_no: int, payload) -> bytes:
    payload = bytes(payload)
    return encode_tag(field_no, WT_LEN) + encode_varint(len(payload)) + payload


def fixed64_field(field_no: int, value: int) -> bytes:
    return encode_tag(field_no, WT_FIXED64) + (value & _UINT64_MASK).to_bytes(8, "little")


def fixed32_field(field_no: int, value: int) -> bytes:
    return encode_tag(field_no, WT_FIXED32) + (value & 0xFFFFFFFF).to_bytes(4, "little")
