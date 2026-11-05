"""Streaming reader for .perfetto-trace files (stdlib only).

The input file is never fully loaded: the (optionally gzipped) stream is
read in multi-MB chunks and top-level Trace fields are yielded one at a
time as PacketRecord objects.

 - `raw` is the exact byte range of the top-level field, tag included, as
   it appeared in the (decompressed) stream -- writing every record's raw
   back reproduces the input byte-for-byte.
 - `payload` is a memoryview of the TracePacket contents (for field_no ==
   Trace.PACKET) or the field value bytes for other top-level fields.
 - `offset` is the field's byte offset in the decompressed stream.
   For records expanded out of `compressed_packets` it is the offset of
   the enclosing outer packet.
 - Trusted fields (`trusted_packet_sequence_id`, `trusted_uid`,
   `trusted_pid`) are exposed as properties. For inner records of a
   compressed packet they fall back to the outer packet's values when the
   inner packet does not set them -- see `expand_compressed`.

Note on perfetto parity: trace_processor (v57, proto_trace_tokenizer.h)
inflates compressed_packets and forwards inner packets verbatim WITHOUT
injecting the outer trusted fields. The service-side producer may put the
trusted ids only on the outer wrapper; the inheritance here is a pftrim
convenience so sequence-scoped state (interning, clock defaults) can still
be attributed. Payload bytes are never rewritten.
"""

from __future__ import annotations

import gzip
import os
import zlib

from . import Cancelled, fields
from .wire import (
    WT_FIXED32,
    WT_FIXED64,
    WT_LEN,
    WT_VARINT,
    WireError,
    iter_fields,
    read_varint,
)

READ_CHUNK = 8 * 1024 * 1024
_PROGRESS_STEP = 4 * 1024 * 1024

_UNSET = object()


class TruncatedTraceError(WireError):
    """Stream ended in the middle of a field."""


class PacketRecord:
    """One top-level Trace field (usually a TracePacket)."""

    __slots__ = (
        "field_no", "wire_type", "offset", "raw", "payload",
        "compressed", "_trusted",
    )

    def __init__(self, field_no: int, wire_type: int, offset: int,
                 raw: bytes, payload, compressed: bool = False,
                 trusted: tuple | object = _UNSET):
        self.field_no = field_no
        self.wire_type = wire_type
        self.offset = offset
        self.raw = raw
        self.payload = payload
        self.compressed = compressed
        self._trusted = trusted

    def _trusted_fields(self) -> tuple:
        if self._trusted is _UNSET:
            self._trusted = _parse_trusted(self.payload)
        return self._trusted

    @property
    def trusted_packet_sequence_id(self) -> int | None:
        return self._trusted_fields()[0]

    @property
    def trusted_uid(self) -> int | None:
        return self._trusted_fields()[1]

    @property
    def trusted_pid(self) -> int | None:
        return self._trusted_fields()[2]

    def __repr__(self) -> str:
        return (f"PacketRecord(field_no={self.field_no}, "
                f"len={len(self.raw)}, offset={self.offset})")


def _parse_trusted(payload) -> tuple:
    seq = uid = pid = None
    tp = fields.TracePacket
    for fno, wt, val, _s, _e in iter_fields(payload):
        if wt != WT_VARINT:
            continue
        if fno == tp.TRUSTED_PACKET_SEQUENCE_ID:
            seq = val
        elif fno == tp.TRUSTED_UID:
            uid = val
        elif fno == tp.TRUSTED_PID:
            pid = val
    return seq, uid, pid


class _StreamReader:
    """Buffered reader over a binary stream with absolute offsets."""

    __slots__ = ("stream", "buf", "pos", "base")

    def __init__(self, stream):
        self.stream = stream
        self.buf = bytearray()
        self.pos = 0    # consumed bytes within buf
        self.base = 0   # absolute stream offset of buf[0]

    def offset(self) -> int:
        return self.base + self.pos

    def _compact(self):
        if self.pos:
            del self.buf[:self.pos]
            self.base += self.pos
            self.pos = 0

    def ensure(self, n: int) -> int:
        """Make up to n bytes available; returns bytes actually available."""
        while len(self.buf) - self.pos < n:
            self._compact()
            chunk = self.stream.read(READ_CHUNK)
            if not chunk:
                break
            self.buf += chunk
        return len(self.buf) - self.pos

    def read(self, n: int) -> bytes:
        have = len(self.buf) - self.pos
        if have >= n:
            out = bytes(self.buf[self.pos:self.pos + n])
            self.pos += n
            return out
        parts = [self.buf[self.pos:]]
        need = n - have
        self.base += len(self.buf)
        self.buf = bytearray()
        self.pos = 0
        while need > 0:
            chunk = self.stream.read(min(need, READ_CHUNK))
            if not chunk:
                raise TruncatedTraceError(
                    f"stream truncated: need {need} more bytes")
            parts.append(chunk)
            need -= len(chunk)
        return b"".join(parts)

    def read_varint_raw(self) -> tuple[int, bytes]:
        avail = self.ensure(10)
        if avail == 0:
            raise TruncatedTraceError("stream truncated: expected varint")
        buf = self.buf
        i = self.pos
        result = 0
        shift = 0
        while True:
            if i >= len(buf):
                raise TruncatedTraceError("stream truncated mid-varint")
            b = buf[i]
            i += 1
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                raw = bytes(buf[self.pos:i])
                self.pos = i
                return result, raw
            shift += 7
            if shift > 63:
                raise WireError(f"varint too long at offset {self.base + i}")


def _read_top_field(reader: _StreamReader) -> PacketRecord | None:
    if reader.ensure(1) == 0:
        return None
    offset = reader.offset()
    tag_val, tag_raw = reader.read_varint_raw()
    fno = tag_val >> 3
    wt = tag_val & 7
    if fno == 0:
        raise WireError(f"invalid field number 0 at offset {offset}")
    if wt == WT_LEN:
        length, len_raw = reader.read_varint_raw()
        payload = reader.read(length)
        raw = tag_raw + len_raw + payload
        return PacketRecord(fno, wt, offset, raw, memoryview(payload))
    if wt == WT_VARINT:
        _val, vraw = reader.read_varint_raw()
        return PacketRecord(fno, wt, offset, tag_raw + vraw, memoryview(vraw))
    if wt == WT_FIXED64:
        data = reader.read(8)
        return PacketRecord(fno, wt, offset, tag_raw + data, memoryview(data))
    if wt == WT_FIXED32:
        data = reader.read(4)
        return PacketRecord(fno, wt, offset, tag_raw + data, memoryview(data))
    raise WireError(f"unsupported wire type {wt} (group) at offset {offset}")


def _inflate(data: bytes) -> bytes:
    """Decompress zlib-, gzip- or raw-deflate data."""
    try:
        return zlib.decompress(data, wbits=47)  # auto-detect zlib/gzip
    except zlib.error:
        return zlib.decompress(data, wbits=-15)  # raw deflate


def _expand_compressed(rec: PacketRecord):
    """Yield inner records for a packet carrying compressed_packets."""
    outer_trusted = _parse_trusted(rec.payload)
    for fno, wt, val, _s, _e in iter_fields(rec.payload):
        if fno != fields.TracePacket.COMPRESSED_PACKETS or wt != WT_LEN:
            continue
        inner_bytes = _inflate(bytes(val))
        mv = memoryview(inner_bytes)
        pos = 0
        n = len(mv)
        while pos < n:
            field_start = pos
            tag_val, pos = read_varint(mv, pos)
            ifno = tag_val >> 3
            iwt = tag_val & 7
            if iwt == WT_LEN:
                length, pos = read_varint(mv, pos)
                vstart = pos
                pos += length
            elif iwt == WT_VARINT:
                vstart = pos
                _, pos = read_varint(mv, pos)
            elif iwt == WT_FIXED64:
                vstart = pos
                pos += 8
            elif iwt == WT_FIXED32:
                vstart = pos
                pos += 4
            else:
                raise WireError(
                    f"unsupported wire type {iwt} inside compressed_packets")
            if pos > n:
                raise WireError("truncated field inside compressed_packets")
            raw = bytes(mv[field_start:pos])
            payload = memoryview(mv[vstart:pos])
            own = _parse_trusted(payload)
            merged = tuple(o if i is None else i
                           for i, o in zip(own, outer_trusted))
            yield PacketRecord(ifno, iwt, rec.offset, raw, payload,
                               compressed=True, trusted=merged)


def iter_packets(path, *, expand_compressed: bool = False,
                 progress=None, cancel=None):
    """Yield PacketRecord for each top-level field of the trace at `path`.

    expand_compressed: replace packets carrying `compressed_packets` by
    their inner packet records (inner records inherit the outer packet's
    trusted fields where unset; other top-level fields inside the blob are
    yielded too). Without it, the outer packet passes through untouched.

    progress(bytes_done, total_bytes): called periodically with the
    underlying file position (for gz input this is the *compressed*
    position) and the file size.
    """
    path = os.fspath(path)
    total = os.path.getsize(path)
    f = open(path, "rb")
    try:
        magic = f.read(2)
        f.seek(0)
        stream = gzip.GzipFile(fileobj=f) if magic == b"\x1f\x8b" else f
        reader = _StreamReader(stream)
        last_report = 0
        while True:
            rec = _read_top_field(reader)
            if rec is None:
                break
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            if (expand_compressed and rec.field_no == fields.Trace.PACKET
                    and _has_compressed_packets(rec.payload)):
                for inner in _expand_compressed(rec):
                    yield inner
            else:
                yield rec
            if progress is not None:
                done = f.tell()
                if done - last_report >= _PROGRESS_STEP or done == total:
                    last_report = done
                    progress(done, total)
    finally:
        f.close()
    if progress is not None and last_report != total:
        progress(total, total)


def _has_compressed_packets(payload) -> bool:
    for fno, wt, _v, _s, _e in iter_fields(payload):
        if fno == fields.TracePacket.COMPRESSED_PACKETS and wt == WT_LEN:
            return True
    return False
