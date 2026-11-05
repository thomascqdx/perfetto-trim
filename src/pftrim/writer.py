"""Streaming trace writer (stdlib only).

Writes to `<path>.part` and atomically renames to `<path>` on clean close;
the .part file is deleted if the context exits with an exception. Multiple
writers may be open simultaneously on different paths.
"""

from __future__ import annotations

import os

from .wire import WT_LEN, encode_tag, encode_varint

_WRITE_BUF = 1024 * 1024


class TraceWriter:
    def __init__(self, path):
        self.path = os.fspath(path)
        self.part_path = self.path + ".part"
        self.bytes_written = 0
        self._f = None

    def __enter__(self) -> "TraceWriter":
        self._f = open(self.part_path, "wb", buffering=_WRITE_BUF)
        return self

    def write_raw(self, data) -> None:
        """Write a verbatim top-level field (tag+len+payload)."""
        self._f.write(data)
        self.bytes_written += len(data)

    def write_packet(self, payload) -> None:
        """Write payload as a Trace.packet top-level field."""
        payload = bytes(payload)
        head = encode_tag(1, WT_LEN) + encode_varint(len(payload))
        self._f.write(head)
        self._f.write(payload)
        self.bytes_written += len(head) + len(payload)

    def abort(self) -> None:
        """Close and delete the .part file without renaming."""
        f, self._f = self._f, None
        if f is not None:
            f.close()
        try:
            os.unlink(self.part_path)
        except FileNotFoundError:
            pass

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None or self._f is None:
            self.abort()
            return False
        self._f.close()
        self._f = None
        os.replace(self.part_path, self.path)
        return False
