"""Bounded reorder buffer for out-of-order timestamped events (stdlib only).

Traces interleave per-CPU ftrace bundles whose event timestamps are not
globally sorted. Processing that needs chronological order (TP sorts all
events by ts) uses this buffer: items are released in nondecreasing ts
order once they are older than ``max_pushed_ts - window_ns``. Items pushed
with a ts older than the last released ts can't be held back any more --
they are released immediately and counted in ``late_events``.

Memory is O(items within window_ns), independent of trace length.
Used by scan.py and reused by later boundary-state milestones (PLAN 3.3).
"""

from __future__ import annotations

import heapq


class ReorderBuffer:
    __slots__ = ("window_ns", "_heap", "_seq", "_max_ts", "_last", "late_events")

    def __init__(self, window_ns: int = 2_000_000_000):
        self.window_ns = window_ns
        self._heap: list = []          # (ts, seq, item) min-heap
        self._seq = 0                  # push counter -> stable for equal ts
        self._max_ts: int | None = None
        self._last: int | None = None  # last released ts
        self.late_events = 0

    def push(self, ts: int, item) -> list:
        """Push an item; returns a list of items released in ts order."""
        if self._last is not None and ts < self._last:
            self.late_events += 1
            return [item]
        if self._max_ts is None or ts > self._max_ts:
            self._max_ts = ts
        heapq.heappush(self._heap, (ts, self._seq, item))
        self._seq += 1
        limit = self._max_ts - self.window_ns
        out = []
        heap = self._heap
        while heap and heap[0][0] < limit:
            _t, _s, it = heapq.heappop(heap)
            self._last = _t
            out.append(it)
        return out

    def drain(self) -> list:
        """Release all remaining items in ts order (call at EOF)."""
        out = []
        heap = self._heap
        while heap:
            _t, _s, it = heapq.heappop(heap)
            self._last = _t
            out.append(it)
        return out

    @property
    def pending(self) -> int:
        return len(self._heap)
