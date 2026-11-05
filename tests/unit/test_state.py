import heapq
import random

import pytest

from pftrim.state import ReorderBuffer


def test_release_in_ts_order():
    rb = ReorderBuffer(window_ns=100)
    out = []
    out += rb.push(50, "a")
    out += rb.push(200, "b")  # releases a
    out += rb.push(300, "c")
    out += rb.push(160, "d")  # releases d then b? limit=200: 160<200, 200!<200
    out += rb.drain()
    assert out == ["a", "d", "b", "c"]


def test_stable_for_equal_ts():
    rb = ReorderBuffer(window_ns=10)
    out = []
    out += rb.push(100, "x1")
    out += rb.push(100, "x2")
    out += rb.push(500, "y")
    out += rb.drain()
    assert out == ["x1", "x2", "y"]


def test_late_events_counted():
    rb = ReorderBuffer(window_ns=10)
    out = []
    out += rb.push(100, "a")
    out += rb.push(500, "b")   # releases a (limit 490)
    out += rb.push(120, "z")
    out += rb.push(50, "late")  # 50 < last_released(100) -> immediate
    out += rb.push(600, "c")
    out += rb.drain()
    assert rb.late_events == 1
    assert out == ["a", "z", "late", "b", "c"]


def test_memory_bounded_by_window():
    rb = ReorderBuffer(window_ns=100)
    for i in range(100_000):
        rb.push(i, i)
    assert rb.pending <= 101
    rb.drain()


def test_empty():
    rb = ReorderBuffer()
    assert rb.drain() == []


class _HeapOracle:
    """The original per-item heap ReorderBuffer (frozen reference)."""

    def __init__(self, window_ns):
        self.window_ns = window_ns
        self._heap, self._seq = [], 0
        self._max_ts = self._last = None
        self.late_events = 0

    def push(self, ts, item):
        if self._last is not None and ts < self._last:
            self.late_events += 1
            return [item]
        if self._max_ts is None or ts > self._max_ts:
            self._max_ts = ts
        heapq.heappush(self._heap, (ts, self._seq, item))
        self._seq += 1
        limit = self._max_ts - self.window_ns
        out = []
        while self._heap and self._heap[0][0] < limit:
            t, _s, it = heapq.heappop(self._heap)
            self._last = t
            out.append(it)
        return out

    def push_many(self, items):
        out = []
        for pair in items:
            out += self.push(pair[0], pair)
        return out

    def drain(self):
        out = []
        while self._heap:
            t, _s, it = heapq.heappop(self._heap)
            self._last = t
            out.append(it)
        return out


def _random_stream(rng, n):
    """Mostly-increasing per-'cpu' runs, jitter, ties, big jumps back
    (late items) and occasional far-future outliers."""
    ts, out = 1000, []
    for i in range(n):
        r = rng.random()
        if r < 0.05:
            t = ts - rng.randint(0, 5000)          # old / late
        elif r < 0.07:
            t = ts                                 # tie
        elif r < 0.072:
            t = ts + rng.randint(10_000, 100_000)  # outlier jump
        else:
            ts += rng.randint(0, 40)
            t = ts - rng.randint(0, 300)
        out.append((max(t, 0), ("it", i)))
    return out


@pytest.mark.parametrize("seed", range(40))
@pytest.mark.parametrize("bin_shift", [0, 3, 6, 23])
def test_matches_heap_oracle(seed, bin_shift):
    rng = random.Random(seed)
    window = rng.choice([1, 50, 200, 1000])
    stream = _random_stream(rng, 3000)
    ref = _HeapOracle(window)
    rb = ReorderBuffer(window_ns=window, bin_shift=bin_shift)
    i = 0
    while i < len(stream):
        k = rng.randint(1, 60)
        chunk = stream[i:i + k]
        i += k
        r = rng.random()
        if r < 0.2:
            for ts, it in chunk:
                assert rb.push(ts, it) == ref.push(ts, it)
        elif r < 0.4:
            exp = []
            for ts, it in chunk:
                exp += ref.push(ts, it)
            assert rb.push_many(chunk, unwrap=True) == exp
        else:
            assert rb.push_many(chunk) == ref.push_many(chunk)
        assert rb.last_released == ref._last
        assert rb.late_events == ref.late_events
        assert rb.pending == len(ref._heap)
    assert rb.drain() == ref.drain()
    assert rb.last_released == ref._last
