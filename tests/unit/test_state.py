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
