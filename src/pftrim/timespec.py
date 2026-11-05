"""Time / size spec parsing for CLI and UI.

- parse_time(spec, trace_start_ns): "3.5s" / "1200ms" / "800us" / "250ns"
  are relative to the trace start; a bare integer is absolute ns.
- parse_duration(spec): same units, returns ns.
- parse_size(spec): "500MB" / "1.5GB" / "200k" -- binary units (1024).
- format_ns: human-readable, e.g. "3.512 s".
"""

from __future__ import annotations

import re

_TIME_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(ns|us|ms|s)?\s*$",
                      re.IGNORECASE)
_UNIT_NS = {"ns": 1, "us": 1_000, "ms": 1_000_000, "s": 1_000_000_000}

_SIZE_RE = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(b|k|kb|m|mb|g|gb|t|tb)?\s*$",
    re.IGNORECASE)
_UNIT_BYTES = {
    "b": 1, "k": 1024, "kb": 1024, "m": 1024 ** 2, "mb": 1024 ** 2,
    "g": 1024 ** 3, "gb": 1024 ** 3, "t": 1024 ** 4, "tb": 1024 ** 4,
}


def _err(msg: str) -> ValueError:
    return ValueError(msg)


def parse_duration(spec) -> int:
    """'3.5s'/'1200ms'/'800us'/'250ns'/bare int (ns) -> nanoseconds."""
    if isinstance(spec, (int, float)) and not isinstance(spec, bool):
        return int(spec)
    m = _TIME_RE.match(str(spec))
    if not m:
        raise _err(f"无法识别的时长: {spec!r}（示例: 3.5s, 1200ms, 800us, 250ns）")
    unit = (m.group(2) or "ns").lower()
    return int(float(m.group(1)) * _UNIT_NS[unit])


def parse_time(spec, trace_start_ns: int) -> int:
    """Relative time spec -> absolute ns from trace start.

    With a unit suffix the value is relative to trace_start_ns; a bare
    integer is already an absolute timestamp in ns.
    """
    if isinstance(spec, int) and not isinstance(spec, bool):
        return spec
    m = _TIME_RE.match(str(spec))
    if not m:
        raise _err(f"无法识别的时间: {spec!r}（示例: 3.5s, 1200ms, 或纳秒整数）")
    value = float(m.group(1))
    unit = m.group(2)
    if unit is None:
        if value != int(value):
            raise _err(f"绝对时间戳必须是整数纳秒: {spec!r}")
        return int(value)
    return trace_start_ns + int(value * _UNIT_NS[unit.lower()])


def parse_size(spec) -> int:
    """'500MB'/'1.5GB'/'200k'/bare int -> bytes (binary units, 1024)."""
    if isinstance(spec, int) and not isinstance(spec, bool):
        return spec
    m = _SIZE_RE.match(str(spec))
    if not m:
        raise _err(f"无法识别的大小: {spec!r}（示例: 500MB, 1.5GB, 200k）")
    value = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    return int(value * _UNIT_BYTES[unit])


def format_ns(ns) -> str:
    if ns is None:
        return "-"
    ns = int(ns)
    sign = "-" if ns < 0 else ""
    ns = abs(ns)
    if ns < 1_000:
        return f"{sign}{ns} ns"
    if ns < 1_000_000:
        return f"{sign}{ns / 1_000:.3f} us"
    if ns < 1_000_000_000:
        return f"{sign}{ns / 1_000_000:.3f} ms"
    return f"{sign}{ns / 1_000_000_000:.3f} s"


def format_size(n) -> str:
    n = int(n)
    for unit, mult in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= mult:
            return f"{n / mult:.1f} {unit}"
    return f"{n} B"
