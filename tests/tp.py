"""trace_processor test helpers (dev-only; requires perfetto pip package).

Binary resolution: env PERFETTO_TRIM_TP_BIN, else the v57.2 prebuilt cached in the
user's perfetto prebuilts dir (matches perfetto 0.58.2).
"""

from __future__ import annotations

import os
import pathlib

import pytest

from pftrim.env import getenv

_TP_NAME = "trace_processor_shell-100334b6091596fb.exe"  # v57.2
_CANDIDATES = [
    pathlib.Path.home() / ".local" / "share" / "perfetto" / "prebuilts" / _TP_NAME,
    pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "perfetto" / "prebuilts" / _TP_NAME,
]


def tp_bin() -> pathlib.Path:
    override = getenv("TP_BIN")
    if override:
        return pathlib.Path(override)
    for p in _CANDIDATES:
        if p.exists():
            return p
    return _CANDIDATES[0]


def open_tp(trace_path, **config_kwargs):
    """Open a trace in trace_processor; skips the test if no binary."""
    from perfetto.trace_processor import TraceProcessor, TraceProcessorConfig

    bin_path = tp_bin()
    if not bin_path.exists():
        pytest.skip(f"trace_processor binary not found: {bin_path}")
    config = TraceProcessorConfig(bin_path=str(bin_path), **config_kwargs)
    return TraceProcessor(trace=str(trace_path), config=config)


def query(tp, sql: str) -> list[dict]:
    """Run SQL and return rows as a list of dicts."""
    it = tp.query(sql)
    cols = it.column_names
    return [{c: getattr(row, c) for c in cols} for row in it]
