"""M0 acceptance: load the sample trace in trace_processor."""

import pytest

from tp import query

pytestmark = [pytest.mark.tp, pytest.mark.sample]


def test_sample_loads_and_has_trace_bounds(sample_tp):
    rows = query(sample_tp, "select start_ts, end_ts from trace_bounds")
    assert len(rows) == 1
    assert rows[0]["start_ts"] > 0
    assert rows[0]["end_ts"] > rows[0]["start_ts"]


def test_sample_has_ftrace_data(sample_tp):
    rows = query(sample_tp, "select count(*) as c from sched_slice")
    assert rows[0]["c"] > 0
    rows = query(sample_tp, "select count(*) as c from slice")
    assert rows[0]["c"] > 0
