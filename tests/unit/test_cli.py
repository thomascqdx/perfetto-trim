from __future__ import annotations

from pftrim.cli import build_parser


def test_cut_reorder_window_default_is_none():
    args = build_parser().parse_args(
        ["cut", "x.perfetto-trace", "--start", "1s", "--end", "2s"])
    assert args.reorder_window is None


def test_cut_reorder_window_explicit():
    args = build_parser().parse_args(
        ["cut", "x.perfetto-trace", "--start", "1s", "--end", "2s",
         "--reorder-window", "5s"])
    assert args.reorder_window == "5s"
