"""pftrim command-line interface."""

from __future__ import annotations

import argparse

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pftrim",
        description="Perfetto Trim - trim/split perfetto traces by time.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_info = sub.add_parser("info", help="显示 trace 概况")
    p_info.add_argument("trace", help=".perfetto-trace 文件路径（可为 .gz）")
    p_info.add_argument("--json", action="store_true", help="输出 JSON")
    p_info.add_argument("--no-cache", action="store_true",
                        help="不使用/不写入扫描缓存")
    p_cut = sub.add_parser("cut", help="按时间窗口裁剪 trace")
    p_cut.add_argument("trace", help=".perfetto-trace 文件路径（可为 .gz）")
    g = p_cut.add_argument_group("时间窗口（二选一）")
    g.add_argument("--start", help="窗口起点: 相对值如 3.5s / 绝对 ns 整数")
    g.add_argument("--end", help="窗口终点: 相对值 / 绝对 ns")
    g.add_argument("--duration", help="窗口时长: 如 2s / 500ms")
    g.add_argument("--last", help="取 trace 末尾的时长: 如 2s")
    p_cut.add_argument("-o", "--out-dir", help="输出目录（默认: 输入目录）")
    p_cut.add_argument("--keep-original-ts", action="store_true",
                       help="carry-in 事件保留原始时间戳")
    p_cut.add_argument("--reorder-window", default="2s",
                       help="乱序窗口大小（默认 2s）")
    p_cut.add_argument("--no-cache", action="store_true",
                       help="不使用不写入扫描缓存")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "info":
        from .ops import info
        return info.run(args.trace, json_out=args.json,
                        use_cache=not args.no_cache)
    if args.command == "cut":
        from .ops import cut
        return cut.cut(vars(args))
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
