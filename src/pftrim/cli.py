"""pftrim command-line interface."""

from __future__ import annotations

import argparse
import multiprocessing
import sys

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
    p_cut.add_argument("--reorder-window",
                       help="乱序窗口大小（默认自动: 扫描测得的延迟 + 250ms，限 2s~30s）")
    p_cut.add_argument("--no-cache", action="store_true",
                       help="不使用不写入扫描缓存")

    p_split = sub.add_parser("split", help="将 trace 切成多段")
    p_split.add_argument("trace")
    g2 = p_split.add_argument_group("切分方式（三选一）")
    g2.add_argument("--parts", type=int)
    g2.add_argument("--every")
    g2.add_argument("--size")
    p_split.add_argument("--overlap")
    p_split.add_argument("-o", "--out-dir")
    p_split.add_argument("--keep-original-ts", action="store_true")
    p_split.add_argument("--no-cache", action="store_true")

    p_find = sub.add_parser("find", help="在 trace 中查找匹配事件")
    p_find.add_argument("trace")
    p_find.add_argument("pattern")
    p_find.add_argument("--regex", action="store_true")
    p_find.add_argument("-i", "--ignore-case", dest="ignore_case",
                        action="store_true")
    p_find.add_argument("--source", choices=["atrace", "logcat", "all"],
                        default="all")
    p_find.add_argument("--list", action="store_true")
    p_find.add_argument("--pick", type=int)
    p_find.add_argument("--all", action="store_true")
    p_find.add_argument("--before")
    p_find.add_argument("--after")
    p_find.add_argument("-o", "--out-dir")
    p_find.add_argument("--max-matches", type=int, default=1000)
    p_find.add_argument("--json", action="store_true")
    p_find.add_argument("--no-cache", action="store_true")
    for p in (p_info, p_cut, p_split, p_find):
        p.add_argument("-j", "--jobs", type=int,
                       help="并行解析进程数（默认 CPU 数-1，最多 3；1=单进程）")

    p_ui = sub.add_parser("ui", help="启动本地网页界面（无参数运行时的默认行为）")
    p_ui.add_argument("--port", type=int, default=0,
                      help="监听端口（默认随机，仅 127.0.0.1）")
    p_ui.add_argument("--no-browser", action="store_true",
                      help="不自动打开浏览器")
    return parser


def main(argv: list[str] | None = None) -> int:
    multiprocessing.freeze_support()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:                     # double-clicked exe -> UI mode
        argv = ["ui"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ui":
        from .web.server import serve
        return serve(port=args.port, open_browser=not args.no_browser)
    if getattr(args, "jobs", None) is not None:
        from . import ftpar
        ftpar.set_default_jobs(args.jobs)
    if args.command == "info":
        from .ops import info
        return info.run(args.trace, json_out=args.json,
                        use_cache=not args.no_cache)
    if args.command == "cut":
        from .ops import cut
        return cut.cut(vars(args))
    if args.command == "split":
        from .ops import split
        return split.split(vars(args))
    if args.command == "find":
        from .ops import find
        return find.find(vars(args))
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
