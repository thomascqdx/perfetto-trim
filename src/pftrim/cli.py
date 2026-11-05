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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "info":
        from .ops import info
        return info.run(args.trace, json_out=args.json,
                        use_cache=not args.no_cache)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
