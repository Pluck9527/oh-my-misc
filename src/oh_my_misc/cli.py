from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from oh_my_misc import __version__
from oh_my_misc.inspection import inspect_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="omm", description="Native CTF Misc toolkit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    inspect_parser = commands.add_parser("inspect", help="生成文件基础画像")
    inspect_parser.add_argument("file", type=Path, help="待检查文件")
    inspect_parser.add_argument("--json", action="store_true", dest="as_json", help="输出稳定 JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    result = inspect_file(args.file)
    if args.as_json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"状态：{result.status}")
        print(f"文件：{result.input_path}")
        if result.summary:
            print(f"类型：{result.summary['kind']} ({result.summary['media_type']})")
            print(f"大小：{result.summary['size']} bytes")
            print(f"SHA-256：{result.summary['sha256']}")
            if "width" in result.summary:
                print(f"尺寸：{result.summary['width']} × {result.summary['height']}")
        for finding in result.findings:
            print(f"[{finding.severity}] {finding.title}：{finding.evidence}")
        for error in result.errors:
            print(f"[error] {error['message']}", file=sys.stderr)
    return 0 if result.status in {"success", "empty"} else 2
