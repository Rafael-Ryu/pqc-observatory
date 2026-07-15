from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

from .scan import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqc-observatory")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="probe a target list and write a dataset")
    s.add_argument("--targets", type=Path, required=True)
    s.add_argument("--out", type=Path, default=Path("data"))
    s.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="run date recorded in the dataset (default: today)",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        path = scan(args.targets, args.out, args.date)
        print(path)
    return 0
