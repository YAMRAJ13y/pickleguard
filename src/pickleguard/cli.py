"""PickleGuard command-line interface.

    pickleguard scan <file-or-dir> [--json] [--fail-on safe|suspicious|malicious|never]
    pickleguard version
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .engine import scan_path
from .models import VERDICT_RANK
from .report import to_dict, to_markdown

_FAIL_THRESHOLD = {"safe": 0, "suspicious": 1, "malicious": 2, "never": 99}


def _run_scan(args) -> int:
    try:
        reports = scan_path(args.path)
    except FileNotFoundError:
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2
    if not reports:
        print(
            "No model files found (.pkl/.pt/.pth/.bin/.ckpt/.safetensors).",
            file=sys.stderr,
        )
        return 0

    if args.json:
        print(json.dumps(to_dict(reports), indent=2, ensure_ascii=False))
    else:
        print(to_markdown(reports))

    worst = max([VERDICT_RANK.get(r.verdict, 0) for r in reports] + [0])
    return 1 if worst >= _FAIL_THRESHOLD[args.fail_on] else 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="pickleguard",
        description="Statically scan ML model files for malicious pickle opcodes "
        "(never unpickles them).",
    )
    sub = parser.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="scan a model file or a directory of models")
    sc.add_argument("path", help="a model file (.pkl/.pt/.pth/.bin/.safetensors) or a directory")
    sc.add_argument("--json", action="store_true", help="emit JSON SBOM instead of markdown")
    sc.add_argument(
        "--fail-on",
        choices=list(_FAIL_THRESHOLD),
        default="suspicious",
        help="exit non-zero at/above this verdict (default: suspicious)",
    )

    sub.add_parser("version", help="print the version")

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return _run_scan(args)
    if args.cmd == "version":
        print(__version__)
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
