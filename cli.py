#!/usr/bin/env python3
"""LogSentinel command line interface.

Examples:
    python cli.py analyze --input sample_logs/access.log
    python cli.py analyze -i sample_logs/access.log --format json --min-severity high
    python cli.py list-detectors

Exit codes: 0 = clean, 1 = alerts found, 2 = error.
"""

import argparse
import sys
from pathlib import Path

from logsentinel.detectors import REGISTRY, SEVERITY_ORDER, analyze, build_detectors
from logsentinel.models import InvalidArgumentError, LogSentinelError
from logsentinel.report import FORMATTERS, render


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer")
    if not 1 <= number <= 1_000_000:
        raise argparse.ArgumentTypeError("value must be between 1 and 1000000")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logsentinel", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyze a log file for suspicious activity")
    run.add_argument("-i", "--input", required=True, help="path to access log")
    run.add_argument("-d", "--detectors", nargs="+", choices=sorted(REGISTRY),
                     default=sorted(REGISTRY), help="detectors to run (default: all)")
    run.add_argument("-t", "--threshold", type=positive_int, default=5,
                     help="bruteforce/scanner/errorspike threshold (default: 5; signatures alert on one match)")
    run.add_argument("-w", "--window", type=positive_int, default=60,
                     help="bruteforce window in seconds (default: 60)")
    run.add_argument("-f", "--format", choices=sorted(FORMATTERS), default="text")
    run.add_argument("-m", "--min-severity", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
                     default="low", help="hide alerts below this severity")
    run.add_argument("-o", "--output", help="write report to this file instead of stdout (replaces existing reports)")

    sub.add_parser("list-detectors", help="show available detectors")
    return parser


def write_output(text: str, target: str) -> None:
    path = Path(target).expanduser()
    if not path.parent.is_dir():
        raise InvalidArgumentError(f"Output folder does not exist: {path.parent}")
    if path.is_dir():
        raise InvalidArgumentError("Output path is a directory")
    path.write_text(text + "\n", encoding="utf-8")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-detectors":
            for name, cls in sorted(REGISTRY.items()):
                print(f"{name:<12} {cls.__doc__}")
            return 0

        detectors = build_detectors(args.detectors, args.threshold, args.window)
        (alerts, stats), elapsed = analyze(args.input, detectors)
        floor = SEVERITY_ORDER[args.min_severity]
        alerts = [a for a in alerts if SEVERITY_ORDER[a.severity] >= floor]
        report = render(args.format, alerts, stats, elapsed)
        if args.output:
            target = Path(args.output).expanduser().resolve()
            source = Path(args.input).expanduser().resolve()
            if target == source or (target.exists() and target.samefile(source)):
                raise InvalidArgumentError("Output must not replace the input log")
            write_output(report, args.output)
        else:
            print(report)
        return 1 if alerts else 0
    except LogSentinelError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"error: {error.strerror or error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
