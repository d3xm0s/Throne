"""Command line interface - orchestrates checks and output."""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .checks import ALL_CHECKS
from .context import Context
from .findings import SEVERITIES, meets_threshold
from .report import Reporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="throne",
        description="Linux privilege escalation enumerator - find your way to the throne.",
    )
    parser.add_argument(
        "--checks",
        metavar="LIST",
        help="comma-separated checks to run (default: all). Available: " + ", ".join(ALL_CHECKS),
    )
    parser.add_argument("--json", metavar="FILE", help="write full results as JSON to FILE")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--lang", choices=("en", "ru"), default="en", help="interface language (default: en)")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="only show findings at or above this severity (default: info)",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        metavar="SEVERITY",
        help="exit 1 if any finding reaches this severity (useful in scripts)",
    )
    parser.add_argument("--list-checks", action="store_true", help="print available checks and exit")
    parser.add_argument("--version", action="version", version=f"throne {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        for name in ALL_CHECKS:
            print(name)
        return 0

    selected = _select_checks(args.checks)
    if selected is None:
        return 2

    ctx = Context()
    reporter = Reporter(color=not args.no_color, min_severity=args.min_severity, lang=args.lang)

    if ctx.is_root:
        print(reporter.t["root_warning"], file=sys.stderr)

    reporter.banner(__version__)

    started = time.monotonic()
    results = []
    for name in selected:
        module = ALL_CHECKS[name]
        try:
            results.append(module.check(ctx))
        except Exception as exc:  # a broken check must never kill the sweep
            from .findings import CheckResult

            failed = CheckResult(name=name)
            failed.errors.append(f"check crashed: {exc}")
            results.append(failed)
    elapsed = time.monotonic() - started

    reporter.render(results)
    reporter.summary(results, elapsed)

    for result in results:
        for error in result.errors:
            print(f"[!] {result.name}: {error}", file=sys.stderr)

    if args.json:
        with open(args.json, "w") as fh:
            fh.write(reporter.to_json(results))
        print(reporter.t["json_written"].format(path=args.json, elapsed=elapsed), file=sys.stderr)

    if args.fail_on:
        for result in results:
            for finding in result.findings:
                if meets_threshold(finding.severity, args.fail_on):
                    return 1
    return 0


def _select_checks(raw: str | None) -> list[str] | None:
    if not raw:
        return list(ALL_CHECKS)
    names = [n.strip() for n in raw.split(",") if n.strip()]
    unknown = [n for n in names if n not in ALL_CHECKS]
    if unknown:
        from .i18n import get

        t = get("en")
        print(t["unknown_checks"].format(names=", ".join(unknown)), file=sys.stderr)
        print(f"{t['available']}: " + ", ".join(ALL_CHECKS), file=sys.stderr)
        return None
    return names


if __name__ == "__main__":
    sys.exit(main())
