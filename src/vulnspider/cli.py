"""Command-line entrypoint for the VulnSpider prototype."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vulnspider import __version__
from vulnspider.observation.executor import RequestTransport
from vulnspider.pipeline import analyze_legacy_records
from vulnspider.reporting import write_json_report


class CLIError(ValueError):
    """Raised for normal user-facing CLI input errors."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnspider",
        description="VulnSpider prototype command line interface.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")
    analyze = subparsers.add_parser(
        "analyze",
        help="Run authorized loopback Light Probes from legacy crawl-record JSON.",
        description=(
            "Analyze adapter-compatible legacy crawl records for authorized "
            "localhost or loopback test targets."
        ),
    )
    analyze.add_argument(
        "--input",
        required=True,
        type=Path,
        help="JSON array of LegacyCrawlerAdapter-compatible crawl records.",
    )
    analyze.add_argument(
        "--top-k",
        required=True,
        type=_positive_integer,
        help="Number of unique rankable candidates to select.",
    )
    analyze.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination for the deterministic JSON report.",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    transport: RequestTransport | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return 0
    if args.command != "analyze":
        parser.error(f"unsupported command: {args.command}")
    try:
        records = _load_legacy_records(args.input)
        analysis = analyze_legacy_records(
            records,
            top_k=args.top_k,
            transport=transport,
        )
        write_json_report(
            analysis.selection,
            args.output,
            warnings=analysis.warnings,
        )
    except (OSError, ValueError) as exc:
        print(f"vulnspider: error: {exc}", file=sys.stderr)
        return 2
    return 0


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("top-k must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("top-k must be a positive integer")
    return parsed


def _load_legacy_records(path: Path) -> tuple[Mapping[str, Any], ...]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CLIError(f"input is not valid JSON: {path}") from exc
    if not isinstance(parsed, list):
        raise CLIError("input JSON must be an array of legacy crawl records")
    records: list[Mapping[str, Any]] = []
    for index, item in enumerate(parsed):
        if not isinstance(item, Mapping):
            raise CLIError(f"legacy crawl record at index {index} must be an object")
        link = item.get("link") or item.get("url")
        if not isinstance(link, str) or not link:
            raise CLIError(
                f"legacy crawl record at index {index} requires a non-empty link"
            )
        try:
            parts = urlsplit(link)
        except ValueError as exc:
            raise CLIError(
                f"legacy crawl record at index {index} requires an absolute HTTP(S) link"
            ) from exc
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise CLIError(
                f"legacy crawl record at index {index} requires an absolute HTTP(S) link"
            )
        records.append(item)
    return tuple(records)
