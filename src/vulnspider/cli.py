"""Command-line entrypoint for the VulnSpider prototype."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vulnspider import __version__
from vulnspider.domain import Endpoint
from vulnspider.observation.executor import RequestTransport
from vulnspider.pipeline import AnalysisResult, analyze_legacy_records
from vulnspider.reporting import write_html_report, write_json_report


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
    analyze.add_argument(
        "--html-output",
        required=False,
        default=None,
        type=Path,
        help=(
            "Optional destination for a static HTML dashboard report "
            "rendering the same data as --output (ADR-011)."
        ),
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
        _reject_shared_report_destinations(args.output, args.html_output)
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
        if args.html_output is not None:
            _write_html_report(analysis, args.html_output)
    except (OSError, ValueError) as exc:
        print(f"vulnspider: error: {exc}", file=sys.stderr)
        return 2
    return 0


def _write_html_report(analysis: AnalysisResult, destination: Path) -> None:
    adapter_result = analysis.adapter_result
    input_points = {
        input_point.id or "": input_point
        for input_point in adapter_result.input_points
    }
    endpoints = {
        endpoint.id or "": endpoint for endpoint in adapter_result.endpoints
    }
    probe_runs = {
        observation.feature_vector_id: (
            observation.probe_plan,
            observation.baseline_response,
            observation.probe_response,
        )
        for observation in analysis.probe_observations
    }
    write_html_report(
        analysis.selection,
        destination,
        warnings=analysis.warnings,
        input_points=input_points,
        endpoints=endpoints,
        probe_runs=probe_runs,
        target=_target_label(adapter_result.endpoints),
        elapsed_seconds=analysis.elapsed_seconds,
    )


def _target_label(endpoints: Sequence[Endpoint]) -> str:
    origins = sorted({f"{endpoint.scheme}://{endpoint.host}" for endpoint in endpoints})
    return ", ".join(origins)


def _reject_shared_report_destinations(
    json_destination: Path,
    html_destination: Path | None,
) -> None:
    if html_destination is None:
        return
    if _normalized_destination(json_destination) == _normalized_destination(
        html_destination
    ):
        raise CLIError("--output and --html-output must refer to different files")


def _normalized_destination(destination: Path) -> str:
    return os.path.normcase(
        os.path.normpath(os.fspath(destination.resolve(strict=False)))
    )


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
