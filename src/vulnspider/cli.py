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
from vulnspider.discovery import (
    CrawlPolicy,
    DiscoveryContractError,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicCapabilityError,
    DynamicCrawler,
    DynamicCrawlerError,
    DynamicCrawlPolicy,
    DynamicIntegrityError,
    DynamicRequestAuthority,
    DynamicResourceGrant,
    DynamicResourceKind,
    StaticCrawler,
    StaticCrawlerTransport,
)
from vulnspider.domain import Endpoint
from vulnspider.observation.executor import RequestTransport
from vulnspider.pipeline import (
    AnalysisResult,
    analyze_legacy_records,
    analyze_url,
)
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
        help="Analyze a native root URL or legacy crawl-record JSON.",
        description=(
            "Analyze one native static root URL or adapter-compatible legacy "
            "crawl records for authorized localhost or loopback test targets."
        ),
    )
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--input",
        type=Path,
        help="JSON array of LegacyCrawlerAdapter-compatible crawl records.",
    )
    source.add_argument(
        "--url",
        help="Root URL for bounded native static discovery.",
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
    analyze.add_argument(
        "--max-pages",
        type=_positive_integer,
        default=None,
        help="Maximum number of HTML pages to process for --url.",
    )
    analyze.add_argument(
        "--max-depth",
        type=_non_negative_integer,
        default=None,
        help="Maximum link depth to schedule for --url.",
    )
    analyze.add_argument(
        "--max-requests",
        type=_positive_integer,
        default=None,
        help="Maximum number of crawler requests for --url.",
    )
    analyze.add_argument(
        "--timeout-seconds",
        type=_positive_number,
        default=None,
        help="Per-request crawler timeout for --url.",
    )
    analyze.add_argument(
        "--max-redirects",
        type=_non_negative_integer,
        default=None,
        help="Maximum redirects followed per URL for --url.",
    )
    analyze.add_argument(
        "--dynamic",
        action="store_true",
        help="Opt in to bounded combined Static and Dynamic discovery.",
    )
    analyze.add_argument(
        "--dynamic-allow-navigation",
        action="append",
        default=None,
        metavar="URL",
        help="Allow one exact same-origin Dynamic navigation URL (repeatable).",
    )
    analyze.add_argument(
        "--dynamic-allow-resource",
        action="append",
        default=None,
        metavar="CATEGORY=URL",
        help=(
            "Allow one exact same-origin Dynamic resource URL in category "
            "script, style, or fetch_xhr (repeatable)."
        ),
    )
    analyze.add_argument(
        "--dynamic-max-pages",
        type=_positive_integer,
        default=None,
        help="Maximum rendered pages for combined discovery.",
    )
    analyze.add_argument(
        "--dynamic-max-depth",
        type=_non_negative_integer,
        default=None,
        help="Maximum Dynamic navigation depth.",
    )
    analyze.add_argument(
        "--dynamic-max-navigation-attempts",
        type=_positive_integer,
        default=None,
        help="Maximum Dynamic main-frame navigation attempts.",
    )
    analyze.add_argument(
        "--dynamic-max-route-actions",
        type=_positive_integer,
        default=None,
        help="Maximum passive route actions considered for navigation.",
    )
    analyze.add_argument(
        "--dynamic-max-elapsed-seconds",
        type=_positive_number,
        default=None,
        help="Hard elapsed-time limit for one Dynamic crawl.",
    )
    analyze.add_argument(
        "--dynamic-navigation-timeout-seconds",
        type=_positive_number,
        default=None,
        help="Timeout for each Dynamic main-frame navigation.",
    )
    analyze.add_argument(
        "--dynamic-max-redirects",
        type=_positive_integer,
        default=None,
        help="Maximum redirects followed per Dynamic navigation.",
    )
    analyze.add_argument(
        "--dynamic-request-decision-budget",
        type=_positive_integer,
        default=None,
        help="Maximum browser request-authority decisions.",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    transport: RequestTransport | None = None,
    crawler_transport: StaticCrawlerTransport | None = None,
    crawler: StaticCrawler | None = None,
    dynamic_crawler: DynamicCrawler | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return 0
    if args.command != "analyze":
        parser.error(f"unsupported command: {args.command}")
    try:
        _reject_shared_report_destinations(args.output, args.html_output)
        if args.input is not None:
            _reject_native_policy_with_legacy_input(args)
            records = _load_legacy_records(args.input)
            analysis = analyze_legacy_records(
                records,
                top_k=args.top_k,
                transport=transport,
            )
        else:
            _reject_dynamic_options_without_opt_in(args)
            dynamic_authority = (
                _dynamic_authority_from_args(args) if args.dynamic else None
            )
            analysis = analyze_url(
                args.url,
                top_k=args.top_k,
                crawl_policy=_crawl_policy_from_args(args),
                crawler=crawler,
                crawler_transport=crawler_transport,
                dynamic_authority=dynamic_authority,
                dynamic_policy=(
                    _dynamic_policy_from_args(args) if args.dynamic else None
                ),
                dynamic_crawler=(dynamic_crawler if args.dynamic else None),
                transport=transport,
            )
        write_json_report(
            analysis.selection,
            args.output,
            warnings=analysis.warnings,
        )
        if args.html_output is not None:
            _write_html_report(analysis, args.html_output)
    except (DiscoveryContractError, DynamicIntegrityError, DynamicCrawlerError):
        print(
            "vulnspider: error: DYNAMIC_INTEGRITY: "
            "combined discovery failed validation",
            file=sys.stderr,
        )
        return 3
    except DynamicCapabilityError as exc:
        print(
            f"vulnspider: error: {exc.code.value}: {exc}; {exc.setup_hint}",
            file=sys.stderr,
        )
        return 2
    except DynamicBrowserError as exc:
        if exc.code == DynamicBrowserErrorCode.INVALID_AUTHORITY:
            print(
                f"vulnspider: error: {exc.code.value}: {exc}",
                file=sys.stderr,
            )
            return 2
        print(
            f"vulnspider: error: DYNAMIC_INCOMPLETE: {exc.code.value}",
            file=sys.stderr,
        )
        return 4
    except (OSError, ValueError) as exc:
        print(f"vulnspider: error: {exc}", file=sys.stderr)
        return 2
    if analysis.combined_result is not None and analysis.combined_result.degraded:
        return 4
    return 0


def _write_html_report(analysis: AnalysisResult, destination: Path) -> None:
    input_points = {
        input_point.id or "": input_point
        for input_point in analysis.input_points
    }
    endpoints = {
        endpoint.id or "": endpoint for endpoint in analysis.endpoints
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
        target=_analysis_target(analysis),
        elapsed_seconds=analysis.elapsed_seconds,
    )


def _analysis_target(analysis: AnalysisResult) -> str:
    if analysis.discovery_result is not None:
        return analysis.discovery_result.scope_metadata.root_url
    return _target_label(analysis.endpoints)


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
        raise argparse.ArgumentTypeError(
            "value must be a positive integer"
        ) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _non_negative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "value must be a non-negative integer"
        ) from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError(
            "value must be a non-negative integer"
        )
    return parsed


def _positive_number(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "value must be a positive number"
        ) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive number")
    return parsed


def _reject_native_policy_with_legacy_input(args: argparse.Namespace) -> None:
    if any(
        getattr(args, name) is not None
        for name in (
            "max_pages",
            "max_depth",
            "max_requests",
            "timeout_seconds",
            "max_redirects",
            "dynamic_allow_navigation",
            "dynamic_allow_resource",
            "dynamic_max_pages",
            "dynamic_max_depth",
            "dynamic_max_navigation_attempts",
            "dynamic_max_route_actions",
            "dynamic_max_elapsed_seconds",
            "dynamic_navigation_timeout_seconds",
            "dynamic_max_redirects",
            "dynamic_request_decision_budget",
        )
    ) or args.dynamic:
        raise CLIError("crawler policy options require --url")


_DYNAMIC_OPTION_NAMES = (
    "dynamic_allow_navigation",
    "dynamic_allow_resource",
    "dynamic_max_pages",
    "dynamic_max_depth",
    "dynamic_max_navigation_attempts",
    "dynamic_max_route_actions",
    "dynamic_max_elapsed_seconds",
    "dynamic_navigation_timeout_seconds",
    "dynamic_max_redirects",
    "dynamic_request_decision_budget",
)


def _reject_dynamic_options_without_opt_in(args: argparse.Namespace) -> None:
    if args.dynamic:
        return
    if any(getattr(args, name) is not None for name in _DYNAMIC_OPTION_NAMES):
        raise CLIError("Dynamic policy and authority options require --dynamic")


def _dynamic_authority_from_args(
    args: argparse.Namespace,
) -> DynamicRequestAuthority:
    grants: list[DynamicResourceGrant] = []
    for value in args.dynamic_allow_resource or ():
        category, separator, url = value.partition("=")
        if not separator or not category or not url:
            raise CLIError(
                "--dynamic-allow-resource requires CATEGORY=URL"
            )
        try:
            kind = DynamicResourceKind(category)
        except ValueError:
            allowed = ", ".join(item.value for item in DynamicResourceKind)
            raise CLIError(
                "--dynamic-allow-resource category must be one of: "
                f"{allowed}"
            ) from None
        grants.append(DynamicResourceGrant(kind=kind, url=url))
    return DynamicRequestAuthority(
        root_url=args.url,
        navigation_urls=tuple(args.dynamic_allow_navigation or ()),
        resource_grants=tuple(grants),
    )


def _dynamic_policy_from_args(args: argparse.Namespace) -> DynamicCrawlPolicy:
    defaults = DynamicCrawlPolicy()
    try:
        return DynamicCrawlPolicy(
            max_pages=(
                defaults.max_pages
                if args.dynamic_max_pages is None
                else args.dynamic_max_pages
            ),
            max_depth=(
                defaults.max_depth
                if args.dynamic_max_depth is None
                else args.dynamic_max_depth
            ),
            max_navigation_attempts=(
                defaults.max_navigation_attempts
                if args.dynamic_max_navigation_attempts is None
                else args.dynamic_max_navigation_attempts
            ),
            max_route_actions=(
                defaults.max_route_actions
                if args.dynamic_max_route_actions is None
                else args.dynamic_max_route_actions
            ),
            max_elapsed_seconds=(
                defaults.max_elapsed_seconds
                if args.dynamic_max_elapsed_seconds is None
                else args.dynamic_max_elapsed_seconds
            ),
            navigation_timeout_seconds=(
                defaults.navigation_timeout_seconds
                if args.dynamic_navigation_timeout_seconds is None
                else args.dynamic_navigation_timeout_seconds
            ),
            max_redirects_per_navigation=(
                defaults.max_redirects_per_navigation
                if args.dynamic_max_redirects is None
                else args.dynamic_max_redirects
            ),
            request_decision_budget=(
                defaults.request_decision_budget
                if args.dynamic_request_decision_budget is None
                else args.dynamic_request_decision_budget
            ),
            rendered_dom_policy=defaults.rendered_dom_policy,
        )
    except DynamicCrawlerError as exc:
        raise CLIError(str(exc)) from None


def _crawl_policy_from_args(args: argparse.Namespace) -> CrawlPolicy:
    defaults = CrawlPolicy()
    return CrawlPolicy(
        max_pages=(
            defaults.max_pages if args.max_pages is None else args.max_pages
        ),
        max_depth=(
            defaults.max_depth if args.max_depth is None else args.max_depth
        ),
        max_requests=(
            defaults.max_requests
            if args.max_requests is None
            else args.max_requests
        ),
        timeout_seconds=(
            defaults.timeout_seconds
            if args.timeout_seconds is None
            else args.timeout_seconds
        ),
        max_redirects=(
            defaults.max_redirects
            if args.max_redirects is None
            else args.max_redirects
        ),
        delay_seconds=defaults.delay_seconds,
        max_elapsed_seconds=defaults.max_elapsed_seconds,
        max_response_bytes=defaults.max_response_bytes,
    )


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
