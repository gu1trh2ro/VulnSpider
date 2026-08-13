"""Canonical crawl evidence reporting for the public simple CLI."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from vulnspider.discovery import (
    CombinedDiscoveryResult,
    DynamicCrawlCompletion,
    StaticCrawlResult,
)
from vulnspider.reporting.json_report import (
    REPORT_SCHEMA_VERSION,
    ReportingError,
    render_json_document,
    write_json_document,
)


def build_crawl_report(
    crawl: StaticCrawlResult | CombinedDiscoveryResult,
) -> dict[str, Any]:
    """Wrap a revalidated producer-owned canonical serialization."""

    try:
        if type(crawl) is CombinedDiscoveryResult:
            validated = replace(crawl)
            mode = "combined"
            completion = validated.completion.value
            degraded = validated.degraded
        elif type(crawl) is StaticCrawlResult:
            validated = replace(crawl)
            mode = "static_only"
            completion = DynamicCrawlCompletion.COMPLETE.value
            degraded = False
        else:
            raise ReportingError(
                "crawl must be a StaticCrawlResult or CombinedDiscoveryResult"
            )
    except (TypeError, ValueError) as exc:
        raise ReportingError("crawl result failed revalidation") from exc

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": "crawl",
        "crawl_mode": mode,
        "completion": completion,
        "degraded": degraded,
        "crawl": validated.to_dict(),
    }


def render_crawl_report(
    crawl: StaticCrawlResult | CombinedDiscoveryResult,
) -> str:
    return render_json_document(build_crawl_report(crawl))


def write_crawl_report(
    crawl: StaticCrawlResult | CombinedDiscoveryResult,
    destination: str | Path,
) -> None:
    write_json_document(render_crawl_report(crawl), destination)
