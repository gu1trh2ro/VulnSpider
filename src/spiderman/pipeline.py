"""Small v0.1 orchestration path from legacy records to Top-K results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from spiderman.discovery import (
    LegacyAdapterResult,
    LegacyCrawlerAdapter,
    LegacyCrawlRecord,
)
from spiderman.features import extract_minimal_features
from spiderman.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ProbePlanner,
    ProbePlanningError,
    RequestExecutor,
    UrlLibTransport,
)
from spiderman.observation.executor import RequestTransport
from spiderman.scoring import ScoringResult, generate_candidates
from spiderman.selection import SelectionOutcome, select_top_k


class PipelineError(ValueError):
    """Raised when adapter records cannot safely traverse the v0.1 pipeline."""


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    adapter_result: LegacyAdapterResult
    scoring_results: tuple[ScoringResult, ...]
    selection: SelectionOutcome
    warnings: tuple[str, ...]


def analyze_legacy_records(
    records: Sequence[LegacyCrawlRecord | Mapping[str, Any]],
    *,
    top_k: int,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> AnalysisResult:
    """Run adapter-compatible records through the implemented v0.1 pipeline."""

    adapter_result = LegacyCrawlerAdapter().convert(records)
    input_points = {
        input_point.id or "": input_point
        for input_point in adapter_result.input_points
    }
    request_templates = {
        template.id or "": template
        for template in adapter_result.request_templates
    }
    active_transport = transport if transport is not None else UrlLibTransport()
    executor = RequestExecutor(
        transport=active_transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    planner = ProbePlanner()
    scoring_results: list[ScoringResult] = []
    warnings = list(adapter_result.warnings)

    for context in sorted(
        adapter_result.input_point_request_contexts,
        key=lambda item: item.id,
    ):
        input_point = input_points.get(context.input_point_id)
        request_template = request_templates.get(context.request_template_id)
        if input_point is None or request_template is None:
            raise PipelineError("adapter emitted an unresolved request context")
        _require_loopback_request(request_template.url)
        try:
            probe_plan = planner.plan(input_point, request_template, context)
        except ProbePlanningError as exc:
            warnings.append(
                f"input point {input_point.id} context {context.id} skipped: {exc}"
            )
            continue

        execution = executor.execute_plan(probe_plan)
        feature_vector = extract_minimal_features(
            input_point,
            probe_plan,
            execution.response_pair,
            execution.baseline_response,
            execution.probe_response,
        )
        scoring_results.extend(generate_candidates(feature_vector))

    selection = select_top_k(scoring_results, k=top_k)
    return AnalysisResult(
        adapter_result=adapter_result,
        scoring_results=tuple(scoring_results),
        selection=selection,
        warnings=tuple(warnings),
    )


def _require_loopback_request(url: str) -> None:
    hostname = urlsplit(url).hostname
    if hostname is None:
        raise PipelineError("request template URL must contain a host")
    if hostname.lower() == "localhost":
        return
    try:
        address = ip_address(hostname)
    except ValueError as exc:
        raise PipelineError(
            "CLI analysis permits only localhost or loopback IP request templates"
        ) from exc
    if not address.is_loopback:
        raise PipelineError(
            "CLI analysis permits only localhost or loopback IP request templates"
        )
