"""Small v0.1 orchestration path from legacy records to Top-K results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

from vulnspider.access import (
    AccessProbeExecutionResult,
    execute_access_plan,
    extract_access_features,
    plan_credential_strip,
    plan_identifier_substitution,
    score_access_plan,
    select_top_k_access,
)
from vulnspider.discovery import (
    LegacyAdapterResult,
    LegacyCrawlerAdapter,
    LegacyCrawlRecord,
)
from vulnspider.domain import AccessProbePlan, AccessScoringResult, ProbePlan, ResponseSnapshot
from vulnspider.features import extract_minimal_features
from vulnspider.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ProbePlanner,
    ProbePlanningError,
    RequestExecutor,
    UrlLibTransport,
)
from vulnspider.observation.executor import RequestTransport
from vulnspider.scoring import ScoringResult, generate_candidates
from vulnspider.selection import (
    CombinedSelectionOutcome,
    SelectionOutcome,
    select_combined_top_k,
    select_top_k,
)


class PipelineError(ValueError):
    """Raised when adapter records cannot safely traverse the v0.1 pipeline."""


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    """The one executed baseline/probe request pair behind a FeatureVector.

    Retained only for reporting (ADR-011): it lets a report join a selected
    candidate back to the real request it was derived from without
    reporting recomputing or re-deriving anything.
    """

    feature_vector_id: str
    input_point_id: str
    probe_plan: ProbePlan
    baseline_response: ResponseSnapshot
    probe_response: ResponseSnapshot


@dataclass(frozen=True, slots=True)
class AccessProbeObservation:
    """The one executed reference/comparison request pair behind an
    AccessCandidate. Same reporting-join purpose as :class:`ProbeObservation`,
    for the separate BAC pipeline (ADR-012)."""

    candidate_id: str
    access_probe_plan: AccessProbePlan
    reference_response: ResponseSnapshot
    comparison_response: ResponseSnapshot


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    adapter_result: LegacyAdapterResult
    scoring_results: tuple[ScoringResult, ...]
    selection: SelectionOutcome
    warnings: tuple[str, ...]
    probe_observations: tuple[ProbeObservation, ...]
    elapsed_seconds: float
    access_scoring_results: tuple[AccessScoringResult, ...]
    access_probe_observations: tuple[AccessProbeObservation, ...]
    combined_selection: CombinedSelectionOutcome


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
    probe_observations: list[ProbeObservation] = []
    access_scoring_results: list[AccessScoringResult] = []
    access_probe_observations: list[AccessProbeObservation] = []
    credential_strip_planned_templates: set[str] = set()
    warnings = list(adapter_result.warnings)
    started = monotonic()

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
        probe_observations.append(
            ProbeObservation(
                feature_vector_id=feature_vector.id or "",
                input_point_id=input_point.id or "",
                probe_plan=probe_plan,
                baseline_response=execution.baseline_response,
                probe_response=execution.probe_response,
            )
        )
        scoring_results.extend(generate_candidates(feature_vector))

        template_id = request_template.id or ""
        if template_id not in credential_strip_planned_templates:
            credential_strip_planned_templates.add(template_id)
            credential_plan = plan_credential_strip(request_template)
            if credential_plan is not None:
                _run_access_plan(
                    credential_plan,
                    transport=active_transport,
                    timeout_seconds=timeout_seconds,
                    max_body_bytes=max_body_bytes,
                    access_scoring_results=access_scoring_results,
                    access_probe_observations=access_probe_observations,
                )

        identifier_plan = plan_identifier_substitution(input_point, request_template)
        if identifier_plan is not None:
            _run_access_plan(
                identifier_plan,
                transport=active_transport,
                timeout_seconds=timeout_seconds,
                max_body_bytes=max_body_bytes,
                access_scoring_results=access_scoring_results,
                access_probe_observations=access_probe_observations,
            )

    elapsed_seconds = monotonic() - started
    selection = select_top_k(scoring_results, k=top_k)
    access_selection = select_top_k_access(access_scoring_results, k=top_k)
    combined_selection = select_combined_top_k(selection, access_selection, k=top_k)
    return AnalysisResult(
        adapter_result=adapter_result,
        scoring_results=tuple(scoring_results),
        selection=selection,
        warnings=tuple(warnings),
        probe_observations=tuple(probe_observations),
        elapsed_seconds=elapsed_seconds,
        access_scoring_results=tuple(access_scoring_results),
        access_probe_observations=tuple(access_probe_observations),
        combined_selection=combined_selection,
    )


def _run_access_plan(
    plan: AccessProbePlan,
    *,
    transport: RequestTransport,
    timeout_seconds: float,
    max_body_bytes: int,
    access_scoring_results: list[AccessScoringResult],
    access_probe_observations: list[AccessProbeObservation],
) -> None:
    execution: AccessProbeExecutionResult = execute_access_plan(
        plan,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    features = extract_access_features(
        plan,
        execution.reference_response,
        execution.comparison_response,
    )
    result = score_access_plan(plan, features)
    access_scoring_results.append(result)
    access_probe_observations.append(
        AccessProbeObservation(
            candidate_id=result.candidate.id or "",
            access_probe_plan=plan,
            reference_response=execution.reference_response,
            comparison_response=execution.comparison_response,
        )
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
