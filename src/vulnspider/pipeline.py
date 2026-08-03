"""Orchestration paths from discovery inputs to Top-K results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from functools import partial
from ipaddress import ip_address
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

from vulnspider.discovery import (
    CanonicalDiscoveryResult,
    CombinedDiscoveryResult,
    CrawlPolicy,
    DynamicCrawler,
    DynamicCrawlCompletion,
    DynamicCrawlPolicy,
    DynamicCrawlResult,
    DynamicIntegrityError,
    DynamicRequestAuthority,
    LegacyAdapterResult,
    LegacyCrawlerAdapter,
    LegacyCrawlRecord,
    ProbeReadyStatus,
    SensitiveFormElisionPolicy,
    StaticCrawler,
    StaticCrawlerTransport,
    StaticCrawlResult,
    discover_native_combined,
    extract_static_html,
)
from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputPoint,
    InputPointRequestContext,
    ProbePlan,
    RequestTemplate,
    ResponseSnapshot,
)
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
from vulnspider.selection import SelectionOutcome, select_top_k


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
class AnalysisResult:
    adapter_result: LegacyAdapterResult | None
    scoring_results: tuple[ScoringResult, ...]
    selection: SelectionOutcome
    warnings: tuple[str, ...]
    probe_observations: tuple[ProbeObservation, ...]
    elapsed_seconds: float
    discovery_result: CanonicalDiscoveryResult | None = None
    crawl_result: StaticCrawlResult | None = None
    combined_result: CombinedDiscoveryResult | None = None

    @property
    def dynamic_crawl_result(self) -> DynamicCrawlResult | None:
        """Return Dynamic crawl evidence when combined discovery was requested."""

        if self.combined_result is None:
            return None
        return self.combined_result.dynamic_crawl

    @property
    def endpoints(self) -> tuple[Endpoint, ...]:
        if self.discovery_result is not None:
            return self.discovery_result.endpoints
        if self.adapter_result is not None:
            return self.adapter_result.endpoints
        raise PipelineError("analysis result has no discovery source")

    @property
    def input_points(self) -> tuple[InputPoint, ...]:
        if self.discovery_result is not None:
            return self.discovery_result.input_points
        if self.adapter_result is not None:
            return self.adapter_result.input_points
        raise PipelineError("analysis result has no discovery source")


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
    ready_contexts: list[
        tuple[InputPoint, RequestTemplate, InputPointRequestContext]
    ] = []
    for context in sorted(
        adapter_result.input_point_request_contexts,
        key=lambda item: item.id,
    ):
        input_point = input_points.get(context.input_point_id)
        request_template = request_templates.get(context.request_template_id)
        if input_point is None or request_template is None:
            raise PipelineError("adapter emitted an unresolved request context")
        ready_contexts.append((input_point, request_template, context))

    return _analyze_contexts(
        ready_contexts,
        top_k=top_k,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        initial_warnings=adapter_result.warnings,
        adapter_result=adapter_result,
    )


def analyze_discovery_result(
    discovery_result: CanonicalDiscoveryResult,
    *,
    top_k: int,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> AnalysisResult:
    """Analyze READY GET contexts from a canonical native discovery result."""

    if not isinstance(discovery_result, CanonicalDiscoveryResult):
        raise PipelineError(
            "discovery_result must be a CanonicalDiscoveryResult"
        )
    discovery_result.validate()
    return _analyze_contexts(
        discovery_result.ready_contexts(),
        top_k=top_k,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        initial_warnings=tuple(
            f"discovery {warning.code}: {warning.message}"
            for warning in discovery_result.warnings
        ),
        discovery_result=discovery_result,
        allowed_methods=frozenset({HttpMethod.GET}),
    )


def analyze_url(
    root_url: str,
    *,
    top_k: int,
    crawl_policy: CrawlPolicy | None = None,
    crawler: StaticCrawler | None = None,
    crawler_transport: StaticCrawlerTransport | None = None,
    dynamic_authority: DynamicRequestAuthority | None = None,
    dynamic_policy: DynamicCrawlPolicy | None = None,
    dynamic_crawler: DynamicCrawler | None = None,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> AnalysisResult:
    """Analyze Static discovery, or explicit Static-plus-Dynamic discovery."""

    if crawler is not None and crawler_transport is not None:
        raise PipelineError(
            "crawler and crawler_transport cannot be supplied together"
        )
    if dynamic_authority is None and (
        dynamic_policy is not None or dynamic_crawler is not None
    ):
        raise PipelineError(
            "dynamic policy and crawler require explicit dynamic authority"
        )
    if dynamic_authority is not None:
        try:
            combined = discover_native_combined(
                root_url,
                authority=dynamic_authority,
                static_policy=crawl_policy,
                dynamic_policy=dynamic_policy,
                static_crawler=_combined_static_crawler(
                    crawler=crawler,
                    crawler_transport=crawler_transport,
                ),
                dynamic_crawler=dynamic_crawler,
            )
        except TypeError as exc:
            raise DynamicIntegrityError(
                "combined discovery boundary returned an invalid type"
            ) from exc
        if type(combined) is not CombinedDiscoveryResult:
            raise DynamicIntegrityError(
                "combined discovery must return CombinedDiscoveryResult"
            )
        try:
            combined = replace(combined)
        except (TypeError, ValueError) as exc:
            raise DynamicIntegrityError(
                "combined discovery wrapper failed revalidation"
            ) from exc
        analysis = analyze_discovery_result(
            combined.discovery,
            top_k=top_k,
            transport=transport,
            timeout_seconds=timeout_seconds,
            max_body_bytes=max_body_bytes,
        )
        return replace(
            analysis,
            warnings=(
                *analysis.warnings,
                *_combined_handoff_warnings(combined),
            ),
            crawl_result=combined.static_crawl,
            combined_result=combined,
        )

    active_crawler = crawler
    if active_crawler is None:
        active_crawler = (
            StaticCrawler(transport=crawler_transport)
            if crawler_transport is not None
            else StaticCrawler()
        )
    crawl_result = active_crawler.crawl(root_url, crawl_policy)
    analysis = analyze_discovery_result(
        crawl_result.discovery,
        top_k=top_k,
        transport=transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    return replace(analysis, crawl_result=crawl_result)


_COMBINED_STATIC_EXTRACTOR = partial(
    extract_static_html,
    sensitive_form_policy=SensitiveFormElisionPolicy(),
)


def _combined_static_crawler(
    *,
    crawler: StaticCrawler | None,
    crawler_transport: StaticCrawlerTransport | None,
) -> StaticCrawler:
    """Bind pre-canonical sensitive-form elision only for combined mode."""

    if crawler is not None:
        if type(crawler) is not StaticCrawler:
            raise TypeError("crawler must be a StaticCrawler")
        return replace(crawler, extractor=_COMBINED_STATIC_EXTRACTOR)
    if crawler_transport is None:
        return StaticCrawler(extractor=_COMBINED_STATIC_EXTRACTOR)
    return StaticCrawler(
        transport=crawler_transport,
        extractor=_COMBINED_STATIC_EXTRACTOR,
    )


def _combined_handoff_warnings(
    combined: CombinedDiscoveryResult,
) -> tuple[str, ...]:
    ready = sum(
        item.status == ProbeReadyStatus.READY
        for item in combined.discovery.probe_readiness
    )
    not_ready = sum(
        item.status == ProbeReadyStatus.NOT_READY
        for item in combined.discovery.probe_readiness
    )
    warnings = [
        "discovery NATIVE_COMBINED: "
        f"READY contexts={ready}; NOT_READY contexts={not_ready}"
    ]
    if combined.completion == DynamicCrawlCompletion.DEGRADED:
        warnings.append(
            "discovery DYNAMIC_INCOMPLETE: validated partial Dynamic "
            "discovery was retained"
        )
    return tuple(warnings)


def _analyze_contexts(
    contexts: Sequence[
        tuple[InputPoint, RequestTemplate, InputPointRequestContext]
    ],
    *,
    top_k: int,
    transport: RequestTransport | None,
    timeout_seconds: float,
    max_body_bytes: int,
    initial_warnings: Sequence[str],
    adapter_result: LegacyAdapterResult | None = None,
    discovery_result: CanonicalDiscoveryResult | None = None,
    allowed_methods: frozenset[HttpMethod] | None = None,
) -> AnalysisResult:
    active_transport = transport if transport is not None else UrlLibTransport()
    executor = RequestExecutor(
        transport=active_transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    planner = ProbePlanner()
    scoring_results: list[ScoringResult] = []
    probe_observations: list[ProbeObservation] = []
    warnings = list(initial_warnings)
    started = monotonic()

    for input_point, request_template, context in sorted(
        contexts,
        key=lambda item: item[2].id,
    ):
        if (
            allowed_methods is not None
            and request_template.method not in allowed_methods
        ):
            warnings.append(
                f"input point {input_point.id} context {context.id} skipped: "
                "native static analysis executes GET request contexts only"
            )
            continue
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

    elapsed_seconds = monotonic() - started
    selection = select_top_k(scoring_results, k=top_k)
    return AnalysisResult(
        adapter_result=adapter_result,
        scoring_results=tuple(scoring_results),
        selection=selection,
        warnings=tuple(warnings),
        probe_observations=tuple(probe_observations),
        elapsed_seconds=elapsed_seconds,
        discovery_result=discovery_result,
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
