"""Unified Top-N reporting across SQL Injection, Reflected XSS, and Broken
Access Control (BAC).

Consumes a :class:`~vulnspider.selection.combined.CombinedSelectionOutcome`
-- the already-validated, already-ranked merge of the existing injection
``SelectionOutcome`` and the new BAC ``AccessSelectionOutcome`` (ADR-012). No
score is recomputed here; this module only renders. The existing
``json_report``/``html_report`` modules and their SQLi/XSS-only public
functions are unchanged and still directly usable -- this module is
additive, not a replacement.

For the injection half of each report this intentionally reuses
``html_report``'s private candidate-context/render helpers (same
subpackage): duplicating that rendering logic here would be the actual risk
to keep in sync, not the intra-package reuse.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from vulnspider.access.selection import RankedAccessScoringResult
from vulnspider.domain import (
    ACCESS_REQUEST_ROLE_COMPARISON,
    AccessCheckKind,
    AccessProbePlan,
    AccessScoreEvidence,
    Endpoint,
    InputPoint,
    ProbePlan,
    RequestInstance,
    ResponseSnapshot,
)
import vulnspider.reporting.html_report as html_report
from vulnspider.reporting.json_report import ReportingError, _evidence_record
from vulnspider.selection.combined import CombinedSelectionError, CombinedSelectionOutcome

COMBINED_REPORT_SCHEMA_VERSION = "0.1"

ACCESS_CHECK_KIND_LABELS: Mapping[AccessCheckKind, str] = MappingProxyType(
    {
        AccessCheckKind.CREDENTIAL_STRIP: "Broken Access Control (인증 검사 누락)",
        AccessCheckKind.IDENTIFIER_SUBSTITUTION: "Broken Access Control (IDOR)",
    }
)

ACCESS_GUIDANCE: Mapping[AccessCheckKind, str] = MappingProxyType(
    {
        AccessCheckKind.CREDENTIAL_STRIP: (
            "클라이언트가 자격 증명을 제거하지 않으리라고 가정하지 말고, "
            "서버에서 이 엔드포인트에 대한 인가 검사를 수행해 유효한 자격 "
            "증명이 없는 요청을 거부하세요."
        ),
        AccessCheckKind.IDENTIFIER_SUBSTITUTION: (
            "형식만 맞는 식별자를 신뢰하지 말고, 인증된 주체가 참조된 식별자에 "
            "대한 소유·접근 권한을 실제로 가지고 있는지 서버에서 확인한 뒤 "
            "데이터를 반환하세요."
        ),
    }
)

# The BAC pipeline's display tag; doubles as its chart tone name.
ACCESS_TAG = "bac"

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = MappingProxyType({})
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = MappingProxyType({})
ProbeRun = tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]
AccessProbeRun = tuple[AccessProbePlan, ResponseSnapshot, ResponseSnapshot]

_EMPTY_PROBE_RUNS: Mapping[str, ProbeRun] = MappingProxyType({})
_EMPTY_ACCESS_PROBE_RUNS: Mapping[str, AccessProbeRun] = MappingProxyType({})


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def build_combined_json_report(
    outcome: CombinedSelectionOutcome,
    *,
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    if not isinstance(outcome, CombinedSelectionOutcome):
        raise ReportingError("outcome must be a CombinedSelectionOutcome")
    try:
        outcome.validate()
    except CombinedSelectionError as exc:
        raise ReportingError("combined selection outcome is internally inconsistent") from exc

    summary = outcome.summary
    return {
        "schema_version": COMBINED_REPORT_SCHEMA_VERSION,
        "categories": ["SQLI", "REFLECTED_XSS", "BROKEN_ACCESS_CONTROL"],
        "ranking_policy": {
            "selection_key": "rank_score / exact_scorer_maximum",
            "tie_breaker": "candidate_id ascending",
        },
        "summary": {
            "total_scoring_results": summary.total_scoring_results,
            "rankable_results": summary.rankable_results,
            "unrankable_results": summary.unrankable_results,
            "selected_results": summary.selected_results,
            "top_k_requested": summary.top_k_requested,
        },
        "warnings": sorted(dict.fromkeys(str(item) for item in warnings)),
        "candidates": [
            _combined_candidate_record(entry, rank=rank)
            for rank, entry in enumerate(outcome.selected, start=1)
        ],
    }


def render_combined_json_report(
    outcome: CombinedSelectionOutcome,
    *,
    warnings: Sequence[str] = (),
) -> str:
    report = build_combined_json_report(outcome, warnings=warnings)
    try:
        return (
            json.dumps(
                report,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise ReportingError("report contains a non-finite or unsupported value") from exc


def write_combined_json_report(
    outcome: CombinedSelectionOutcome,
    destination: str | Path,
    *,
    warnings: Sequence[str] = (),
) -> None:
    Path(destination).write_text(
        render_combined_json_report(outcome, warnings=warnings),
        encoding="utf-8",
    )


def _combined_candidate_record(entry: Any, *, rank: int) -> dict[str, Any]:
    if entry.origin == "injection":
        return _injection_candidate_record(entry.injection_result, rank=rank)
    return _access_candidate_record(entry.access_result, rank=rank)


def _injection_candidate_record(item: Any, *, rank: int) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    return {
        "rank": rank,
        "category": "INJECTION",
        "vulnerability_type": candidate.vulnerability_type.value,
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "evidence": [
            _evidence_record(evidence)
            for evidence in sorted(result.evidence, key=lambda evidence: evidence.feature_name)
        ],
    }


def _access_candidate_record(item: RankedAccessScoringResult, *, rank: int) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    return {
        "rank": rank,
        "category": "BROKEN_ACCESS_CONTROL",
        "check_kind": candidate.check_kind.value,
        "candidate_id": candidate.id,
        "endpoint_id": candidate.endpoint_id,
        "input_point_id": candidate.input_point_id,
        "subject_context": candidate.subject_context.value,
        "resource_reference": candidate.resource_reference,
        "resource_owner_context": candidate.resource_owner_context,
        "access_probe_plan_id": result.access_probe_plan_id,
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "evidence": [
            _access_evidence_record(evidence)
            for evidence in sorted(result.evidence, key=lambda evidence: evidence.feature_name)
        ],
    }


def _access_evidence_record(evidence: AccessScoreEvidence) -> dict[str, Any]:
    return {
        "candidate_id": evidence.candidate_id,
        "access_probe_plan_id": evidence.access_probe_plan_id,
        "check_kind": evidence.check_kind.value if evidence.check_kind is not None else None,
        "feature_name": evidence.feature_name,
        "feature_value": evidence.feature_value,
        "observed": evidence.observed,
        "weight": evidence.weight,
        "contribution": evidence.contribution,
        "reason": evidence.reason,
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def build_combined_html_report_context(
    outcome: CombinedSelectionOutcome,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]] = (
        _EMPTY_PROBE_RUNS
    ),
    access_probe_runs: Mapping[str, AccessProbeRun] = _EMPTY_ACCESS_PROBE_RUNS,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    if not isinstance(outcome, CombinedSelectionOutcome):
        raise ReportingError("outcome must be a CombinedSelectionOutcome")
    try:
        outcome.validate()
    except CombinedSelectionError as exc:
        raise ReportingError("combined selection outcome is internally inconsistent") from exc

    summary = outcome.summary
    band_counts = {"high": 0, "medium": 0, "low": 0}
    candidates: list[dict[str, Any]] = []
    for rank, entry in enumerate(outcome.selected, start=1):
        if entry.origin == "injection":
            context = html_report._candidate_context(
                entry.injection_result,
                rank=rank,
                input_points=input_points,
                endpoints=endpoints,
                probe_runs=probe_runs,
            )
        else:
            context = _access_candidate_context(
                entry.access_result,
                rank=rank,
                endpoints=endpoints,
                access_probe_runs=access_probe_runs,
            )
        band_counts[context["priority_band"]] += 1
        candidates.append({"origin": entry.origin, "context": context})

    return {
        "schema_version": COMBINED_REPORT_SCHEMA_VERSION,
        "target": str(target),
        "summary": {
            "endpoints": len(endpoints),
            "input_points": len(input_points),
            "total_scoring_results": summary.total_scoring_results,
            "rankable_results": summary.rankable_results,
            "unrankable_results": summary.unrankable_results,
            "selected_results": summary.selected_results,
            "top_k_requested": summary.top_k_requested,
            "requests_executed": 2 * len(probe_runs) + 2 * len(access_probe_runs),
            "elapsed_seconds": float(elapsed_seconds),
        },
        "priority_bands": band_counts,
        "warnings": sorted(dict.fromkeys(str(item) for item in warnings)),
        "candidates": candidates,
        "injection_unrankable": [
            html_report._unrankable_context(result) for result in outcome.injection_unrankable
        ],
        "access_unrankable": [
            _access_unrankable_context(result) for result in outcome.access_unrankable
        ],
    }


def render_combined_html_report(
    outcome: CombinedSelectionOutcome,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]] = (
        _EMPTY_PROBE_RUNS
    ),
    access_probe_runs: Mapping[str, AccessProbeRun] = _EMPTY_ACCESS_PROBE_RUNS,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> str:
    context = build_combined_html_report_context(
        outcome,
        warnings=warnings,
        input_points=input_points,
        endpoints=endpoints,
        probe_runs=probe_runs,
        access_probe_runs=access_probe_runs,
        target=target,
        elapsed_seconds=elapsed_seconds,
    )
    return _render_document(context)


def write_combined_html_report(
    outcome: CombinedSelectionOutcome,
    destination: str | Path,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]] = (
        _EMPTY_PROBE_RUNS
    ),
    access_probe_runs: Mapping[str, AccessProbeRun] = _EMPTY_ACCESS_PROBE_RUNS,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> None:
    Path(destination).write_text(
        render_combined_html_report(
            outcome,
            warnings=warnings,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            access_probe_runs=access_probe_runs,
            target=target,
            elapsed_seconds=elapsed_seconds,
        ),
        encoding="utf-8",
    )


def _access_candidate_context(
    item: RankedAccessScoringResult,
    *,
    rank: int,
    endpoints: Mapping[str, Endpoint],
    access_probe_runs: Mapping[str, AccessProbeRun],
) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    endpoint = endpoints.get(candidate.endpoint_id)
    observation = access_probe_runs.get(candidate.id or "")
    return {
        "rank": rank,
        "candidate_id": candidate.id,
        "check_kind": candidate.check_kind.value,
        "check_kind_label": ACCESS_CHECK_KIND_LABELS.get(
            candidate.check_kind, candidate.check_kind.value
        ),
        "subject_context": candidate.subject_context.value,
        "resource_reference": candidate.resource_reference,
        "resource_owner_context": candidate.resource_owner_context,
        "input_point_id": candidate.input_point_id,
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "priority_band": html_report._priority_band(item.selection_priority),
        "endpoint": _access_endpoint_context(endpoint),
        "evidence": [
            _access_evidence_context(evidence)
            for evidence in sorted(result.evidence, key=lambda evidence: evidence.feature_name)
        ],
        "requests": _access_requests_context(observation),
        "general_guidance": ACCESS_GUIDANCE.get(candidate.check_kind),
    }


def _access_endpoint_context(endpoint: Endpoint | None) -> dict[str, Any] | None:
    if endpoint is None:
        return None
    return {
        "method": endpoint.method.value,
        "url": f"{endpoint.scheme}://{endpoint.host}{endpoint.path}",
    }


def _access_evidence_context(evidence: AccessScoreEvidence) -> dict[str, Any]:
    signal_on = (
        evidence.observed
        and evidence.feature_value is not None
        and evidence.feature_value > 0.0
    )
    return {
        "feature_name": evidence.feature_name,
        "feature_value": evidence.feature_value,
        "observed": evidence.observed,
        "weight": evidence.weight,
        "contribution": evidence.contribution,
        "reason": evidence.reason,
        "signal_on": signal_on,
    }


def _access_requests_context(
    observation: AccessProbeRun | None,
) -> list[dict[str, Any]]:
    if observation is None:
        return []
    plan, reference_response, comparison_response = observation
    return [
        {
            "role": "reference",
            **_request_context(plan.reference_request),
            "changed_aspect": None,
            "response": _response_context(reference_response),
        },
        {
            "role": ACCESS_REQUEST_ROLE_COMPARISON,
            **_request_context(plan.comparison_request),
            "changed_aspect": plan.changed_aspect,
            "response": _response_context(comparison_response),
        },
    ]


def _request_context(request: RequestInstance) -> dict[str, Any]:
    return {
        "method": request.method.value,
        "url": request.url,
        "form": [{"name": name, "value": value} for name, value in request.form],
    }


def _response_context(response: ResponseSnapshot) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "elapsed_ms": response.elapsed_ms,
        "body_length_bytes": response.body_length_bytes,
        "execution_error": response.execution_error,
    }


def _access_unrankable_context(result: Any) -> dict[str, Any]:
    candidate = result.candidate
    return {
        "candidate_id": candidate.id,
        "check_kind": candidate.check_kind.value,
        "resource_reference": candidate.resource_reference,
        "reasons": sorted(
            dict.fromkeys(
                evidence.reason for evidence in result.evidence if not evidence.observed
            )
        ),
    }


# ---------------------------------------------------------------------------
# Rendering: everything below turns a plain-data context into an HTML string.
# All interpolated text is escaped; the context above may hold text observed
# from a scanned target, which is untrusted.
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    return html_report._esc(value)


def _render_document(context: Mapping[str, Any]) -> str:
    candidate_contexts = [entry["context"] for entry in context["candidates"]]
    sections = [
        _render_header(context),
        html_report._render_stats(context["summary"]),
        html_report._render_chart_grid(
            context["summary"],
            context["priority_bands"],
            _category_rows(context["candidates"]),
        ),
        html_report._render_priority_card(
            html_report._priority_bars(candidate_contexts)
        ),
        html_report._render_band_bar(context["priority_bands"]),
        html_report._render_warnings(context["warnings"]),
        html_report._section_heading(
            "순위별 후보 상세 (SQLi / Reflected XSS / Broken Access Control)",
            "Ranked candidates",
        ),
        _render_candidates(context["candidates"]),
        _render_unrankable(context["injection_unrankable"], context["access_unrankable"]),
        html_report._render_reading_guide(),
        html_report._render_footer(),
    ]
    return html_report._wrap_document(context["target"], sections)


def _render_header(context: Mapping[str, Any]) -> str:
    return html_report._render_masthead(
        context,
        tagline=(
            "SQL Injection · Reflected XSS · Broken Access Control 후보를 검증 "
            "우선순위 순으로 정리하고, 각 순위의 근거와 실제로 전송된 요청을 "
            "함께 보여줍니다. RankScore는 먼저 검증할 대상을 고르기 위한 "
            "우선순위 점수이며, 취약점이 있다는 판정이 아닙니다."
        ),
    )


def _category_rows(
    candidates: Sequence[Mapping[str, Any]],
) -> list[tuple[str, int, str]]:
    """Count selected candidates per display category (injection + BAC)."""

    injection = [
        entry["context"] for entry in candidates if entry["origin"] == "injection"
    ]
    rows = html_report._category_rows(injection)
    access_count = len(candidates) - len(injection)
    if access_count:
        rows.append(("Broken Access Control", access_count, ACCESS_TAG))
    return rows


def _render_candidates(candidates: Sequence[Mapping[str, Any]]) -> str:
    if not candidates:
        return '<div class="empty">선정된 순위 후보가 없습니다.</div>'
    rendered = []
    for entry in candidates:
        if entry["origin"] == "injection":
            rendered.append(html_report._render_candidate(entry["context"]))
        else:
            rendered.append(_render_access_candidate(entry["context"]))
    return "\n".join(rendered)


def _render_access_candidate(candidate: Mapping[str, Any]) -> str:
    band = candidate["priority_band"]
    evidence_html = html_report._render_evidence_chart(
        candidate["evidence"],
        candidate["raw_rank_score_max"],
        band,
        default_tag=ACCESS_TAG,
    )
    return html_report._compose_card(
        band=band,
        rank=candidate["rank"],
        label=_esc(candidate["check_kind_label"]),
        endpoint_line=_render_access_endpoint_line(candidate),
        candidate=candidate,
        evidence_html=evidence_html,
        requests_html=_render_access_requests_table(candidate["requests"], band),
        guidance_html=html_report._render_guidance(
            candidate["general_guidance"], "점검 유형"
        ),
        ids_line=f'<div class="ids">candidate {_esc(candidate["candidate_id"])}</div>',
    )


def _render_access_endpoint_line(candidate: Mapping[str, Any]) -> str:
    endpoint = candidate["endpoint"]
    method = endpoint["method"] if endpoint else "?"
    url = endpoint["url"] if endpoint else "(unknown endpoint)"
    return (
        f'<div class="ep">{_esc(method)} {_esc(url)}'
        f' &mdash; <span class="param">{_esc(candidate["resource_reference"])}</span></div>'
    )


def _render_access_requests_table(
    requests: Sequence[Mapping[str, Any]],
    band: str,
) -> str:
    if not requests:
        return (
            '<div class="notice small">이 후보에 대한 실행 요청 상세가 '
            "리포트에 전달되지 않았습니다.</div>"
        )
    rows = "".join(_render_access_request_row(request) for request in requests)
    comparison = html_report._render_response_comparison(requests, band)
    return f"""<div class="why">
      <div class="lab">실제로 전송된 요청<span class="en">Executed requests</span></div>
      <table class="rec">
        <thead><tr><th>역할</th><th>요청</th><th>상태</th><th>본문 크기</th><th>소요</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      {comparison}
    </div>"""


def _render_access_request_row(request: Mapping[str, Any]) -> str:
    role = request["role"]
    method = request["method"]
    url = request["url"]
    form = request["form"]
    changed_aspect = request.get("changed_aspect")
    response = request["response"]
    request_text = f"{method} {url}"
    if form:
        pairs = "&".join(f"{item['name']}={item['value']}" for item in form)
        request_text += f" (form: {pairs})"
    if changed_aspect:
        request_text += f" — 변경한 부분: {changed_aspect}"
    status = response["execution_error"] or str(response["status_code"])
    elapsed_text = f"{response['elapsed_ms']:.1f} ms"
    return (
        "<tr>"
        f'<td class="role">{_esc(role)}</td>'
        f'<td class="pl">{_esc(request_text)}</td>'
        f'<td class="status">{_esc(status)}</td>'
        f"<td>{_esc(response['body_length_bytes'])} B</td>"
        f"<td>{_esc(elapsed_text)}</td>"
        "</tr>"
    )


def _render_unrankable(
    injection_unrankable: Sequence[Mapping[str, Any]],
    access_unrankable: Sequence[Mapping[str, Any]],
) -> str:
    if not injection_unrankable and not access_unrankable:
        return ""
    items = "".join(
        f"<li>{_esc(item['vulnerability_type'])} &middot; "
        f"input point {_esc(item['input_point_id'])}: "
        f"{_esc('; '.join(item['reasons']) or '관측된 채점 항목 없음')}</li>"
        for item in injection_unrankable
    ) + "".join(
        f"<li>{_esc(item['check_kind'])} &middot; "
        f"{_esc(item['resource_reference'])}: "
        f"{_esc('; '.join(item['reasons']) or '관측된 채점 항목 없음')}</li>"
        for item in access_unrankable
    )
    return html_report._unrankable_notice(items)
