"""Static HTML dashboard reporting for deterministic v0.1 Top-K outcomes.

Renders the same validated `SelectionOutcome` the JSON reporter renders
(`vulnspider.reporting.json_report`), plus optional display-only joins to the
`InputPoint`/`Endpoint` objects the adapter already produced and the
`ProbePlan`/`ResponseSnapshot` pair `execute_probe_plan()` already produced
for each `FeatureVector`. No score is recomputed and no evidence is
invented here (ADR-011, docs/PROTOTYPE_V0_1.md §13); the charts are a second
reading of those same numbers.

Body copy is Korean because the report is read by the project team; domain
proper nouns (SQL Injection, Reflected XSS), identifiers, URLs, and feature
names stay verbatim so they match the JSON report and the docs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from vulnspider.domain import (
    Endpoint,
    InputPoint,
    ProbePlan,
    RequestInstance,
    ResponseSnapshot,
    ScoreEvidence,
    VulnerabilityType,
)
from vulnspider.reporting import charts
from vulnspider.reporting.charts import Bar, Slice, escape_text
from vulnspider.reporting.json_report import ReportingError
from vulnspider.scoring import ScoringResult
from vulnspider.selection import RankedScoringResult, SelectionError, SelectionOutcome

HTML_REPORT_SCHEMA_VERSION = "0.1"

PRIORITY_BAND_HIGH = 0.7
PRIORITY_BAND_MEDIUM = 0.4

BAND_ORDER = ("high", "medium", "low")

BAND_LABELS: Mapping[str, str] = MappingProxyType(
    {"high": "높음", "medium": "보통", "low": "낮음"}
)

VULNERABILITY_LABELS: Mapping[VulnerabilityType, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI: "SQL Injection",
        VulnerabilityType.REFLECTED_XSS: "Reflected XSS",
    }
)

VULNERABILITY_SHORT_TAGS: Mapping[str, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI.value: "sqli",
        VulnerabilityType.REFLECTED_XSS.value: "xss",
    }
)

VULNERABILITY_TONES: Mapping[str, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI.value: "sqli",
        VulnerabilityType.REFLECTED_XSS.value: "xss",
    }
)

GENERAL_GUIDANCE: Mapping[VulnerabilityType, str] = MappingProxyType(
    {
        VulnerabilityType.SQLI: (
            "SQL 문자열을 이어 붙이지 말고 파라미터 바인딩(prepared "
            "statement)을 사용하고, 데이터베이스 계정 권한을 최소한으로 "
            "제한하세요."
        ),
        VulnerabilityType.REFLECTED_XSS: (
            "응답에 다시 출력되는 입력값에 출력 맥락에 맞는 인코딩을 적용하고, "
            "엄격한 Content-Security-Policy를 설정하며, 가능한 곳에서는 입력값을 "
            "검증하세요."
        ),
    }
)

ProbeRun = tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = MappingProxyType({})
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = MappingProxyType({})
_EMPTY_PROBE_RUNS: Mapping[str, ProbeRun] = MappingProxyType({})


def build_html_report_context(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    """Build a plain-data rendering context from an already-validated outcome.

    This performs no scoring, ranking, or feature-extraction work; it only
    joins the outcome to optional display data the caller already produced
    elsewhere in the pipeline.
    """

    if not isinstance(outcome, SelectionOutcome):
        raise ReportingError("outcome must be a SelectionOutcome")
    try:
        outcome.validate()
    except SelectionError as exc:
        raise ReportingError("selection outcome is internally inconsistent") from exc

    summary = outcome.summary
    band_counts = {"high": 0, "medium": 0, "low": 0}
    candidates: list[dict[str, Any]] = []
    for rank, item in enumerate(outcome.selected, start=1):
        candidate_context = _candidate_context(
            item,
            rank=rank,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
        )
        band_counts[candidate_context["priority_band"]] += 1
        candidates.append(candidate_context)

    return {
        "schema_version": HTML_REPORT_SCHEMA_VERSION,
        "target": str(target),
        "summary": {
            "endpoints": len(endpoints),
            "input_points": len(input_points),
            "total_scoring_results": summary.total_scoring_results,
            "rankable_results": summary.rankable_results,
            "unrankable_results": summary.unrankable_results,
            "selected_results": summary.selected_results,
            "top_k_requested": summary.top_k_requested,
            "requests_executed": 2 * len(probe_runs),
            "elapsed_seconds": float(elapsed_seconds),
        },
        "priority_bands": band_counts,
        "warnings": sorted(dict.fromkeys(str(item) for item in warnings)),
        "candidates": candidates,
        "unrankable": [
            _unrankable_context(result) for result in outcome.unrankable
        ],
    }


def render_html_report(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> str:
    context = build_html_report_context(
        outcome,
        warnings=warnings,
        input_points=input_points,
        endpoints=endpoints,
        probe_runs=probe_runs,
        target=target,
        elapsed_seconds=elapsed_seconds,
    )
    return _render_document(context)


def write_html_report(
    outcome: SelectionOutcome,
    destination: str | Path,
    *,
    warnings: Sequence[str] = (),
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    target: str = "",
    elapsed_seconds: float = 0.0,
) -> None:
    Path(destination).write_text(
        render_html_report(
            outcome,
            warnings=warnings,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            target=target,
            elapsed_seconds=elapsed_seconds,
        ),
        encoding="utf-8",
    )


def _priority_band(priority: float) -> str:
    if priority >= PRIORITY_BAND_HIGH:
        return "high"
    if priority >= PRIORITY_BAND_MEDIUM:
        return "medium"
    return "low"


def _candidate_context(
    item: RankedScoringResult,
    *,
    rank: int,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    vulnerability_type = candidate.vulnerability_type
    input_point = input_points.get(candidate.input_point_id)
    endpoint = (
        endpoints.get(input_point.endpoint_id) if input_point is not None else None
    )
    return {
        "rank": rank,
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": vulnerability_type.value,
        "vulnerability_label": VULNERABILITY_LABELS.get(
            vulnerability_type, vulnerability_type.value
        ),
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "priority_band": _priority_band(item.selection_priority),
        "endpoint": _endpoint_context(endpoint, input_point),
        "evidence": [
            _evidence_context(evidence)
            for evidence in sorted(
                result.evidence, key=lambda evidence: evidence.feature_name
            )
        ],
        "requests": _requests_context(result.feature_vector_id, probe_runs),
        "general_guidance": GENERAL_GUIDANCE.get(vulnerability_type),
    }


def _endpoint_context(
    endpoint: Endpoint | None,
    input_point: InputPoint | None,
) -> dict[str, Any] | None:
    if input_point is None:
        return None
    return {
        "method": endpoint.method.value if endpoint is not None else None,
        "url": (
            f"{endpoint.scheme}://{endpoint.host}{endpoint.path}"
            if endpoint is not None
            else None
        ),
        "location": input_point.location.value,
        "name": input_point.name,
        "occurrence_index": input_point.occurrence_index,
    }


def _evidence_context(evidence: ScoreEvidence) -> dict[str, Any]:
    signal_on = (
        evidence.observed
        and evidence.feature_value is not None
        and evidence.feature_value > 0.0
    )
    return {
        "vulnerability_type": (
            evidence.vulnerability_type.value
            if evidence.vulnerability_type is not None
            else None
        ),
        "feature_name": evidence.feature_name,
        "feature_value": evidence.feature_value,
        "observed": evidence.observed,
        "weight": evidence.weight,
        "contribution": evidence.contribution,
        "reason": evidence.reason,
        "signal_on": signal_on,
    }


def _requests_context(
    feature_vector_id: str,
    probe_runs: Mapping[str, ProbeRun],
) -> list[dict[str, Any]]:
    run = probe_runs.get(feature_vector_id)
    if run is None:
        return []
    probe_plan, baseline_response, probe_response = run
    return [
        {
            "role": "baseline",
            **_request_context(probe_plan.baseline_request),
            "injected_value": None,
            "response": _response_context(baseline_response),
        },
        {
            "role": "probe",
            **_request_context(probe_plan.probe_request),
            "injected_value": probe_plan.probe_marker,
            "changed_field": (
                probe_plan.changed_fields[0] if probe_plan.changed_fields else None
            ),
            "response": _response_context(probe_response),
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


def _unrankable_context(result: ScoringResult) -> dict[str, Any]:
    candidate = result.candidate
    return {
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "reasons": sorted(
            dict.fromkeys(
                evidence.reason
                for evidence in result.evidence
                if not evidence.observed
            )
        ),
    }


# ---------------------------------------------------------------------------
# Rendering: everything below turns a plain-data context into an HTML string.
# All interpolated text is escaped; the context above may hold text observed
# from a scanned target (endpoint paths, evidence reasons, warnings), which
# is untrusted. Chart colours come from a tone whitelist in `charts`, never
# from observed data.
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    return escape_text(value)


def _fmt_number(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _fmt_percent(priority: float) -> str:
    return f"{priority * 100:.1f}".rstrip("0").rstrip(".")


def _fmt_bytes(value: Any) -> str:
    return f"{value} B"


def _render_document(context: Mapping[str, Any]) -> str:
    sections = [
        _render_header(context),
        _render_stats(context["summary"]),
        _render_chart_grid(
            context["summary"],
            context["priority_bands"],
            _category_rows(context["candidates"]),
        ),
        _render_priority_card(_priority_bars(context["candidates"])),
        _render_band_bar(context["priority_bands"]),
        _render_warnings(context["warnings"]),
        _section_heading("순위별 후보 상세", "Ranked candidates"),
        _render_candidates(context["candidates"]),
        _render_unrankable(context["unrankable"]),
        _render_reading_guide(),
        _render_footer(),
    ]
    return _wrap_document(context["target"], sections)


def _wrap_document(target: str, sections: Sequence[str]) -> str:
    title = "VulnSpider 리포트" + (f" — {target}" if target else "")
    body = "\n\n".join(section for section in sections if section)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="ko">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_DOCUMENT_STYLE}</style>\n"
        f'</head>\n<body>\n<div class="wrap">\n\n{body}\n\n</div>\n</body>\n</html>\n'
    )


def _section_heading(korean: str, english: str) -> str:
    return (
        f'<h2 class="section">{_esc(korean)}'
        f'<span class="en">{_esc(english)}</span></h2>'
    )


def _render_header(context: Mapping[str, Any]) -> str:
    return _render_masthead(
        context,
        tagline=(
            "SQL Injection · Reflected XSS 후보를 검증 우선순위 순으로 "
            "정리하고, 각 순위의 근거와 실제로 전송된 요청을 함께 보여줍니다. "
            "RankScore는 먼저 검증할 대상을 고르기 위한 우선순위 점수이며, "
            "취약점이 있다는 판정이 아닙니다."
        ),
    )


def _render_masthead(context: Mapping[str, Any], *, tagline: str) -> str:
    target = context["target"]
    schema_version = context["schema_version"]
    target_line = (
        f'<div class="target">대상 &rarr; {_esc(target)}</div>' if target else ""
    )
    version_line = f"v0.1 &middot; 스캔 리포트 (schema {_esc(schema_version)})"
    return (
        '<header class="masthead">\n'
        '  <div class="brand">\n'
        "    <h1>VulnSpider</h1>"
        f'<span class="ver">{version_line}</span>\n'
        "  </div>\n"
        f'  <div class="tagline">{_esc(tagline)}</div>\n'
        f"  {target_line}\n"
        "</header>"
    )


def _render_stats(summary: Mapping[str, Any]) -> str:
    stats = (
        (str(summary["endpoints"]), "엔드포인트", "Endpoints"),
        (str(summary["input_points"]), "입력 지점", "Input points"),
        (str(summary["selected_results"]), "선정 후보", "Selected (Top-K)"),
        (str(summary["requests_executed"]), "실행된 요청", "Requests executed"),
        (f"{summary['elapsed_seconds']:.1f}s", "소요 시간", "Elapsed"),
    )
    cells = "".join(
        f'<div class="stat"><div class="n">{_esc(value)}</div>'
        f'<div class="l">{_esc(korean)}</div>'
        f'<div class="l en">{_esc(english)}</div></div>'
        for value, korean, english in stats
    )
    return f'<div class="stats">{cells}</div>'


# -- overview charts ---------------------------------------------------------


def _render_chart_grid(
    summary: Mapping[str, Any],
    bands: Mapping[str, int],
    category_rows: Sequence[tuple[str, int, str]],
) -> str:
    cards = "\n".join(
        (
            _render_band_donut(bands),
            _render_category_card(category_rows),
            _render_funnel_card(summary),
        )
    )
    return f'<div class="chart-grid">\n{cards}\n</div>'


def _render_band_donut(bands: Mapping[str, int]) -> str:
    total = sum(bands[band] for band in BAND_ORDER)
    slices = [
        Slice(label=BAND_LABELS[band], value=bands[band], tone=band)
        for band in BAND_ORDER
    ]
    body = charts.donut_chart(
        slices,
        center_value=str(total),
        center_caption="선정된 후보를 우선순위 구간별로 나눈 분포입니다.",
        empty_caption="선정된 후보가 없습니다.",
    )
    return charts.chart_card(
        "우선순위 구간 분포",
        body,
        english="Priority bands",
        note=(
            f"구간 기준: 높음 {_fmt_percent(PRIORITY_BAND_HIGH)}% 이상, "
            f"보통 {_fmt_percent(PRIORITY_BAND_MEDIUM)}% 이상, 나머지는 낮음."
        ),
    )


def _category_rows(
    candidates: Sequence[Mapping[str, Any]],
) -> list[tuple[str, int, str]]:
    counts: dict[tuple[str, str], int] = {}
    for candidate in candidates:
        key = (
            str(candidate["vulnerability_label"]),
            str(candidate["vulnerability_type"]),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        (label, counts[(label, raw_type)], VULNERABILITY_TONES.get(raw_type, "accent"))
        for label, raw_type in sorted(counts)
    ]


def _render_category_card(rows: Sequence[tuple[str, int, str]]) -> str:
    largest = max((count for _label, count, _tone in rows), default=0)
    bars = [
        Bar(
            label=label,
            value_label=f"{count}건",
            ratio=(count / largest) if largest else 0.0,
            tone=tone,
        )
        for label, count, tone in rows
    ]
    body = charts.bar_chart(bars, empty_caption="선정된 후보가 없습니다.")
    return charts.chart_card(
        "유형별 선정 후보",
        body,
        english="Selected by type",
        note="Top-K에 선정된 후보만 세며, 전체 채점 결과 수와는 다릅니다.",
    )


def _render_funnel_card(summary: Mapping[str, Any]) -> str:
    steps = (
        ("엔드포인트", summary["endpoints"], "accent"),
        ("입력 지점", summary["input_points"], "accent"),
        ("채점 결과", summary["total_scoring_results"], "accent"),
        ("순위 산정 가능", summary["rankable_results"], "medium"),
        ("선정(Top-K)", summary["selected_results"], "high"),
    )
    largest = max((value for _label, value, _tone in steps), default=0)
    bars = [
        Bar(
            label=label,
            value_label=str(value),
            ratio=(value / largest) if largest else 0.0,
            tone=tone,
        )
        for label, value, tone in steps
    ]
    body = charts.bar_chart(bars)
    unrankable = summary["unrankable_results"]
    return charts.chart_card(
        "분석 파이프라인 요약",
        body,
        english="Pipeline funnel",
        note=(
            f"요청한 Top-K는 {summary['top_k_requested']}개이고, 순위 산정 "
            f"불가로 제외된 결과는 {unrankable}개입니다."
        ),
    )


def _priority_bars(candidates: Sequence[Mapping[str, Any]]) -> list[Bar]:
    bars: list[Bar] = []
    for candidate in candidates:
        endpoint = candidate.get("endpoint")
        caption = _endpoint_caption(endpoint)
        raw = _fmt_number(candidate["raw_rank_score"])
        raw_max = _fmt_number(candidate["raw_rank_score_max"])
        label = candidate.get("vulnerability_label") or candidate.get(
            "check_kind_label", ""
        )
        bars.append(
            Bar(
                label=f"#{candidate['rank']} {label}",
                value_label=f"{_fmt_percent(candidate['selection_priority'])}%",
                ratio=candidate["selection_priority"],
                tone=candidate["priority_band"],
                caption=f"{caption} · RankScore {raw} / {raw_max}",
            )
        )
    return bars


def _endpoint_caption(endpoint: Mapping[str, Any] | None) -> str:
    if endpoint is None:
        return "엔드포인트 정보 없음"
    method = endpoint.get("method") or "?"
    url = endpoint.get("url") or "(unknown endpoint)"
    name = endpoint.get("name")
    if name:
        return f"{method} {url} · {str(endpoint.get('location', '')).lower()}.{name}"
    return f"{method} {url}"


def _render_priority_card(bars: Sequence[Bar]) -> str:
    body = charts.bar_chart(
        bars, empty_caption="선정된 후보가 없어 비교할 항목이 없습니다."
    )
    return charts.chart_card(
        "선정 후보 우선순위 비교",
        body,
        english="Priority comparison",
        note=(
            "막대 길이는 각 후보의 RankScore를 해당 스코어러의 정확한 최댓값으로 "
            "나눈 값입니다. 유형이 다른 후보를 같은 축에서 비교하기 위한 정규화이며, "
            "취약점 판정 값이 아닙니다."
        ),
    )


def _render_band_bar(bands: Mapping[str, int]) -> str:
    pills = "".join(
        f'<span class="pill"><span class="dot {band}"></span>'
        f"우선순위 {_esc(BAND_LABELS[band])} {_esc(bands[band])}건</span>"
        for band in BAND_ORDER
    )
    return f'<div class="bandbar">{pills}</div>'


def _render_warnings(warnings: Sequence[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{_esc(item)}</li>" for item in warnings)
    return (
        '<div class="notice">'
        '<div class="lab">경고<span class="en">Warnings</span></div>'
        f"<ul>{items}</ul></div>"
    )


# -- candidate cards ---------------------------------------------------------


def _render_candidates(candidates: Sequence[Mapping[str, Any]]) -> str:
    if not candidates:
        return '<div class="empty">선정된 순위 후보가 없습니다.</div>'
    return "\n".join(_render_candidate(candidate) for candidate in candidates)


def _render_candidate(candidate: Mapping[str, Any]) -> str:
    band = candidate["priority_band"]
    rank = candidate["rank"]
    vulnerability_label = _esc(candidate["vulnerability_label"])
    endpoint_line = _render_endpoint_line(candidate["endpoint"])
    evidence_html = _render_evidence_chart(
        candidate["evidence"], candidate["raw_rank_score_max"], band
    )
    requests_html = _render_requests_table(candidate["requests"], band)
    guidance_html = _render_guidance(candidate["general_guidance"], "취약점 유형")
    ids_line = (
        f'<div class="ids">candidate {_esc(candidate["candidate_id"])} '
        f"&middot; feature vector {_esc(candidate['feature_vector_id'])}</div>"
    )
    return _compose_card(
        band=band,
        rank=rank,
        label=vulnerability_label,
        endpoint_line=endpoint_line,
        candidate=candidate,
        evidence_html=evidence_html,
        requests_html=requests_html,
        guidance_html=guidance_html,
        ids_line=ids_line,
    )


def _compose_card(
    *,
    band: str,
    rank: int,
    label: str,
    endpoint_line: str,
    candidate: Mapping[str, Any],
    evidence_html: str,
    requests_html: str,
    guidance_html: str,
    ids_line: str,
) -> str:
    percent = _fmt_percent(candidate["selection_priority"])
    raw_score = _fmt_number(candidate["raw_rank_score"])
    raw_score_max = _fmt_number(candidate["raw_rank_score_max"])
    band_label = _esc(BAND_LABELS[band])
    return f"""<article class="finding {band}">
    <div class="fhead">
      <div class="fhead-main">
        <div class="rank">#{rank}</div>
        <div class="vtype">{label}</div>
        {endpoint_line}
      </div>
      <div class="meterwrap">
        <div class="prio {band}">{percent}%</div>
        <div class="meter"><i class="{band}" style="width:{percent}%"></i></div>
        <div class="pcaption">우선순위 {band_label} &middot; RankScore {raw_score} / {raw_score_max}</div>
      </div>
    </div>

    <div class="why">
      <div class="lab">이 순위가 나온 근거<span class="en">Why it ranks here</span></div>
      {evidence_html}
    </div>

    {requests_html}

    {guidance_html}
    {ids_line}
  </article>"""


def _render_endpoint_line(endpoint: Mapping[str, Any] | None) -> str:
    if endpoint is None:
        return '<div class="ep unknown">엔드포인트 정보가 리포트에 전달되지 않았습니다.</div>'
    method = endpoint["method"] or "?"
    url = endpoint["url"] or "(unknown endpoint)"
    location = endpoint["location"].lower()
    name = endpoint["name"]
    occurrence = endpoint["occurrence_index"]
    occurrence_label = f"[{occurrence}]" if occurrence is not None else ""
    return (
        f'<div class="ep">{_esc(method)} {_esc(url)}'
        f' &mdash; <span class="param">{_esc(location)}.{_esc(name)}'
        f"{_esc(occurrence_label)}</span></div>"
    )


def _render_evidence_chart(
    evidence: Sequence[Mapping[str, Any]],
    raw_rank_score_max: float,
    band: str,
    *,
    default_tag: str = "",
) -> str:
    """Draw one bar per evidence term, sized by its share of the scorer maximum.

    The values are exactly the contributions the JSON report already lists;
    `default_tag` labels evidence that carries no `vulnerability_type` of its
    own (the BAC pipeline's `AccessScoreEvidence`).
    """

    if not evidence:
        return '<div class="chart-empty">기록된 근거 항목이 없습니다.</div>'
    denominator = float(raw_rank_score_max) or 1.0
    bars = [
        _evidence_bar(item, denominator, band, default_tag) for item in evidence
    ]
    return charts.bar_chart(bars)


def _evidence_bar(
    evidence: Mapping[str, Any],
    denominator: float,
    band: str,
    default_tag: str = "",
) -> Bar:
    raw_type = evidence.get("vulnerability_type") or ""
    tag = VULNERABILITY_SHORT_TAGS.get(raw_type, raw_type.lower()) or default_tag
    name = evidence["feature_name"]
    label = f"[{tag}] {name}" if tag else str(name)
    weight = _fmt_number(evidence["weight"])
    if evidence["observed"]:
        value = _fmt_number(evidence["feature_value"])
        contribution = _fmt_number(evidence["contribution"])
        return Bar(
            label=label,
            value_label=f"+{contribution}",
            ratio=float(evidence["contribution"]) / denominator,
            tone=band if evidence["signal_on"] else "muted",
            caption=f"{name}={value} × 가중치 +{weight} → 기여 +{contribution}",
        )
    return Bar(
        label=label,
        value_label="미관측",
        ratio=0.0,
        tone="muted",
        caption=f"미관측 — {evidence['reason']} (가중치 +{weight})",
    )


def _render_requests_table(requests: Sequence[Mapping[str, Any]], band: str) -> str:
    if not requests:
        return (
            '<div class="notice small">이 후보에 대한 실행 요청 상세가 '
            "리포트에 전달되지 않았습니다.</div>"
        )
    rows = "".join(_render_request_row(request) for request in requests)
    comparison = _render_response_comparison(requests, band)
    return f"""<div class="why">
      <div class="lab">실제로 전송된 요청<span class="en">Executed requests</span></div>
      <table class="rec">
        <thead><tr><th>역할</th><th>요청</th><th>상태</th><th>본문 크기</th><th>소요</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      {comparison}
    </div>"""


def _render_request_row(request: Mapping[str, Any]) -> str:
    role = request["role"]
    method = request["method"]
    url = request["url"]
    form = request["form"]
    injected = request.get("injected_value")
    response = request["response"]
    request_text = f"{method} {url}"
    if form:
        pairs = "&".join(f"{item['name']}={item['value']}" for item in form)
        request_text += f" (form: {pairs})"
    if injected:
        request_text += f" — 주입값: {injected}"
    status = response["execution_error"] or str(response["status_code"])
    elapsed_text = f"{response['elapsed_ms']:.1f} ms"
    return (
        "<tr>"
        f'<td class="role">{_esc(role)}</td>'
        f'<td class="pl">{_esc(request_text)}</td>'
        f'<td class="status">{_esc(status)}</td>'
        f"<td>{_esc(_fmt_bytes(response['body_length_bytes']))}</td>"
        f"<td>{_esc(elapsed_text)}</td>"
        "</tr>"
    )


def _render_response_comparison(
    requests: Sequence[Mapping[str, Any]],
    band: str,
) -> str:
    lengths = [float(item["response"]["body_length_bytes"]) for item in requests]
    elapsed = [float(item["response"]["elapsed_ms"]) for item in requests]
    largest_length = max(lengths, default=0.0)
    largest_elapsed = max(elapsed, default=0.0)
    bars: list[Bar] = []
    for index, request in enumerate(requests):
        tone = "muted" if request["role"] in {"baseline", "reference"} else band
        role = str(request["role"])
        bars.append(
            Bar(
                label=f"{role} 본문",
                value_label=_fmt_bytes(request["response"]["body_length_bytes"]),
                ratio=(lengths[index] / largest_length) if largest_length else 0.0,
                tone=tone,
            )
        )
    for index, request in enumerate(requests):
        tone = "muted" if request["role"] in {"baseline", "reference"} else band
        role = str(request["role"])
        bars.append(
            Bar(
                label=f"{role} 소요",
                value_label=f"{elapsed[index]:.1f} ms",
                ratio=(elapsed[index] / largest_elapsed) if largest_elapsed else 0.0,
                tone=tone,
            )
        )
    return (
        '<div class="subchart">'
        '<div class="lab">응답 비교<span class="en">Response comparison</span></div>'
        f"{charts.bar_chart(bars)}"
        "</div>"
    )


def _render_guidance(guidance: str | None, subject: str) -> str:
    if not guidance:
        return ""
    return (
        '<div class="fix"><b>일반 대응 가이드</b><br>'
        f"{_esc(guidance)}<br>"
        f"<i>해당 {_esc(subject)}에 대한 일반적인 권고이며, 이 후보가 실제로 "
        "악용 가능하다는 의미는 아닙니다.</i></div>"
    )


def _render_unrankable(unrankable: Sequence[Mapping[str, Any]]) -> str:
    if not unrankable:
        return ""
    items = "".join(
        f"<li>{_esc(item['vulnerability_type'])} &middot; "
        f"input point {_esc(item['input_point_id'])}: "
        f"{_esc('; '.join(item['reasons']) or '관측된 채점 항목 없음')}</li>"
        for item in unrankable
    )
    return _unrankable_notice(items)


def _unrankable_notice(items: str) -> str:
    return (
        '<div class="notice">'
        '<div class="lab">순위 산정 불가<span class="en">Unrankable</span></div>'
        '<p class="hint">관측된 채점 항목이 없어 순위에서 제외된 결과입니다. '
        "안전하다는 뜻이 아니라 이번 관측으로는 판단할 근거가 없다는 뜻입니다.</p>"
        f"<ul>{items}</ul></div>"
    )


def _render_reading_guide() -> str:
    rows = (
        (
            "RankScore / 우선순위(%)",
            "먼저 검증할 순서를 정하기 위한 점수입니다. 백분율은 RankScore를 "
            "해당 스코어러의 정확한 최댓값으로 나눈 값이며, 취약점이 존재할 "
            "가능성의 크기를 나타내지 않습니다.",
        ),
        (
            "근거 막대",
            "각 feature의 기여도(feature 값 × 가중치)를 스코어러 최댓값 대비 "
            "비율로 그린 것입니다. JSON 리포트의 evidence와 동일한 값입니다.",
        ),
        (
            "미관측",
            "값이 0이라는 뜻이 아니라 이번 관측에서 해당 feature를 얻지 "
            "못했다는 뜻입니다. 0으로 대체하지 않고 그대로 표시합니다.",
        ),
        (
            "실제로 전송된 요청",
            "v0.1은 입력 지점마다 baseline 1회, probe 1회만 전송합니다. "
            "표에 보이는 두 요청이 실제로 전송된 전부입니다.",
        ),
    )
    items = "".join(
        f"<div class='guide-row'><div class='guide-term'>{_esc(term)}</div>"
        f"<div class='guide-desc'>{_esc(description)}</div></div>"
        for term, description in rows
    )
    return (
        '<section class="guide">'
        '<div class="lab">리포트 읽는 법<span class="en">How to read this</span></div>'
        f"{items}</section>"
    )


def _render_footer() -> str:
    return (
        "<footer>"
        '<span class="warn">승인된 대상에 대해서만 사용하세요.</span> '
        "VulnSpider는 검토할 후보의 우선순위를 정리합니다. 우선순위가 높다는 "
        "것은 먼저 확인해 볼 만한 단서라는 뜻이며, 검증된 취약점이라는 뜻이 "
        "아닙니다. 위에 표시된 요청은 v0.1이 입력 지점마다 실제로 보낸 "
        "baseline 1건과 probe 1건뿐이며, 추가 검증 payload는 전송하지 "
        "않았습니다. Generated by VulnSpider v0.1."
        "</footer>"
    )


_BASE_STYLE = """
  :root{
    --paper:#f6f7f9; --card:#ffffff; --ink:#12161d; --muted:#5b6472;
    --line:#e3e7ee; --track:#eef1f6; --accent:#2f4b7c;
    --low:#7c8798; --medium:#c08a2d; --high:#c0463b;
    --sqli:#2f6f8f; --xss:#7a5aa8; --bac:#2f7d5f;
    --fix-bg:#f3f6fb; --fix-line:#e0e8f3;
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,Segoe UI,"Malgun Gothic","Apple SD Gothic Neo",
           Roboto,Helvetica,Arial,sans-serif;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --paper:#0f1319; --card:#161c24; --ink:#e6eaf0; --muted:#96a3b4;
      --line:#26303c; --track:#1d2632; --accent:#7fa6dd;
      --low:#8794a6; --medium:#e0a944; --high:#e07064;
      --sqli:#5fa8cd; --xss:#a98add; --bac:#5bb08a;
      --fix-bg:#18222e; --fix-line:#27374a;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
       line-height:1.6;-webkit-font-smoothing:antialiased;word-break:keep-all}
  .wrap{max-width:960px;margin:0 auto;padding:40px 24px 80px}
  header.masthead{border-bottom:2px solid var(--ink);padding-bottom:18px;margin-bottom:8px}
  .brand{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .brand h1{font-size:26px;margin:0;letter-spacing:-.02em}
  .brand .ver{font-size:12px;color:var(--muted);font-family:var(--mono)}
  .tagline{color:var(--muted);font-size:14px;margin-top:6px;max-width:70ch}
  .target{font-family:var(--mono);font-size:13px;margin-top:14px;
          word-break:break-all;color:var(--accent)}
  .stats{display:flex;flex-wrap:wrap;gap:0;border:1px solid var(--line);
         border-radius:10px;background:var(--card);margin:22px 0 8px;overflow:hidden}
  .stat{flex:1 1 130px;padding:14px 16px;border-right:1px solid var(--line)}
  .stat:last-child{border-right:0}
  .stat .n{font-family:var(--mono);font-size:22px;font-weight:600;line-height:1.2}
  .stat .l{font-size:12px;color:var(--ink);margin-top:2px}
  .stat .l.en{font-size:10px;text-transform:uppercase;letter-spacing:.08em;
              color:var(--muted);margin-top:0}
  .bandbar{display:flex;gap:8px;margin:18px 0 30px;font-size:13px;flex-wrap:wrap}
  .pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:999px;
        border:1px solid var(--line);background:var(--card)}
  .dot{width:9px;height:9px;border-radius:50%;display:inline-block}
  .dot.high{background:var(--high)} .dot.medium{background:var(--medium)} .dot.low{background:var(--low)}
  h2.section{font-size:15px;color:var(--ink);margin:34px 0 14px;font-weight:600;
             display:flex;align-items:baseline;gap:9px;flex-wrap:wrap}
  h2.section .en{font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;
                 color:var(--muted);font-weight:500}
  .finding{background:var(--card);border:1px solid var(--line);border-radius:12px;
           padding:20px 22px;margin-bottom:16px;border-left:4px solid var(--low)}
  .finding.high{border-left-color:var(--high)}
  .finding.medium{border-left-color:var(--medium)}
  .fhead{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
  .fhead-main{min-width:0;flex:1 1 320px}
  .rank{font-family:var(--mono);font-size:13px;color:var(--muted)}
  .vtype{font-weight:600;font-size:16px;margin:2px 0}
  .ep{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}
  .ep.unknown{color:var(--muted);font-style:italic;font-family:var(--sans)}
  .ep .param{color:var(--accent)}
  .meterwrap{min-width:210px;text-align:right}
  .prio{font-family:var(--mono);font-size:22px;font-weight:600;line-height:1.2}
  .prio.high{color:var(--high)} .prio.medium{color:var(--medium)} .prio.low{color:var(--low)}
  .meter{height:8px;border-radius:4px;background:var(--track);margin-top:6px;overflow:hidden}
  .meter > i{display:block;height:100%;border-radius:4px}
  .meter > i.high{background:var(--high)} .meter > i.medium{background:var(--medium)} .meter > i.low{background:var(--low)}
  .pcaption{font-size:11px;color:var(--muted);margin-top:5px;font-family:var(--mono)}
  .why{margin-top:18px}
  .why .lab,.notice .lab,.guide .lab{font-size:11px;letter-spacing:.04em;
       color:var(--muted);margin-bottom:8px;display:flex;align-items:baseline;gap:7px;
       flex-wrap:wrap}
  .why .lab .en,.notice .lab .en,.guide .lab .en{font-size:9.5px;text-transform:uppercase;
       letter-spacing:.1em;opacity:.75}
  .subchart{margin-top:14px}
  table.rec{width:100%;border-collapse:collapse;margin-top:6px;font-size:12px}
  table.rec th{text-align:left;font-size:10.5px;letter-spacing:.04em;
               color:var(--muted);border-bottom:1px solid var(--line);padding:6px 8px;
               font-weight:600}
  table.rec td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  table.rec td.pl{font-family:var(--mono);color:var(--accent);word-break:break-all;max-width:340px}
  table.rec td.role{font-family:var(--mono);text-transform:uppercase;font-size:10.5px;color:var(--muted)}
  .status{font-family:var(--mono)}
  .fix{margin-top:16px;padding:12px 14px;background:var(--fix-bg);
       border:1px solid var(--fix-line);border-radius:8px;font-size:13px}
  .fix b{font-size:11px;letter-spacing:.04em;color:var(--accent)}
  .fix i{color:var(--muted);font-size:12px}
  .ids{margin-top:12px;font-size:10.5px;color:var(--muted);font-family:var(--mono);
       word-break:break-all}
  .notice{background:var(--card);border:1px solid var(--line);border-radius:10px;
          padding:14px 18px;margin:16px 0;font-size:13px}
  .notice.small{padding:10px 14px;color:var(--muted);font-style:italic}
  .notice .hint{margin:0 0 8px;color:var(--muted);font-size:12px}
  .notice ul{margin:0;padding-left:18px}
  .notice li{padding:2px 0}
  .guide{background:var(--card);border:1px solid var(--line);border-radius:10px;
         padding:16px 18px;margin:26px 0 0;font-size:13px}
  .guide-row{display:grid;grid-template-columns:minmax(120px,150px) 1fr;gap:14px;
             padding:8px 0;border-bottom:1px dotted var(--line)}
  .guide-row:last-child{border-bottom:0}
  .guide-term{font-weight:600;font-size:12.5px}
  .guide-desc{color:var(--muted);font-size:12.5px}
  .empty{background:var(--card);border:1px dashed var(--line);border-radius:10px;
         padding:40px;text-align:center;color:var(--muted)}
  footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);
         font-size:12px;color:var(--muted);max-width:80ch}
  footer .warn{color:var(--high);font-weight:600}
  @media (max-width:600px){
    .wrap{padding:28px 16px 60px}
    .meterwrap{text-align:left;min-width:0;width:100%}
    .guide-row{grid-template-columns:1fr;gap:2px}
  }
  @media print{
    body{background:#fff}
    .finding,.chart-card,.notice,.guide{break-inside:avoid}
  }
"""

_DOCUMENT_STYLE = _BASE_STYLE + charts.CHART_STYLE
