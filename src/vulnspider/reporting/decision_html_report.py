"""결정 계층 대시보드 — 차트 기반 최종 스캔 리포트.

`analyze --html-output`이 만드는 것과 같은 완전한 스캔 리포트지만, 순위와 선택을
휴리스틱 `selection_priority`가 아니라 **보정된 확률 + 제약 조건 하 선택**으로
수행한 결과를 렌더링한다.

차트는 `reporting/charts.py`의 인라인 SVG/CSS를 쓴다(f6a70f0에서 이식). 외부
스크립트·폰트·이미지를 전혀 참조하지 않으므로 리포트는 **파일 하나로 오프라인에서
열리고 아무 외부 요청도 하지 않는다.** 스캔 디렉터리에서 바로 열리는 파일에는
그게 중요하다.

본문 설명은 한국어다. 이 리포트를 읽는 사람과 `docs/`의 나머지가 한국어이기
때문이다. feature 이름, 식별자, HTTP 값 같은 기계 값은 원문 그대로 둔다.

**아무것도 재계산하지 않는다**(`docs/ARCHITECTURE.md`). 모든 차트는 이미 검증된
``DecisionOutcome``에 들어 있는 숫자를 두 번째 방식으로 보여주는 것뿐이다.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import DecisionOutcome
from vulnspider.domain import Endpoint, InputPoint, VulnerabilityType
from vulnspider.reporting.charts import (
    CHART_STYLE,
    Bar,
    Slice,
    bar_chart,
    chart_card,
    donut_chart,
)
from vulnspider.reporting.html_report import (
    GENERAL_GUIDANCE,
    VULNERABILITY_LABELS,
    ProbeRun,
    _DOCUMENT_STYLE,
    _endpoint_context,
    _esc,
    _fmt_number,
    _fmt_percent,
    _priority_band,
    _render_warnings,
    _requests_context,
)
from vulnspider.scoring.calibration import CalibratedProbability, CalibratedScorer

DECISION_HTML_REPORT_VERSION = "decision-html-v2"

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = {}
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = {}
_EMPTY_PROBE_RUNS: Mapping[str, ProbeRun] = {}
_EMPTY_PROBABILITIES: Mapping[str, CalibratedProbability] = {}
_EMPTY_MODELS: Mapping[str, CalibratedScorer] = {}

_BAND_LABEL = {"high": "높음", "medium": "중간", "low": "낮음"}
_FAMILY_TONE = {"SQLI": "sqli", "REFLECTED_XSS": "xss", "BROKEN_ACCESS_CONTROL": "bac"}
_FAMILY_LABEL_KO = {"SQLI": "SQL Injection", "REFLECTED_XSS": "Reflected XSS"}
_CONSTRAINT_KO = {
    "top_k": "Top-K 상한에 도달",
    "budget": "요청 예산 소진",
    "both": "Top-K와 예산 모두 도달",
    "none": "모든 후보가 제약 안에 들어감",
}


def render_decision_html_report(
    outcome: DecisionOutcome,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
    endpoint_count: int = 0,
    input_point_count: int = 0,
) -> str:
    """결정 계층 결과를 하나의 정적 HTML 문서로 렌더링한다."""

    if not isinstance(outcome, DecisionOutcome):
        raise TypeError("outcome must be a DecisionOutcome")
    outcome.validate()

    selected = outcome.selection.selected
    sections = [
        _render_header(target, outcome, models),
        _render_stats(outcome),
        _render_charts(
            outcome,
            endpoint_count=endpoint_count or len(endpoints),
            input_point_count=input_point_count or len(input_points),
        ),
        _render_guarantee(outcome),
        _render_warnings(list(warnings)),
        '<h2 class="section">검증 순서 <span class="ko-en">Verification order</span></h2>',
        _render_intro(outcome),
        _render_candidates(
            selected,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            probabilities=probabilities,
        ),
        _render_unselected(outcome, input_points, endpoints),
        _render_footer(outcome, elapsed_seconds),
    ]
    body = "\n\n".join(section for section in sections if section)
    title = "VulnSpider 결정 리포트" + (f" — {target}" if target else "")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="ko">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_DOCUMENT_STYLE}{CHART_STYLE}{_EXTRA_STYLE}</style>\n"
        f'</head>\n<body>\n<div class="wrap">\n\n{body}\n\n</div>\n</body>\n</html>\n'
    )


def write_decision_html_report(
    outcome: DecisionOutcome,
    destination: str | Path,
    **kwargs: Any,
) -> None:
    """결정 리포트를 파일로 쓴다."""

    Path(destination).write_text(
        render_decision_html_report(outcome, **kwargs), encoding="utf-8"
    )


def _family_type(family: str) -> VulnerabilityType | None:
    try:
        return VulnerabilityType(family)
    except ValueError:
        return None


def _family_label(family: str) -> str:
    family_type = _family_type(family)
    if family_type is not None:
        return VULNERABILITY_LABELS.get(family_type, family)
    return _FAMILY_LABEL_KO.get(family, family)


def _render_header(
    target: str,
    outcome: DecisionOutcome,
    models: Mapping[str, CalibratedScorer],
) -> str:
    trained = sorted(
        (family, scorer.training_samples) for family, scorer in models.items()
    )
    if not trained:
        model_line = "휴리스틱 prior (코퍼스 없음)"
    elif all(count == 0 for _family, count in trained):
        model_line = "휴리스틱 prior (학습 데이터 0개 — 기존 순서와 동일)"
    else:
        detail = ", ".join(f"{family} n={count}" for family, count in trained)
        model_line = f"코퍼스 학습 모델 ({detail})"
    target_line = (
        f'<div class="target">대상 &rarr; {_esc(target)}</div>' if target else ""
    )
    return (
        '<header class="masthead">\n'
        '  <div class="brand">\n'
        "    <h1>VulnSpider</h1>"
        f'<span class="ver">결정 리포트 &middot; {_esc(outcome.policy_version)}</span>\n'
        "  </div>\n"
        '  <div class="tagline">보정된 확률로 후보 순위를 매기고 명시적 제약 안에서 '
        "검증 대상을 선택한 결과입니다. <b>검증 우선순위이며 확정된 취약점이 "
        "아닙니다.</b></div>\n"
        f"  {target_line}\n"
        f'  <div class="target">모델 &rarr; {_esc(model_line)}</div>\n'
        "</header>"
    )


def _render_stats(outcome: DecisionOutcome) -> str:
    selection = outcome.selection
    cells = (
        (_fmt_number(outcome.initial_candidates), "채점된 후보"),
        (_fmt_number(len(selection.selected)), "선택됨"),
        ("—" if selection.top_k is None else _fmt_number(selection.top_k), "Top-K"),
        (
            "—" if selection.budget is None else _fmt_number(selection.budget),
            "요청 예산",
        ),
        (_fmt_number(selection.spent_cost), "확정 요청 수"),
        (f"{selection.expected_findings:.2f}", "기대 발견 수"),
    )
    items = "\n".join(
        f'  <div class="stat"><div class="n">{_esc(value)}</div>'
        f'<div class="l">{_esc(label)}</div></div>'
        for value, label in cells
    )
    ratio = (
        "제약이 둘 다 걸려 결합 보장은 주장하지 않습니다"
        if selection.approximation_ratio is None
        else f"이 목적함수 최적값의 최소 "
        f"{_fmt_percent(selection.approximation_ratio)}%를 보장합니다"
    )
    limit = _CONSTRAINT_KO.get(
        selection.binding_constraint, selection.binding_constraint
    )
    return (
        f'<section class="stats">\n{items}\n</section>\n'
        f'<div class="notice small">선택이 멈춘 이유: {_esc(limit)}. 근사 보장: '
        f"{_esc(ratio)}.</div>"
    )


def _render_charts(
    outcome: DecisionOutcome,
    *,
    endpoint_count: int,
    input_point_count: int,
) -> str:
    selection = outcome.selection
    selected = selection.selected

    bands = {"high": 0, "medium": 0, "low": 0}
    for candidate in selected:
        bands[_priority_band(float(candidate.probability))] += 1
    donut = donut_chart(
        [
            Slice(_BAND_LABEL[name], bands[name], name)
            for name in ("high", "medium", "low")
        ],
        center_value=_fmt_number(len(selected)),
        center_caption="선택된 후보의 확률 구간 분포",
        empty_caption="선택된 후보가 없습니다.",
    )

    by_family: dict[str, int] = {}
    for candidate in selected:
        by_family[candidate.family] = by_family.get(candidate.family, 0) + 1
    total_family = max(sum(by_family.values()), 1)
    family_bars = bar_chart(
        [
            Bar(
                label=_family_label(family),
                ratio=count / total_family,
                value_label=f"{count}건",
                tone=_FAMILY_TONE.get(family, "accent"),
            )
            for family, count in sorted(by_family.items())
        ],
        empty_caption="선택된 후보가 없습니다.",
    )

    funnel_stages = (
        ("발견된 엔드포인트", endpoint_count, "muted"),
        ("입력점", input_point_count, "muted"),
        ("채점된 후보", outcome.initial_candidates, "accent"),
        ("보장 집합", outcome.conformal_set_size or outcome.initial_candidates, "medium"),
        ("최종 선택", len(selected), "high"),
    )
    widest = max((value for _label, value, _tone in funnel_stages), default=1) or 1
    funnel = bar_chart(
        [
            Bar(
                label=label,
                ratio=value / widest,
                value_label=_fmt_number(value),
                tone=tone,
            )
            for label, value, tone in funnel_stages
        ],
        empty_caption="파이프라인 수치가 없습니다.",
    )

    top_bars = bar_chart(
        [
            Bar(
                label=f"#{order} {_family_label(candidate.family)}",
                ratio=float(candidate.probability),
                value_label=f"{_fmt_percent(float(candidate.probability))}%",
                tone=_priority_band(float(candidate.probability)),
                caption=(
                    f"기대값 {candidate.expected_value:.2f} · "
                    f"{candidate.verification_cost} 요청"
                ),
            )
            for order, candidate in enumerate(selected, start=1)
        ],
        empty_caption="선택된 후보가 없습니다.",
    )

    return (
        '<div class="chart-grid">\n'
        + chart_card(
            "확률 구간 분포",
            donut,
            english="probability bands",
            note="취약할 확률이 70% 이상이면 높음, 40% 이상이면 중간입니다. "
            "구간은 표시용이며 선택 자체는 이미 끝났습니다.",
        )
        + chart_card(
            "유형별 선택 건수",
            family_bars,
            english="selected by family",
            note="유형마다 검증 비용과 심각도가 다르므로 건수만으로 위험도를 "
            "비교할 수는 없습니다.",
        )
        + chart_card(
            "파이프라인 축소",
            funnel,
            english="pipeline funnel",
            note="크롤링으로 찾은 것에서 실제로 검증할 것까지 몇 단계로 줄었는지 "
            "보여줍니다. 이 축소가 이 프로젝트의 핵심 주장입니다.",
        )
        + chart_card(
            "선택된 후보 확률 비교",
            top_bars,
            english="selected candidates",
            note="막대 길이가 곧 취약할 확률입니다. 검증은 위에서부터 순서대로 "
            "수행하면 됩니다.",
        )
        + "\n</div>"
    )


def _render_guarantee(outcome: DecisionOutcome) -> str:
    conformal = outcome.conformal
    if conformal is None:
        return (
            '<div class="notice"><div class="lab">Recall 보장</div>'
            "요청하지 않았습니다. 선택 개수는 Top-K와 요청 예산만으로 정해집니다."
            "</div>"
        )
    if not conformal.guarantee_attainable:
        return (
            '<div class="notice"><div class="lab">Recall 보장</div>'
            "<b>보장이 성립하지 않습니다.</b> 목표 위험도 "
            f"{_fmt_percent(conformal.target_risk)}%를 인증하려면 보정용 "
            f"애플리케이션이 더 필요한데 {_fmt_number(conformal.calibration_groups)}"
            "개뿐입니다. 임계값을 인증하지 못했으므로 후보를 모두 남겼습니다."
            "</div>"
        )
    covered = (
        "예산이 이 집합을 감당합니다"
        if outcome.budget_covers_conformal_set
        else "<b>예산이 이 집합을 감당하지 못하므로 이번 실행에서는 보장이 "
        "성립하지 않습니다</b>"
    )
    return (
        '<div class="notice"><div class="lab">Recall 보장</div>'
        f"실제 취약점의 최소 {_fmt_percent(1.0 - conformal.target_risk)}%가 "
        f"확률 {conformal.threshold:.4f} 컷을 통과할 것으로 기대됩니다"
        f"(보정 애플리케이션 {_fmt_number(conformal.calibration_groups)}개, "
        f"실측 위험도 {conformal.empirical_risk:.4f}). 보장 집합은 "
        f"{_fmt_number(outcome.conformal_set_size)}개이며 {covered}."
        "</div>"
    )


def _render_intro(outcome: DecisionOutcome) -> str:
    return (
        '<div class="notice small">아래 순서대로 검증하십시오. 각 항목의 '
        "<b>순위 근거</b>는 어떤 신호가 확률을 얼마나 올리거나 내렸는지, "
        "<b>실행된 요청</b>은 그 판단의 바탕이 된 실제 baseline/probe 쌍입니다.</div>"
    )


def _render_candidates(
    selected: Sequence[DecisionCandidate],
    *,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
    probabilities: Mapping[str, CalibratedProbability],
) -> str:
    if not selected:
        return '<div class="empty">선택된 후보가 없습니다.</div>'
    return "\n".join(
        _render_candidate(
            candidate,
            rank=rank,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            calibrated=probabilities.get(candidate.candidate_id),
        )
        for rank, candidate in enumerate(selected, start=1)
    )


def _render_candidate(
    candidate: DecisionCandidate,
    *,
    rank: int,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
    calibrated: CalibratedProbability | None,
) -> str:
    probability = float(candidate.probability)
    band = _priority_band(probability)
    percent = _fmt_percent(probability)
    input_point = input_points.get(candidate.subject_ref)
    endpoint = (
        endpoints.get(input_point.endpoint_id) if input_point is not None else None
    )
    family_type = _family_type(candidate.family)
    guidance = GENERAL_GUIDANCE.get(family_type) if family_type is not None else None
    guidance_html = (
        f'<div class="fix"><b>일반 지침</b><br>{_esc(guidance)}<br>'
        "<i>해당 취약점 유형의 일반적인 대응이며, 이 후보가 실제로 악용 가능하다는 "
        "뜻은 아닙니다.</i></div>"
        if guidance
        else ""
    )
    return f"""<article class="finding {band}">
    <div class="fhead">
      <div>
        <div class="rank">#{rank}</div>
        <div class="vtype">{_esc(_family_label(candidate.family))}</div>
        {_render_endpoint_line(endpoint, input_point)}
      </div>
      <div class="meterwrap">
        <div class="prio {band}">{percent}%</div>
        <div class="meter"><i class="{band}" style="width:{percent}%"></i></div>
        <div class="pcaption">취약 확률 &middot; 기대값 \
{candidate.expected_value:.2f} &middot; {candidate.verification_cost} 요청</div>
      </div>
    </div>

    {_render_evidence(candidate, calibrated)}

    {_render_requests(candidate, probe_runs)}

    {guidance_html}
    <div class="ids">candidate {_esc(candidate.candidate_id)} &middot; \
feature vector {_esc(candidate.feature_vector_ref)}</div>
  </article>"""


def _render_endpoint_line(
    endpoint: Endpoint | None,
    input_point: InputPoint | None,
) -> str:
    context = _endpoint_context(endpoint, input_point)
    if context is None:
        return '<div class="ep unknown">입력점 정보가 리포트에 전달되지 않았습니다</div>'
    method = context["method"] or "?"
    url = context["url"] or "(엔드포인트 미상)"
    occurrence = context["occurrence_index"]
    suffix = f"[{occurrence}]" if occurrence is not None else ""
    return (
        f'<div class="ep">{_esc(method)} {_esc(url)} &mdash; '
        f'<span class="param">{_esc(context["location"].lower())}.'
        f'{_esc(context["name"])}{_esc(suffix)}</span></div>'
    )


def _render_evidence(
    candidate: DecisionCandidate,
    calibrated: CalibratedProbability | None,
) -> str:
    """신호별 log-odds 기여를 막대로 보여준다.

    미관측 feature도 남긴다. "확인했는데 없었다"와 "확인하지 못했다"는 다르고,
    후자를 빼면 전부 관측된 것처럼 읽히는 리포트가 된다.
    """

    if calibrated is None:
        return ""
    contributions = [
        abs(item.logit_contribution or 0.0)
        for item in calibrated.evidence
        if item.observed
    ]
    widest = max(contributions, default=0.0) or 1.0
    bars = []
    for item in sorted(calibrated.evidence, key=lambda e: e.feature_name):
        if not item.observed:
            bars.append(
                Bar(
                    label=item.feature_name,
                    ratio=0.0,
                    value_label="미관측",
                    tone="muted",
                    caption="관측하지 못함 — 값이 0이라는 뜻이 아닙니다",
                )
            )
            continue
        contribution = item.logit_contribution or 0.0
        bars.append(
            Bar(
                label=item.feature_name,
                ratio=abs(contribution) / widest,
                value_label=f"{contribution:+.2f}",
                tone="high" if contribution > 0 else "low",
                caption=f"관측값 {_fmt_number(item.feature_value or 0.0)}",
            )
        )
    return (
        '<div class="why">\n'
        '  <div class="lab">순위 근거 <span class="ko-en">why it ranks here</span>'
        "</div>\n"
        f"  {bar_chart(bars, empty_caption='증거가 없습니다.')}\n"
        '  <div class="chart-note">막대는 각 신호가 log-odds를 움직인 크기입니다. '
        "빨강은 확률을 올린 신호, 회색은 내린 신호입니다.</div>\n"
        "</div>"
    )


def _render_requests(
    candidate: DecisionCandidate,
    probe_runs: Mapping[str, ProbeRun],
) -> str:
    rows = _requests_context(candidate.feature_vector_ref, probe_runs)
    if not rows:
        return ""
    lengths = [row["response"]["body_length_bytes"] for row in rows]
    widest = max(lengths, default=0) or 1
    comparison = bar_chart(
        [
            Bar(
                label="baseline" if row["role"] == "baseline" else "probe",
                ratio=row["response"]["body_length_bytes"] / widest,
                value_label=f"{_fmt_number(row['response']['body_length_bytes'])} B",
                tone="muted" if row["role"] == "baseline" else "accent",
                caption=f"HTTP {row['response']['status_code']}",
            )
            for row in rows
        ]
    )
    table_rows = "".join(
        f'<tr><td class="role">{_esc(row["role"])}</td>'
        f'<td class="pl">{_esc(row["method"])} {_esc(row["url"])}'
        + (
            f' &mdash; 주입값: {_esc(row["injected_value"])}'
            if row.get("injected_value")
            else ""
        )
        + f'</td><td class="status">{_esc(row["response"]["status_code"])}</td>'
        f'<td>{_fmt_number(row["response"]["body_length_bytes"])} B</td></tr>'
        for row in rows
    )
    return (
        '<div class="why">\n'
        '  <div class="lab">실행된 요청 '
        '<span class="ko-en">baseline + probe actually sent</span></div>\n'
        f"  {comparison}\n"
        '  <table class="rec">\n'
        "    <tr><th>역할</th><th>요청</th><th>상태</th><th>본문 크기</th></tr>\n"
        f"    {table_rows}\n"
        "  </table>\n"
        '  <div class="chart-note">probe 응답이 baseline과 크게 다를수록 그 입력점이 '
        "서버 동작을 바꿨다는 신호입니다.</div>\n"
        "</div>"
    )


def _render_unselected(
    outcome: DecisionOutcome,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
) -> str:
    """선택되지 않은 후보를 사유와 함께 전부 보여준다.

    임계값에 잘린 후보는 선택기에 도달조차 하지 않으므로 `deferred`만 보여주면
    "채점 12개, 선택 3개"의 차이를 읽는 사람이 설명할 수 없다.
    """

    selected = {item.candidate_id for item in outcome.selection.selected}
    deferred = {item.candidate_id for item in outcome.selection.deferred}
    threshold = None if outcome.conformal is None else outcome.conformal.threshold
    rows = []
    for candidate in outcome.scored:
        if candidate.candidate_id in selected:
            continue
        if candidate.candidate_id in deferred:
            reason = "순위가 컷 아래"
        elif threshold is not None:
            reason = f"recall 임계값 {threshold:.4f} 미만"
        else:
            reason = "선택되지 않음"
        input_point = input_points.get(candidate.subject_ref)
        endpoint = (
            endpoints.get(input_point.endpoint_id)
            if input_point is not None
            else None
        )
        if input_point is None:
            location = candidate.candidate_id
        elif endpoint is None:
            location = f"{input_point.location.value.lower()}.{input_point.name}"
        else:
            location = (
                f"{endpoint.method.value} {endpoint.path} "
                f"{input_point.location.value.lower()}.{input_point.name}"
            )
        rows.append((float(candidate.probability), location, candidate, reason))
    if not rows:
        return ""
    rows.sort(key=lambda item: (-item[0], item[1]))
    body = "".join(
        f'<tr><td class="pl">{_esc(location)}</td>'
        f'<td class="role">{_esc(_family_label(candidate.family))}</td>'
        f'<td class="status">{probability:.4f}</td>'
        f'<td class="status">{_fmt_number(candidate.verification_cost)}</td>'
        f"<td>{_esc(reason)}</td></tr>"
        for probability, location, candidate, reason in rows
    )
    return (
        f'<h2 class="section">선택되지 않은 후보 ({len(rows)})'
        '<span class="ko-en">not selected</span></h2>\n'
        '<div class="notice"><table class="rec">\n'
        "  <tr><th>위치</th><th>유형</th><th>확률</th><th>요청 수</th>"
        "<th>사유</th></tr>\n"
        f"{body}\n</table>\n"
        "<i>컷 아래라는 뜻이며, 안전하다고 판정한 것이 아닙니다.</i></div>"
    )


def _render_footer(outcome: DecisionOutcome, elapsed_seconds: float) -> str:
    return (
        "<footer>"
        f"{_esc(DECISION_HTML_REPORT_VERSION)} &middot; "
        f"{_esc(outcome.selection.selector_version)} &middot; "
        f"{elapsed_seconds:.2f}s<br>"
        '<span class="warn">여기의 확률은 검증 이전의 우선순위입니다(ADR-016). '
        "확정된 취약점이 아닙니다.</span>"
        "</footer>"
    )


_EXTRA_STYLE = """
  .ko-en{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;
         color:var(--muted);font-weight:500;margin-left:8px}
  .notice b{color:var(--ink)}
  .why .bars{margin-top:4px}
"""
