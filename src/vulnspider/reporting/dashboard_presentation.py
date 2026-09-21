"""Audience-oriented summary screens from authoritative display projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from html import escape
from typing import Any

from vulnspider.reporting.dashboard_story import candidate_caption
from vulnspider.reporting.html_report import _fmt_percent


def evidence_summary(rows: Sequence[Mapping[str, Any]]) -> str:
    groups = (
        ("SUPPORTED", "근거 뒷받침", "추가 확인에서도 유형별 신호 관찰", "supported"),
        ("WEAKENED", "가능성 약화", "기존 의심을 낮추는 관찰", "weakened"),
        ("OTHER", "유지·보류·미검증", "상세 기록을 더 살펴볼 후보", "pending"),
    )
    cards = []
    for state, label, note, tone in groups:
        count = sum(row["state"] == state if state != "OTHER" else row["state"] not in {"SUPPORTED", "WEAKENED"} for row in rows)
        width = count / len(rows) * 100 if rows else 0
        cards.append(f'<div class="evidence-count {tone}"><span>{label}</span><strong>{count}<small>개</small></strong>'
                     f'<div class="status-track" aria-hidden="true"><i style="width:{width:.2f}%"></i></div><p>{note}</p></div>')
    return ('<section class="panel evidence-summary"><div class="panel-head"><div><h2>추가 확인 결과, 한눈에</h2>'
            f'<p class="panel-desc">표시된 대표 후보 {len(rows)}개 기준 · 확정 취약점 수가 아닙니다.</p></div></div>'
            '<div class="evidence-counts">' + ''.join(cards) + '</div></section>')


def priority_ranking(rows: Sequence[Mapping[str, Any]], limit: int = 6) -> str:
    """A ranked, at-a-glance confidence bar for the highest candidates."""
    top = list(rows[:limit])
    if not top:
        return ""
    bars = []
    for row in top:
        pct = _fmt_percent(row["score"])
        family = escape(str(row["family"]))
        bars.append(
            f'<a class="rank-row" href="#candidate-{row["rank"]}">'
            f'<span class="rank-no">{row["rank"]:02d}</span>'
            f'<span class="rank-name"><i class="family-dot {family}" aria-hidden="true"></i>'
            f'{candidate_caption(row)}<small>{escape(str(row["family_label"]))}</small></span>'
            f'<span class="rank-bar" aria-hidden="true"><i class="{family}" style="width:{pct}%"></i></span>'
            f'<span class="rank-pct">{pct}<small>%</small></span></a>'
        )
    return (
        '<section class="panel priority-ranking"><div class="panel-head"><div>'
        '<h2>먼저 확인할 순서</h2><p class="panel-desc">최종 신뢰도가 높은 상위 후보입니다. '
        '막대를 누르면 그 후보의 판단 근거로 이동합니다.</p></div>'
        f'<a class="text-link" href="#candidates">전체 {len(rows)}개 →</a></div>'
        '<div class="rank-list">' + ''.join(bars) + '</div></section>'
    )


def presentation_page(rows: Sequence[Mapping[str, Any]], input_count: int, selected_count: int) -> str:
    featured = rows[:2]
    cards = []
    for row in featured:
        cards.append(
            f'<article class="spotlight-card"><span class="eyebrow">PRIORITY {row["rank"]:02d}</span>'
            f'<h2>{candidate_caption(row)}</h2><p>{escape(row["family_label"])}</p>'
            f'<div class="spotlight-score">{_fmt_percent(row["score"])}<small>%</small></div>'
            f'<b>최종 신뢰도</b><p>{escape(row["verification_explanation"]) if row["state"] != "UNVERIFIED" else "추가 검증 전 · 검증 전 확률을 그대로 표시합니다."}</p>'
            f'<div class="spotlight-actions"><a class="button primary" href="#candidate-{row["rank"]}">요청·응답 근거 보기 →</a></div></article>'
        )
    return (
        '<section class="report-page" id="presentation" aria-label="발표 스토리">'
        '<div class="presentation-hero"><span class="eyebrow">VULNSPIDER · THE EVIDENCE STORY</span>'
        '<h1 class="page-title" tabindex="-1">많은 입력 중에서,<br>어디를 먼저 확인할까요?</h1>'
        f'<p>발견한 입력점 <b>{input_count:,}개</b>에서 분석기가 선택한 유형별 후보 <b>{selected_count:,}개</b>까지.</p>'
        f'<p>상위 대표 후보 {len(featured)}개의 실제 기록을 따라가며 선정 이유를 설명합니다.</p></div>'
        '<ol class="story-route"><li><b>01</b> 후보 선정<span>검증할 대상을 좁힙니다</span></li>'
        '<li><b>02</b> 응답 비교<span>무엇이 달라졌는지 봅니다</span></li>'
        '<li><b>03</b> 근거 해석<span>신뢰도의 변화와 한계를 짚습니다</span></li></ol>'
        + priority_ranking(rows)
        + '<div class="spotlight-grid">' + (''.join(cards) or '<p class="missing-note">선택된 후보가 없습니다.</p>') + '</div>'
        '<p class="presentation-note">이 화면은 저장된 분석 결과를 설명합니다. 최종 신뢰도는 취약점 확정 판정이 아니며, 추가 검증이 없는 후보는 검증 전 확률을 그대로 표시합니다.</p>'
        + evidence_summary(rows) + '</section>'
    )
