"""Deterministic cross-type selection for validated scoring results."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite

from spiderman.domain import VulnerabilityType
from spiderman.scoring import (
    SQLI_MAX_RANK_SCORE,
    SQLI_SCORER_VERSION,
    XSS_MAX_RANK_SCORE,
    XSS_SCORER_VERSION,
    ScoringResult,
)


class SelectionError(ValueError):
    """Raised when scoring results cannot be selected deterministically."""


@dataclass(frozen=True, slots=True)
class RankedScoringResult:
    """A scoring result plus its cross-type selection key."""

    scoring_result: ScoringResult
    raw_rank_score: float
    raw_rank_score_max: float
    selection_priority: float


@dataclass(frozen=True, slots=True)
class SelectionSummary:
    total_scoring_results: int
    rankable_results: int
    unrankable_results: int
    selected_results: int
    top_k_requested: int


@dataclass(frozen=True, slots=True)
class SelectionOutcome:
    """Selected unique candidates and retained unrankable accounting."""

    summary: SelectionSummary
    selected: tuple[RankedScoringResult, ...]
    unrankable: tuple[ScoringResult, ...]


def select_top_k(
    scoring_results: Sequence[ScoringResult],
    *,
    k: int,
) -> SelectionOutcome:
    """Select unique candidates by normalized priority and stable identity."""

    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise SelectionError("top-k must be a positive integer")

    results = tuple(scoring_results)
    rankable: list[RankedScoringResult] = []
    unrankable: list[ScoringResult] = []
    for result in results:
        if not isinstance(result, ScoringResult):
            raise SelectionError("scoring_results must contain ScoringResult objects")
        if not any(item.observed for item in result.evidence):
            unrankable.append(result)
            continue
        rankable.append(_rank_result(result))

    ordered = sorted(rankable, key=_selection_sort_key)
    unique: list[RankedScoringResult] = []
    seen_candidate_ids: set[str] = set()
    for item in ordered:
        candidate_id = item.scoring_result.candidate.id or ""
        if candidate_id in seen_candidate_ids:
            continue
        seen_candidate_ids.add(candidate_id)
        unique.append(item)

    selected = tuple(unique[:k])
    summary = SelectionSummary(
        total_scoring_results=len(results),
        rankable_results=len(rankable),
        unrankable_results=len(unrankable),
        selected_results=len(selected),
        top_k_requested=k,
    )
    return SelectionOutcome(
        summary=summary,
        selected=selected,
        unrankable=tuple(
            sorted(
                unrankable,
                key=lambda item: (
                    item.candidate.id or "",
                    item.feature_vector_id,
                ),
            )
        ),
    )


def _rank_result(result: ScoringResult) -> RankedScoringResult:
    raw_score = result.candidate.rank_score
    if raw_score is None or isinstance(raw_score, bool):
        raise SelectionError("rankable candidate must have a numeric RankScore")
    raw_score = float(raw_score)
    if not isfinite(raw_score):
        raise SelectionError("RankScore must be finite")

    maximum = _maximum_score_for(result)
    if raw_score < 0.0 or raw_score > maximum:
        raise SelectionError("RankScore must be within its exact scorer range")
    priority = raw_score / maximum
    if not isfinite(priority):
        raise SelectionError("selection priority must be finite")
    return RankedScoringResult(
        scoring_result=result,
        raw_rank_score=raw_score,
        raw_rank_score_max=maximum,
        selection_priority=priority,
    )


def _maximum_score_for(result: ScoringResult) -> float:
    candidate = result.candidate
    policy = (candidate.vulnerability_type, candidate.scorer_version)
    if policy == (VulnerabilityType.SQLI, SQLI_SCORER_VERSION):
        return SQLI_MAX_RANK_SCORE
    if policy == (VulnerabilityType.REFLECTED_XSS, XSS_SCORER_VERSION):
        return XSS_MAX_RANK_SCORE
    raise SelectionError("candidate does not identify a supported scorer policy")


def _selection_sort_key(item: RankedScoringResult) -> tuple[float, str, str]:
    result = item.scoring_result
    return (
        -item.selection_priority,
        result.candidate.id or "",
        result.feature_vector_id,
    )
