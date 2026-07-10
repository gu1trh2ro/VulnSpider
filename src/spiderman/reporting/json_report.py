"""Stable JSON reporting for deterministic v0.1 Top-K outcomes."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from spiderman.domain import ScoreEvidence
from spiderman.selection import RankedScoringResult, SelectionOutcome

REPORT_SCHEMA_VERSION = "0.1"


class ReportingError(ValueError):
    """Raised when a selection outcome cannot be emitted as strict JSON."""


def build_json_report(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    if not isinstance(outcome, SelectionOutcome):
        raise ReportingError("outcome must be a SelectionOutcome")
    summary = outcome.summary
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
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
            _candidate_record(item, rank=rank)
            for rank, item in enumerate(outcome.selected, start=1)
        ],
    }


def render_json_report(
    outcome: SelectionOutcome,
    *,
    warnings: Sequence[str] = (),
) -> str:
    report = build_json_report(outcome, warnings=warnings)
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


def write_json_report(
    outcome: SelectionOutcome,
    destination: str | Path,
    *,
    warnings: Sequence[str] = (),
) -> None:
    Path(destination).write_text(
        render_json_report(outcome, warnings=warnings),
        encoding="utf-8",
    )


def _candidate_record(
    item: RankedScoringResult,
    *,
    rank: int,
) -> dict[str, Any]:
    result = item.scoring_result
    candidate = result.candidate
    return {
        "rank": rank,
        "candidate_id": candidate.id,
        "input_point_id": candidate.input_point_id,
        "feature_vector_id": result.feature_vector_id,
        "vulnerability_type": candidate.vulnerability_type.value,
        "scorer_version": candidate.scorer_version,
        "raw_rank_score": item.raw_rank_score,
        "raw_rank_score_max": item.raw_rank_score_max,
        "selection_priority": item.selection_priority,
        "evidence": [
            _evidence_record(evidence)
            for evidence in sorted(
                result.evidence,
                key=lambda evidence: evidence.feature_name,
            )
        ],
    }


def _evidence_record(evidence: ScoreEvidence) -> dict[str, Any]:
    return {
        "candidate_id": evidence.candidate_id,
        "feature_vector_id": evidence.feature_vector_id,
        "vulnerability_type": (
            None
            if evidence.vulnerability_type is None
            else evidence.vulnerability_type.value
        ),
        "feature_name": evidence.feature_name,
        "feature_value": evidence.feature_value,
        "observed": evidence.observed,
        "weight": evidence.weight,
        "contribution": evidence.contribution,
        "reason": evidence.reason,
    }
