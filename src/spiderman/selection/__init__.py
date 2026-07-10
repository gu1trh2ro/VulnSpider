"""Deterministic candidate selection package."""

from spiderman.selection.top_k import (
    RankedScoringResult,
    SelectionError,
    SelectionOutcome,
    SelectionSummary,
    select_top_k,
)

__all__ = [
    "RankedScoringResult",
    "SelectionError",
    "SelectionOutcome",
    "SelectionSummary",
    "select_top_k",
]
