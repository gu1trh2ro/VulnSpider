"""Broken Access Control (BAC) scoring and within-family selection.

A small parallel pipeline to ``features`` / ``scoring`` / ``selection``, but
built around :class:`vulnspider.domain.access.AccessCandidate`
(subject_context x resource_reference) instead of the injection
``InputPoint x VulnerabilityType`` model. See ADR-014 for why these stay
separate pipelines.

On the ``feat/selection-top-k`` branch this package carries only the reused
BAC scorer, its features, and its within-family selector -- exactly what
``selection.combined`` needs to merge access candidates into the global
Top-K. The BAC observation pipeline (planner/executor) is owned by the
discovery/observation modules and is intentionally not re-exported here.
"""

from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
    ACCESS_FEATURE_SCHEMA_VERSION,
    ACCESS_UNAUTHORIZED_SUCCESS,
    extract_access_features,
)
from vulnspider.access.scoring import (
    ACCESS_MAX_RANK_SCORE,
    ACCESS_SCORER_VERSION,
    ACCESS_TERMS,
    AccessScorer,
    AccessScoringError,
    AccessScoringTerm,
    score_access_plan,
)
from vulnspider.access.selection import (
    AccessSelectionError,
    AccessSelectionOutcome,
    AccessSelectionSummary,
    RankedAccessScoringResult,
    select_top_k_access,
)

__all__ = [
    "ACCESS_BODY_SIZE_SIMILARITY_RATIO",
    "ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION",
    "ACCESS_FEATURE_SCHEMA_VERSION",
    "ACCESS_MAX_RANK_SCORE",
    "ACCESS_SCORER_VERSION",
    "ACCESS_TERMS",
    "ACCESS_UNAUTHORIZED_SUCCESS",
    "AccessScorer",
    "AccessScoringError",
    "AccessScoringTerm",
    "AccessSelectionError",
    "AccessSelectionOutcome",
    "AccessSelectionSummary",
    "RankedAccessScoringResult",
    "extract_access_features",
    "score_access_plan",
    "select_top_k_access",
]
