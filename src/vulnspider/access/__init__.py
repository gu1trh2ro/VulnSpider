"""Broken Access Control (BAC) candidate pipeline.

A small parallel pipeline to ``observation`` / ``features`` / ``scoring`` /
``selection``, but built around :class:`vulnspider.domain.access.AccessCandidate`
(subject_context x resource_reference) instead of the injection
``InputPoint x VulnerabilityType`` model. See
``docs/exec-plans/completed/broken-access-control.md`` and ADR-012 for why
these stay separate pipelines.
"""

from vulnspider.access.executor import (
    AccessProbeExecutionResult,
    AccessRequestExecutionError,
    execute_access_plan,
)
from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_FEATURE_SCHEMA_VERSION,
    ACCESS_UNAUTHORIZED_SUCCESS,
    extract_access_features,
)
from vulnspider.access.planner import (
    AccessProbePlanner,
    plan_credential_strip,
    plan_identifier_substitution,
)
from vulnspider.access.scoring import (
    ACCESS_MAX_RANK_SCORE,
    ACCESS_SCORER_VERSION,
    AccessScorer,
    AccessScoringError,
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
    "ACCESS_FEATURE_SCHEMA_VERSION",
    "ACCESS_MAX_RANK_SCORE",
    "ACCESS_SCORER_VERSION",
    "ACCESS_UNAUTHORIZED_SUCCESS",
    "AccessProbeExecutionResult",
    "AccessProbePlanner",
    "AccessRequestExecutionError",
    "AccessScorer",
    "AccessScoringError",
    "AccessSelectionError",
    "AccessSelectionOutcome",
    "AccessSelectionSummary",
    "RankedAccessScoringResult",
    "execute_access_plan",
    "extract_access_features",
    "plan_credential_strip",
    "plan_identifier_substitution",
    "score_access_plan",
    "select_top_k_access",
]
