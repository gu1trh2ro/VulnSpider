"""Ranking evaluation: the metrics and baselines the protocol specifies.

``metrics`` is pure -- rankings and labels in, numbers out -- so every baseline
and the proposed method are measured by identical code. ``baselines`` builds
those rankings from a labeled corpus.

See ``docs/EVALUATION_PROTOCOL.md`` §5 (comparison arms) and §6-A (the judgment
calls that make the metrics computable).
"""

from vulnspider.evaluation.baselines import (
    BASELINE_HEURISTIC,
    BASELINE_RANDOM,
    BASELINE_REFLECTION,
    PROPOSED_CALIBRATED,
    BaselineError,
    FullVerificationReference,
    bug_key_for,
    build_calibrated_queries,
    build_queries,
    full_verification_reference,
    heuristic_score,
    normalize_route,
    random_score,
    reflection_only_score,
)
from vulnspider.evaluation.metrics import (
    METRICS_VERSION,
    MetricError,
    MetricSummary,
    RankedItem,
    RankingQuery,
    RankingReport,
    average_precision_at_k,
    dcg_at_k,
    evaluate_ranking,
    expected_hits_at_k,
    ideal_dcg_at_k,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)

__all__ = [
    "BASELINE_HEURISTIC",
    "BASELINE_RANDOM",
    "BASELINE_REFLECTION",
    "METRICS_VERSION",
    "PROPOSED_CALIBRATED",
    "BaselineError",
    "FullVerificationReference",
    "MetricError",
    "MetricSummary",
    "RankedItem",
    "RankingQuery",
    "RankingReport",
    "average_precision_at_k",
    "bug_key_for",
    "build_calibrated_queries",
    "build_queries",
    "dcg_at_k",
    "evaluate_ranking",
    "expected_hits_at_k",
    "full_verification_reference",
    "heuristic_score",
    "ideal_dcg_at_k",
    "ndcg_at_k",
    "normalize_route",
    "precision_at_k",
    "random_score",
    "recall_at_k",
    "reflection_only_score",
]
