"""Candidate generation and type-specific deterministic scoring."""

from vulnspider.scoring.engine import (
    SQLI_MAX_RANK_SCORE,
    SQLI_SCORER_VERSION,
    SQLI_TERMS,
    XSS_MAX_RANK_SCORE,
    XSS_SCORER_VERSION,
    XSS_TERMS,
    CandidateGenerator,
    ScoringError,
    ScoringResult,
    ScoringTerm,
    SQLiScorer,
    XSSScorer,
    generate_candidates,
)

__all__ = [
    "SQLI_MAX_RANK_SCORE",
    "SQLI_SCORER_VERSION",
    "SQLI_TERMS",
    "XSS_MAX_RANK_SCORE",
    "XSS_SCORER_VERSION",
    "XSS_TERMS",
    "CandidateGenerator",
    "ScoringError",
    "ScoringResult",
    "ScoringTerm",
    "SQLiScorer",
    "XSSScorer",
    "generate_candidates",
]
