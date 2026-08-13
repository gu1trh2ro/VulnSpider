"""Budget-aware decision layer over the authoritative candidate selection.

The scoring and selection layers answer "which candidates exist and in what
order". This package answers the three questions a verification run actually
faces: how likely is each candidate, how many requests should each one get, and
how many candidates must be kept to hold a recall guarantee.

It consumes the selection layer's published contract and recomputes none of it
(ADR-017, ADR-021). See
``docs/exec-plans/completed/decision-layer-algorithms.md`` and ADR-022 through
ADR-024.
"""

from vulnspider.decision.candidate import (
    DecisionCandidate,
    DecisionCandidateError,
    decision_candidate_from_context,
)
from vulnspider.decision.conformal import (
    CONFORMAL_METHOD_VERSION,
    ConformalCalibrationGroup,
    ConformalCalibrationItem,
    ConformalError,
    ConformalThreshold,
    calibrate_conformal_threshold,
    minimum_groups_for_target,
    select_by_threshold,
)
from vulnspider.decision.cost import (
    DEFAULT_FAMILY_COSTS,
    DEFAULT_FAMILY_SEVERITY,
    SEVERITY_POLICY_VERSION,
    VERIFICATION_COST_POLICY_VERSION,
    DecisionPolicyError,
    SeverityPolicy,
    VerificationCostPolicy,
)
from vulnspider.decision.greedy import (
    BUDGETED_SELECTOR_VERSION,
    CARDINALITY_APPROXIMATION_RATIO,
    EXACT_RATIO,
    MODULAR_APPROXIMATION_RATIO,
    SUBMODULAR_APPROXIMATION_RATIO,
    BudgetedSelection,
    BudgetedSelectionError,
    marginal_gain,
    select_candidates,
    set_utility,
)
from vulnspider.decision.policy import (
    DECISION_POLICY_VERSION,
    DecisionOutcome,
    DecisionPolicyRunError,
    run_decision_layer,
)
from vulnspider.decision.voi import (
    INFORMATION_GAIN_VERSION,
    InformationGainError,
    ProbeInformationGain,
    ProbeOption,
    binary_entropy,
    evaluate_probe,
    posterior_after_observation,
    probe_options_from_rates,
    rank_probes_by_information_density,
)

__all__ = [
    "BUDGETED_SELECTOR_VERSION",
    "CARDINALITY_APPROXIMATION_RATIO",
    "EXACT_RATIO",
    "CONFORMAL_METHOD_VERSION",
    "DECISION_POLICY_VERSION",
    "DEFAULT_FAMILY_COSTS",
    "DEFAULT_FAMILY_SEVERITY",
    "INFORMATION_GAIN_VERSION",
    "MODULAR_APPROXIMATION_RATIO",
    "SEVERITY_POLICY_VERSION",
    "SUBMODULAR_APPROXIMATION_RATIO",
    "VERIFICATION_COST_POLICY_VERSION",
    "BudgetedSelection",
    "BudgetedSelectionError",
    "ConformalCalibrationGroup",
    "ConformalCalibrationItem",
    "ConformalError",
    "ConformalThreshold",
    "DecisionCandidate",
    "DecisionCandidateError",
    "DecisionOutcome",
    "DecisionPolicyError",
    "DecisionPolicyRunError",
    "InformationGainError",
    "ProbeInformationGain",
    "ProbeOption",
    "SeverityPolicy",
    "VerificationCostPolicy",
    "binary_entropy",
    "calibrate_conformal_threshold",
    "decision_candidate_from_context",
    "evaluate_probe",
    "marginal_gain",
    "minimum_groups_for_target",
    "posterior_after_observation",
    "probe_options_from_rates",
    "rank_probes_by_information_density",
    "run_decision_layer",
    "select_by_threshold",
    "select_candidates",
    "set_utility",
]
