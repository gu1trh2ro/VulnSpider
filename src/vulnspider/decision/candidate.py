"""The unit the decision layer allocates budget over.

A :class:`DecisionCandidate` is what one already-selected, already-validated
candidate looks like once a calibrated probability, a severity and a cost have
been attached to it. It is deliberately a *projection*, in the same sense as
``selection/handoff.py``: nothing here recomputes a RankScore, re-derives
evidence, or invents an identifier. The selection layer stays the authority on
which candidates exist and what they are called (ADR-017, ADR-021); the
decision layer only decides which of them are worth spending requests on.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from math import isfinite

from vulnspider.decision.cost import SeverityPolicy, VerificationCostPolicy
from vulnspider.scoring.calibration import CalibratedProbability
from vulnspider.selection.handoff import RankedCandidateContext


class DecisionCandidateError(ValueError):
    """Raised when a candidate cannot enter the decision layer honestly."""


@dataclass(frozen=True, slots=True)
class DecisionCandidate:
    """One candidate with everything a budget allocator needs to rank it.

    ``redundancy_key`` groups candidates whose outcomes are correlated -- in
    practice those reachable through the same server-side code path. The
    budgeted selector applies diminishing returns within a group, so a hundred
    input points on one templated route cannot monopolize the budget. Callers
    that know the endpoint identity should pass its fingerprint; the default
    built from a handoff context is the request context reference, which at
    least keeps the SQLi and XSS readings of one input point together.
    """

    candidate_id: str
    family: str
    probability: float
    severity: float
    verification_cost: int
    redundancy_key: str
    logit_variance: float = 0.0
    selection_rank: int | None = None
    subject_ref: str = ""
    """The InputPoint or AccessProbePlan this candidate was derived from.

    Carried forward from the handoff so a report can join a selected candidate
    back to the request it came from. Reporting must not re-derive this
    (ARCHITECTURE.md: reporting displays authoritative results).
    """

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise DecisionCandidateError("candidate_id must not be empty")
        if not self.family:
            raise DecisionCandidateError("family must not be empty")
        if not self.redundancy_key:
            raise DecisionCandidateError("redundancy_key must not be empty")
        if isinstance(self.probability, bool) or not isinstance(
            self.probability, int | float
        ):
            raise DecisionCandidateError("probability must be numeric")
        if not 0.0 < float(self.probability) < 1.0:
            raise DecisionCandidateError(
                "probability must lie strictly inside (0, 1)"
            )
        if not isfinite(self.severity) or self.severity <= 0.0:
            raise DecisionCandidateError("severity must be positive and finite")
        if isinstance(self.verification_cost, bool) or not isinstance(
            self.verification_cost, int
        ):
            raise DecisionCandidateError("verification_cost must be an integer")
        if self.verification_cost <= 0:
            raise DecisionCandidateError("verification_cost must be positive")
        if not isfinite(self.logit_variance) or self.logit_variance < 0.0:
            raise DecisionCandidateError(
                "logit_variance must be finite and non-negative"
            )
        if self.selection_rank is not None:
            if isinstance(self.selection_rank, bool) or not isinstance(
                self.selection_rank, int
            ):
                raise DecisionCandidateError("selection_rank must be an integer")
            if self.selection_rank <= 0:
                raise DecisionCandidateError("selection_rank must be positive")

    @property
    def expected_value(self) -> float:
        """Expected worth of verifying this candidate, before redundancy."""

        return float(self.probability) * self.severity

    @property
    def value_density(self) -> float:
        """Expected worth per verification request."""

        return self.expected_value / self.verification_cost

    def with_probability(
        self,
        probability: float,
        *,
        logit_variance: float | None = None,
    ) -> DecisionCandidate:
        """Return the same candidate after a posterior update."""

        return replace(
            self,
            probability=probability,
            logit_variance=(
                self.logit_variance if logit_variance is None else logit_variance
            ),
        )


def decision_candidate_from_context(
    context: RankedCandidateContext,
    calibrated: CalibratedProbability,
    *,
    cost_policy: VerificationCostPolicy | None = None,
    severity_policy: SeverityPolicy | None = None,
    redundancy_key: str | None = None,
) -> DecisionCandidate:
    """Attach a calibrated probability, cost and severity to one handoff entry.

    This is the decision layer's only entry point from the selection contract.
    ``calibrated`` must have been produced for the same family the handoff
    reports, which stops a SQLi probability from being spent against an XSS
    candidate's cost.
    """

    if not isinstance(context, RankedCandidateContext):
        raise DecisionCandidateError("context must be a RankedCandidateContext")
    if not isinstance(calibrated, CalibratedProbability):
        raise DecisionCandidateError("calibrated must be a CalibratedProbability")
    if calibrated.family != context.family:
        raise DecisionCandidateError(
            "calibrated probability family does not match the handoff family"
        )

    costs = cost_policy or VerificationCostPolicy()
    severities = severity_policy or SeverityPolicy()
    return DecisionCandidate(
        candidate_id=context.candidate_id,
        family=context.family,
        probability=calibrated.probability,
        severity=severities.severity_for(context.family),
        verification_cost=costs.cost_for(context.family),
        redundancy_key=redundancy_key or context.request_context_ref,
        logit_variance=calibrated.logit_variance,
        selection_rank=context.rank,
        subject_ref=context.candidate_subject_ref,
    )
