"""The decision-layer policy: explore, cut, then commit.

One pass over the three layers:

1. **Explore.** While an exploration budget remains, run the probe with the
   highest expected information gain per request, update that candidate's
   posterior with the outcome, and re-rank. This is the step that makes the
   pipeline sequential -- what the first probe returns changes what the second
   one asks.
2. **Cut.** Apply the conformal threshold, if one has been calibrated, to get
   the smallest candidate set carrying the target recall guarantee.
3. **Commit.** Spend the verification budget over that set with the budgeted
   submodular selector.

The policy performs no I/O. Probe outcomes arrive through an injected
``ProbeOutcomeSource``, which keeps network transport behind an interface as
``AGENTS.md`` requires and lets the tests drive the whole loop deterministically
with a fake.

It also never invents a candidate. Everything it returns traces back to a
``DecisionCandidate`` the caller supplied, which the selection layer
authoritatively produced.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.conformal import (
    ConformalThreshold,
    select_by_threshold,
)
from vulnspider.decision.greedy import (
    BudgetedSelection,
    select_candidates,
)
from vulnspider.decision.voi import (
    ProbeInformationGain,
    ProbeOption,
    posterior_after_observation,
    rank_probes_by_information_density,
)

DECISION_POLICY_VERSION = "explore-cut-commit-v1"

ProbeOutcomeSource = Callable[[ProbeOption], bool]


class DecisionPolicyRunError(ValueError):
    """Raised when the decision policy cannot run as configured."""


@dataclass(frozen=True, slots=True, init=False)
class DecisionOutcome:
    """Everything the decision layer decided, and what it spent deciding it."""

    policy_version: str
    initial_candidates: int
    exploration_requests_spent: int
    information_gains: tuple[ProbeInformationGain, ...]
    scored: tuple[DecisionCandidate, ...]
    conformal: ConformalThreshold | None
    conformal_set_size: int
    budget_covers_conformal_set: bool
    selection: BudgetedSelection

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("DecisionOutcome is produced only by run_decision_layer()")

    @classmethod
    def _from_parts(
        cls,
        *,
        initial_candidates: int,
        exploration_requests_spent: int,
        information_gains: tuple[ProbeInformationGain, ...],
        scored: tuple[DecisionCandidate, ...],
        conformal: ConformalThreshold | None,
        conformal_set_size: int,
        budget_covers_conformal_set: bool,
        selection: BudgetedSelection,
    ) -> DecisionOutcome:
        instance = object.__new__(cls)
        object.__setattr__(instance, "policy_version", DECISION_POLICY_VERSION)
        object.__setattr__(instance, "initial_candidates", initial_candidates)
        object.__setattr__(
            instance, "exploration_requests_spent", exploration_requests_spent
        )
        object.__setattr__(instance, "information_gains", information_gains)
        object.__setattr__(instance, "scored", scored)
        object.__setattr__(instance, "conformal", conformal)
        object.__setattr__(instance, "conformal_set_size", conformal_set_size)
        object.__setattr__(
            instance, "budget_covers_conformal_set", budget_covers_conformal_set
        )
        object.__setattr__(instance, "selection", selection)
        instance.validate()
        return instance

    @property
    def total_requests_spent(self) -> int:
        """Exploration plus verification requests this decision commits to."""

        return self.exploration_requests_spent + self.selection.spent_cost

    def validate(self) -> None:
        if self.initial_candidates != len(self.scored):
            raise DecisionPolicyRunError(
                "scored candidates must account for every input candidate"
            )
        if self.exploration_requests_spent < 0:
            raise DecisionPolicyRunError(
                "exploration requests spent must not be negative"
            )
        if self.conformal_set_size > len(self.scored):
            raise DecisionPolicyRunError(
                "conformal set cannot exceed the scored candidates"
            )
        self.selection.validate()
        scored_ids = {item.candidate_id for item in self.scored}
        for item in self.selection.selected:
            if item.candidate_id not in scored_ids:
                raise DecisionPolicyRunError(
                    "selection must not introduce an unscored candidate"
                )


def run_decision_layer(
    candidates: Sequence[DecisionCandidate],
    *,
    top_k: int | None = None,
    verification_budget: int | None = None,
    exploration_budget: int = 0,
    probe_options: Sequence[ProbeOption] = (),
    observe: ProbeOutcomeSource | None = None,
    conformal: ConformalThreshold | None = None,
    discount: float = 0.5,
) -> DecisionOutcome:
    """Run explore-cut-commit over one already-selected candidate pool."""

    pool = tuple(candidates)
    for candidate in pool:
        if not isinstance(candidate, DecisionCandidate):
            raise DecisionPolicyRunError(
                "candidates must contain DecisionCandidate objects"
            )
    identifiers = [candidate.candidate_id for candidate in pool]
    if len(identifiers) != len(set(identifiers)):
        raise DecisionPolicyRunError("candidates must be unique by candidate_id")
    if top_k is None and verification_budget is None:
        raise DecisionPolicyRunError(
            "run_decision_layer needs top_k, verification_budget, or both"
        )
    for name, value in (
        ("top_k", top_k),
        ("verification_budget", verification_budget),
        ("exploration_budget", exploration_budget),
    ):
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            raise DecisionPolicyRunError(f"{name} must be an integer")
        if value < 0:
            raise DecisionPolicyRunError(f"{name} must not be negative")
    if conformal is not None and not isinstance(conformal, ConformalThreshold):
        raise DecisionPolicyRunError("conformal must be a ConformalThreshold")

    options = tuple(probe_options)
    for option in options:
        if not isinstance(option, ProbeOption):
            raise DecisionPolicyRunError(
                "probe_options must contain ProbeOption objects"
            )
        if option.candidate_id not in set(identifiers):
            raise DecisionPolicyRunError(
                f"probe targets unknown candidate {option.candidate_id!r}"
            )
    if options and exploration_budget > 0 and observe is None:
        raise DecisionPolicyRunError(
            "exploration requires an observe callable to supply probe outcomes"
        )

    updated, spent, gains = _explore(
        pool,
        options=options,
        exploration_budget=exploration_budget,
        observe=observe,
    )

    eligible = (
        select_by_threshold(updated, conformal.threshold)
        if conformal is not None
        else updated
    )
    conformal_cost = sum(candidate.verification_cost for candidate in eligible)
    selection = select_candidates(
        eligible,
        top_k=top_k,
        budget=verification_budget,
        discount=discount,
    )
    return DecisionOutcome._from_parts(
        initial_candidates=len(pool),
        exploration_requests_spent=spent,
        information_gains=gains,
        scored=tuple(
            sorted(
                updated,
                key=lambda item: (-float(item.probability), item.candidate_id),
            )
        ),
        conformal=conformal,
        conformal_set_size=len(eligible),
        budget_covers_conformal_set=(
            verification_budget is None or conformal_cost <= verification_budget
        ),
        selection=selection,
    )


def _explore(
    pool: Sequence[DecisionCandidate],
    *,
    options: Sequence[ProbeOption],
    exploration_budget: int,
    observe: ProbeOutcomeSource | None,
) -> tuple[
    tuple[DecisionCandidate, ...],
    int,
    tuple[ProbeInformationGain, ...],
]:
    by_id = {candidate.candidate_id: candidate for candidate in pool}
    if not options or exploration_budget <= 0 or observe is None:
        return tuple(pool), 0, ()

    remaining = {option.probe_id: option for option in options}
    if len(remaining) != len(options):
        raise DecisionPolicyRunError("probe options must be unique by probe_id")

    gains: list[ProbeInformationGain] = []
    spent = 0
    while remaining and spent < exploration_budget:
        priors = {
            candidate_id: float(candidate.probability)
            for candidate_id, candidate in by_id.items()
        }
        ranked = rank_probes_by_information_density(
            priors,
            tuple(remaining.values()),
        )
        chosen = next(
            (
                item
                for item in ranked
                if item.request_cost <= exploration_budget - spent
                and item.expected_information_gain > 0.0
            ),
            None,
        )
        if chosen is None:
            break

        option = remaining.pop(chosen.probe_id)
        outcome = observe(option)
        if not isinstance(outcome, bool):
            raise DecisionPolicyRunError("observe must return a bool outcome")

        candidate = by_id[option.candidate_id]
        posterior = posterior_after_observation(
            float(candidate.probability),
            true_positive_rate=option.true_positive_rate,
            false_positive_rate=option.false_positive_rate,
            observed=outcome,
        )
        by_id[option.candidate_id] = candidate.with_probability(posterior)
        gains.append(chosen)
        spent += option.request_cost

    ordered = tuple(by_id[candidate.candidate_id] for candidate in pool)
    return ordered, spent, tuple(gains)
