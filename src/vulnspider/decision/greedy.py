"""Budget-constrained candidate selection with a stated approximation bound.

This replaces "take the first ``k``" with "spend ``B`` verification requests as
well as possible", which is the question ``docs/EVALUATION_PROTOCOL.md`` §6
already says the project is measured on (cumulative findings against request
budget).

The utility
-----------
Writing ``v(c) = P(vulnerable | evidence) * severity(family)``, the value of a
selected set is *not* the plain sum of ``v``. Input points reachable through
one server-side code path -- a templated route with a hundred product ids --
succeed and fail together, so the second confirmation on that path is worth
much less than the first. Candidates sharing a ``redundancy_key`` are therefore
aggregated with geometrically decreasing weights:

``U(S) = Σ over groups r  Σ over j  discount^(j-1) · v_(j)``

where ``v_(1) ≥ v_(2) ≥ …`` are the group's selected values in decreasing
order. Ordered aggregation with decreasing weights over a modular base is
monotone and submodular, so the diminishing-returns behaviour is a property of
the objective rather than a heuristic bolted onto the search.

The guarantee
-------------
Maximising a monotone submodular ``U`` under a knapsack constraint is NP-hard,
but taking the better of

* greedy by *marginal gain per request*, and
* the single best affordable candidate

is guaranteed to reach ``½(1 − 1/e) ≈ 0.316`` of the optimum. The second arm is
not decoration: density greedy alone is unbounded, because it can fill the
budget with cheap crumbs and never afford the one expensive candidate that
carries most of the value.

With ``discount = 1.0`` the objective collapses to a modular sum, the problem
becomes 0/1 knapsack, and the same procedure is a ``½``-approximation. Note
that this is the *better* bound: submodularity buys a more faithful model of
redundancy, not a tighter guarantee. Both constants are lower bounds proved
against the exact optimum, and both are routinely loose in practice --
``tests/unit/test_decision_greedy.py`` checks them against brute force.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import e, isfinite

from vulnspider.decision.candidate import DecisionCandidate

BUDGETED_SELECTOR_VERSION = "budgeted-submodular-greedy-v1"

MODULAR_APPROXIMATION_RATIO = 0.5
SUBMODULAR_APPROXIMATION_RATIO = 0.5 * (1.0 - 1.0 / e)


class BudgetedSelectionError(ValueError):
    """Raised when a budgeted selection cannot be computed deterministically."""


@dataclass(frozen=True, slots=True, init=False)
class BudgetedSelection:
    """The chosen verification set, its cost, and what it is worth.

    ``selected`` is in execution order: the order greedy committed the requests
    is the order they should be spent, so an interrupted run still holds the
    most valuable prefix.
    """

    selector_version: str
    budget: int
    spent_cost: int
    discount: float
    utility: float
    expected_findings: float
    approximation_ratio: float
    selected: tuple[DecisionCandidate, ...]
    deferred: tuple[DecisionCandidate, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "BudgetedSelection is produced only by select_within_budget()"
        )

    @classmethod
    def _from_parts(
        cls,
        *,
        budget: int,
        spent_cost: int,
        discount: float,
        utility: float,
        expected_findings: float,
        approximation_ratio: float,
        selected: tuple[DecisionCandidate, ...],
        deferred: tuple[DecisionCandidate, ...],
    ) -> BudgetedSelection:
        instance = object.__new__(cls)
        object.__setattr__(instance, "selector_version", BUDGETED_SELECTOR_VERSION)
        object.__setattr__(instance, "budget", budget)
        object.__setattr__(instance, "spent_cost", spent_cost)
        object.__setattr__(instance, "discount", discount)
        object.__setattr__(instance, "utility", utility)
        object.__setattr__(instance, "expected_findings", expected_findings)
        object.__setattr__(instance, "approximation_ratio", approximation_ratio)
        object.__setattr__(instance, "selected", selected)
        object.__setattr__(instance, "deferred", deferred)
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.spent_cost > self.budget:
            raise BudgetedSelectionError("selection cost cannot exceed the budget")
        if self.spent_cost != sum(
            item.verification_cost for item in self.selected
        ):
            raise BudgetedSelectionError(
                "spent cost must equal the selected verification costs"
            )
        selected_ids = tuple(item.candidate_id for item in self.selected)
        if len(selected_ids) != len(set(selected_ids)):
            raise BudgetedSelectionError("selected candidates must be unique")
        deferred_ids = {item.candidate_id for item in self.deferred}
        if deferred_ids & set(selected_ids):
            raise BudgetedSelectionError(
                "a candidate cannot be both selected and deferred"
            )
        recomputed = set_utility(self.selected, discount=self.discount)
        if abs(recomputed - self.utility) > 1e-9:
            raise BudgetedSelectionError(
                "reported utility does not match the selected set"
            )


def set_utility(
    candidates: Sequence[DecisionCandidate],
    *,
    discount: float,
) -> float:
    """Ordered-weighted utility of a selected set under redundancy discounting."""

    _validate_discount(discount)
    grouped: dict[str, list[float]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.redundancy_key, []).append(
            candidate.expected_value
        )
    total = 0.0
    for values in grouped.values():
        for position, value in enumerate(sorted(values, reverse=True)):
            total += (discount**position) * value
    return total


def marginal_gain(
    group_values: Sequence[float],
    value: float,
    *,
    discount: float,
) -> float:
    """Increase in utility from adding ``value`` to a group already holding these."""

    _validate_discount(discount)
    before = _ordered_sum(sorted(group_values, reverse=True), discount)
    after = _ordered_sum(sorted([*group_values, value], reverse=True), discount)
    return after - before


def select_within_budget(
    candidates: Sequence[DecisionCandidate],
    *,
    budget: int,
    discount: float = 0.5,
) -> BudgetedSelection:
    """Choose the verification set to spend ``budget`` requests on.

    Returns the better of density-greedy and the best affordable single
    candidate, which is what earns the approximation bound documented above.
    Ties are broken by ``candidate_id`` so the result is reproducible.
    """

    if isinstance(budget, bool) or not isinstance(budget, int):
        raise BudgetedSelectionError("budget must be an integer")
    if budget < 0:
        raise BudgetedSelectionError("budget must not be negative")
    _validate_discount(discount)

    pool = tuple(candidates)
    for candidate in pool:
        if not isinstance(candidate, DecisionCandidate):
            raise BudgetedSelectionError(
                "candidates must contain DecisionCandidate objects"
            )
    identifiers = [candidate.candidate_id for candidate in pool]
    if len(identifiers) != len(set(identifiers)):
        raise BudgetedSelectionError("candidates must be unique by candidate_id")

    greedy = _density_greedy(pool, budget=budget, discount=discount)
    single = _best_single(pool, budget=budget)

    greedy_utility = set_utility(greedy, discount=discount)
    single_utility = set_utility(single, discount=discount)
    if single_utility > greedy_utility:
        selected = single
        utility = single_utility
    else:
        selected = greedy
        utility = greedy_utility

    selected_ids = {candidate.candidate_id for candidate in selected}
    deferred = tuple(
        sorted(
            (
                candidate
                for candidate in pool
                if candidate.candidate_id not in selected_ids
            ),
            key=lambda item: item.candidate_id,
        )
    )
    return BudgetedSelection._from_parts(
        budget=budget,
        spent_cost=sum(candidate.verification_cost for candidate in selected),
        discount=discount,
        utility=utility,
        expected_findings=sum(
            float(candidate.probability) for candidate in selected
        ),
        approximation_ratio=(
            MODULAR_APPROXIMATION_RATIO
            if discount == 1.0
            else SUBMODULAR_APPROXIMATION_RATIO
        ),
        selected=selected,
        deferred=deferred,
    )


def _density_greedy(
    pool: Sequence[DecisionCandidate],
    *,
    budget: int,
    discount: float,
) -> tuple[DecisionCandidate, ...]:
    selected: list[DecisionCandidate] = []
    group_values: dict[str, list[float]] = {}
    remaining = list(pool)
    spent = 0

    while remaining:
        best: DecisionCandidate | None = None
        best_key: tuple[float, str] | None = None
        for candidate in remaining:
            if spent + candidate.verification_cost > budget:
                continue
            gain = marginal_gain(
                group_values.get(candidate.redundancy_key, []),
                candidate.expected_value,
                discount=discount,
            )
            if gain <= 0.0:
                continue
            key = (-gain / candidate.verification_cost, candidate.candidate_id)
            if best_key is None or key < best_key:
                best = candidate
                best_key = key
        if best is None:
            break
        selected.append(best)
        group_values.setdefault(best.redundancy_key, []).append(best.expected_value)
        spent += best.verification_cost
        remaining.remove(best)
    return tuple(selected)


def _best_single(
    pool: Sequence[DecisionCandidate],
    *,
    budget: int,
) -> tuple[DecisionCandidate, ...]:
    affordable = [
        candidate for candidate in pool if candidate.verification_cost <= budget
    ]
    if not affordable:
        return ()
    best = min(
        affordable,
        key=lambda item: (-item.expected_value, item.candidate_id),
    )
    return (best,)


def _ordered_sum(sorted_values: Sequence[float], discount: float) -> float:
    return sum(
        (discount**position) * value
        for position, value in enumerate(sorted_values)
    )


def _validate_discount(discount: float) -> None:
    if isinstance(discount, bool) or not isinstance(discount, int | float):
        raise BudgetedSelectionError("discount must be numeric")
    if not isfinite(float(discount)) or not 0.0 < float(discount) <= 1.0:
        raise BudgetedSelectionError("discount must lie inside (0, 1]")
