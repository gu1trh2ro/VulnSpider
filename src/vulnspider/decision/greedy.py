"""Selecting the K most vulnerable input points, with optional budget mode.

The product goal is: *given a website, surface the K input points most likely
to be vulnerable, so someone who is not a security expert can study them.*
"취약도" is the **probability of being vulnerable**. Severity does not multiply
into it; it only breaks ties, and it does that through family order
(SQLi, then Reflected XSS, then BAC).

Default mode — exactly what that goal asks for
----------------------------------------------
With a Top-K and no budget (``discount = 1.0``), the objective is the plain sum
of probabilities under a cardinality constraint. Taking the K largest **is the
exact optimum**, so nothing is approximated and ``approximation_ratio`` is
``1.0``. Ties break by family order, then by ``candidate_id`` for
reproducibility.

This is deliberately simple. A selector for this goal should not be cleverer
than a sort, and measuring showed that being cleverer actively hurt: on twelve
unseen applications at K=5, ranking by probability recovered 32 of 33 true
findings while the redundancy-discounted objective recovered 26.

Budget mode — a different question, opt in
------------------------------------------
``EVALUATION_PROTOCOL.md`` §6 also asks how many findings a *request budget*
buys, which is not the same question: candidates cost different numbers of
requests, so the best K and the best spend differ. Passing a budget switches to
that objective, and a ``discount`` below 1.0 additionally models redundancy --
input points on one templated route succeed and fail together, so the second
confirmation there is worth less.

**Do not enable the discount for the default goal.** It deliberately spreads
the selection across routes, which is right when saving requests and wrong when
the user asked to see the most vulnerable input points on their own site: if
three of them sit on one route, all three should be shown.

``U(S) = Σ over groups r  Σ over j  discount^(j-1) · p_(j)``

Ordered aggregation with decreasing weights over a modular base is monotone and
submodular, so diminishing returns is a property of the objective rather than a
heuristic bolted onto the search.

Which bound applies
-------------------
* **Top-K only, discount 1.0** — modular under a cardinality constraint. The
  greedy *is* the optimum. Ratio ``1.0``.
* **Top-K only, discount < 1.0** — monotone submodular under a cardinality
  constraint; greedy by marginal gain attains ``1 − 1/e ≈ 0.632`` (Nemhauser,
  Wolsey & Fisher, 1978). Cost is irrelevant here, so this regime ranks by
  marginal gain rather than gain-per-request, which would forfeit the bound for
  nothing.
* **Budget only** — a knapsack. The better of greedy by gain-per-request and
  the single best affordable candidate attains ``½(1 − 1/e) ≈ 0.316``, or ``½``
  when the discount is 1.0. The second arm is not decoration: density greedy
  alone is unbounded, since it can fill the budget with cheap crumbs and never
  afford the one expensive candidate holding most of the value.
* **Both** — a knapsack intersected with a matroid. Density greedy is what
  runs, but no combined bound is claimed and ``approximation_ratio`` is
  ``None`` rather than a number that cannot be defended.

The bounds above are proved lower bounds against the exact optimum and are
routinely loose; ``tests/unit/test_decision_greedy.py`` checks them against
brute force.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import e, isfinite
from typing import Literal

from vulnspider.decision.candidate import DecisionCandidate

BUDGETED_SELECTOR_VERSION = "constrained-submodular-greedy-v2"

EXACT_RATIO = 1.0
CARDINALITY_APPROXIMATION_RATIO = 1.0 - 1.0 / e
MODULAR_APPROXIMATION_RATIO = 0.5
SUBMODULAR_APPROXIMATION_RATIO = 0.5 * (1.0 - 1.0 / e)

BindingConstraint = Literal["top_k", "budget", "both", "none"]


class BudgetedSelectionError(ValueError):
    """Raised when a selection cannot be computed deterministically."""


@dataclass(frozen=True, slots=True, init=False)
class BudgetedSelection:
    """The chosen verification set, what it cost, and what it is worth.

    ``selected`` is in execution order: the order greedy committed the requests
    is the order they should be spent, so an interrupted run still holds the
    most valuable prefix.

    ``approximation_ratio`` is ``None`` when both constraints are active, since
    no combined bound is claimed. ``binding_constraint`` reports which limit
    actually stopped the selection, so a caller can tell "the budget ran out"
    from "the list was long enough".
    """

    selector_version: str
    top_k: int | None
    budget: int | None
    spent_cost: int
    discount: float
    utility: float
    expected_findings: float
    approximation_ratio: float | None
    binding_constraint: BindingConstraint
    selected: tuple[DecisionCandidate, ...]
    deferred: tuple[DecisionCandidate, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("BudgetedSelection is produced only by select_candidates()")

    @classmethod
    def _from_parts(
        cls,
        *,
        top_k: int | None,
        budget: int | None,
        spent_cost: int,
        discount: float,
        utility: float,
        expected_findings: float,
        approximation_ratio: float | None,
        binding_constraint: BindingConstraint,
        selected: tuple[DecisionCandidate, ...],
        deferred: tuple[DecisionCandidate, ...],
    ) -> BudgetedSelection:
        instance = object.__new__(cls)
        object.__setattr__(instance, "selector_version", BUDGETED_SELECTOR_VERSION)
        object.__setattr__(instance, "top_k", top_k)
        object.__setattr__(instance, "budget", budget)
        object.__setattr__(instance, "spent_cost", spent_cost)
        object.__setattr__(instance, "discount", discount)
        object.__setattr__(instance, "utility", utility)
        object.__setattr__(instance, "expected_findings", expected_findings)
        object.__setattr__(instance, "approximation_ratio", approximation_ratio)
        object.__setattr__(instance, "binding_constraint", binding_constraint)
        object.__setattr__(instance, "selected", selected)
        object.__setattr__(instance, "deferred", deferred)
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.budget is not None and self.spent_cost > self.budget:
            raise BudgetedSelectionError("selection cost cannot exceed the budget")
        if self.top_k is not None and len(self.selected) > self.top_k:
            raise BudgetedSelectionError("selection cannot exceed the requested top-k")
        if self.spent_cost != sum(item.verification_cost for item in self.selected):
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


def select_candidates(
    candidates: Sequence[DecisionCandidate],
    *,
    top_k: int | None = None,
    budget: int | None = None,
    discount: float = 1.0,
) -> BudgetedSelection:
    """Choose the verification set under a Top-K cap, a request budget, or both.

    At least one constraint is required; selecting with neither would silently
    return every candidate, which is never what a caller means.

    Ties are broken by ``candidate_id`` so the result is reproducible.
    """

    if top_k is None and budget is None:
        raise BudgetedSelectionError("select_candidates needs top_k, budget, or both")
    if top_k is not None:
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise BudgetedSelectionError("top_k must be an integer")
        if top_k < 0:
            raise BudgetedSelectionError("top_k must not be negative")
    if budget is not None:
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

    # Cost only matters when a budget constrains it. Under a pure cardinality
    # constraint, ranking by gain-per-request would forfeit the (1 - 1/e) bound
    # for no reason, so that regime ranks by marginal gain instead.
    by_density = budget is not None

    greedy, binding = _greedy(
        pool,
        top_k=top_k,
        budget=budget,
        discount=discount,
        by_density=by_density,
    )
    selected = greedy
    if by_density:
        single = _best_single(pool, top_k=top_k, budget=budget)
        if set_utility(single, discount=discount) > set_utility(
            greedy, discount=discount
        ):
            selected = single
            binding = "budget" if top_k is None else "both"

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
        top_k=top_k,
        budget=budget,
        spent_cost=sum(candidate.verification_cost for candidate in selected),
        discount=discount,
        utility=set_utility(selected, discount=discount),
        expected_findings=sum(float(item.probability) for item in selected),
        approximation_ratio=_approximation_ratio(
            top_k=top_k,
            budget=budget,
            discount=discount,
        ),
        binding_constraint=binding if deferred else "none",
        selected=selected,
        deferred=deferred,
    )


def _approximation_ratio(
    *,
    top_k: int | None,
    budget: int | None,
    discount: float,
) -> float | None:
    if budget is None:
        if discount == 1.0:
            # No budget and no redundancy discount: the objective is modular
            # under a cardinality constraint, so taking the K largest is the
            # exact optimum. Nothing is approximated.
            return EXACT_RATIO
        return CARDINALITY_APPROXIMATION_RATIO
    if top_k is not None:
        # Knapsack intersected with a matroid: no combined bound is claimed.
        return None
    return (
        MODULAR_APPROXIMATION_RATIO
        if discount == 1.0
        else SUBMODULAR_APPROXIMATION_RATIO
    )


def _greedy(
    pool: Sequence[DecisionCandidate],
    *,
    top_k: int | None,
    budget: int | None,
    discount: float,
    by_density: bool,
) -> tuple[tuple[DecisionCandidate, ...], BindingConstraint]:
    selected: list[DecisionCandidate] = []
    group_values: dict[str, list[float]] = {}
    remaining = list(pool)
    spent = 0
    stopped_by_budget = False

    while remaining:
        if top_k is not None and len(selected) >= top_k:
            return tuple(selected), ("both" if stopped_by_budget else "top_k")

        best: DecisionCandidate | None = None
        best_key: tuple[float, str] | None = None
        blocked_by_budget = False
        for candidate in remaining:
            if budget is not None and spent + candidate.verification_cost > budget:
                blocked_by_budget = True
                continue
            gain = marginal_gain(
                group_values.get(candidate.redundancy_key, []),
                candidate.expected_value,
                discount=discount,
            )
            if gain <= 0.0:
                continue
            score = gain / candidate.verification_cost if by_density else gain
            key = (-score, candidate.family_priority, candidate.candidate_id)
            if best_key is None or key < best_key:
                best = candidate
                best_key = key
        if best is None:
            return tuple(selected), ("budget" if blocked_by_budget else "none")
        stopped_by_budget = stopped_by_budget or blocked_by_budget

        selected.append(best)
        group_values.setdefault(best.redundancy_key, []).append(best.expected_value)
        spent += best.verification_cost
        remaining.remove(best)

    return tuple(selected), "none"


def _best_single(
    pool: Sequence[DecisionCandidate],
    *,
    top_k: int | None,
    budget: int | None,
) -> tuple[DecisionCandidate, ...]:
    if top_k is not None and top_k < 1:
        return ()
    affordable = [
        candidate
        for candidate in pool
        if budget is None or candidate.verification_cost <= budget
    ]
    if not affordable:
        return ()
    return (
        min(affordable, key=lambda item: (-item.expected_value, item.candidate_id)),
    )


def _ordered_sum(sorted_values: Sequence[float], discount: float) -> float:
    return sum(
        (discount**position) * value for position, value in enumerate(sorted_values)
    )


def _validate_discount(discount: float) -> None:
    if isinstance(discount, bool) or not isinstance(discount, int | float):
        raise BudgetedSelectionError("discount must be numeric")
    if not isfinite(float(discount)) or not 0.0 < float(discount) <= 1.0:
        raise BudgetedSelectionError("discount must lie inside (0, 1]")
