from __future__ import annotations

import random
import unittest
from itertools import combinations

from vulnspider.decision.candidate import DecisionCandidate, DecisionCandidateError
from vulnspider.decision.greedy import (
    MODULAR_APPROXIMATION_RATIO,
    SUBMODULAR_APPROXIMATION_RATIO,
    BudgetedSelectionError,
    marginal_gain,
    select_within_budget,
    set_utility,
)


def _candidate(
    identifier: str,
    *,
    probability: float,
    severity: float = 10.0,
    cost: int = 1,
    group: str = "g",
) -> DecisionCandidate:
    return DecisionCandidate(
        candidate_id=identifier,
        family="SQLI",
        probability=probability,
        severity=severity,
        verification_cost=cost,
        redundancy_key=group,
    )


def _brute_force_optimum(
    pool: tuple[DecisionCandidate, ...],
    *,
    budget: int,
    discount: float,
) -> float:
    best = 0.0
    for size in range(len(pool) + 1):
        for subset in combinations(pool, size):
            if sum(item.verification_cost for item in subset) > budget:
                continue
            best = max(best, set_utility(subset, discount=discount))
    return best


class UtilityTests(unittest.TestCase):
    def test_distinct_groups_sum_without_discount(self) -> None:
        pool = (
            _candidate("a", probability=0.5, group="g1"),
            _candidate("b", probability=0.5, group="g2"),
        )
        self.assertAlmostEqual(set_utility(pool, discount=0.5), 10.0)

    def test_same_group_second_item_is_discounted(self) -> None:
        pool = (
            _candidate("a", probability=0.5, group="g1"),
            _candidate("b", probability=0.5, group="g1"),
        )
        self.assertAlmostEqual(set_utility(pool, discount=0.5), 7.5)

    def test_discount_applies_in_decreasing_value_order(self) -> None:
        """Utility is a set function: insertion order must not change it."""

        low = _candidate("a", probability=0.2, group="g1")
        high = _candidate("b", probability=0.9, group="g1")
        self.assertAlmostEqual(
            set_utility((low, high), discount=0.5),
            set_utility((high, low), discount=0.5),
        )
        self.assertAlmostEqual(set_utility((low, high), discount=0.5), 10.0)

    def test_marginal_gain_shrinks_as_a_group_fills(self) -> None:
        gains = [
            marginal_gain([5.0] * filled, 5.0, discount=0.5) for filled in range(4)
        ]
        self.assertEqual(gains, sorted(gains, reverse=True))
        self.assertAlmostEqual(gains[0], 5.0)
        self.assertAlmostEqual(gains[1], 2.5)

    def test_unit_discount_is_a_plain_sum(self) -> None:
        pool = tuple(
            _candidate(f"c{index}", probability=0.5, group="g1")
            for index in range(4)
        )
        self.assertAlmostEqual(set_utility(pool, discount=1.0), 20.0)


class BudgetTests(unittest.TestCase):
    def test_selection_never_exceeds_the_budget(self) -> None:
        pool = tuple(
            _candidate(f"c{index}", probability=0.5, cost=3, group=f"g{index}")
            for index in range(10)
        )
        selection = select_within_budget(pool, budget=10)
        self.assertLessEqual(selection.spent_cost, 10)
        self.assertEqual(len(selection.selected), 3)

    def test_zero_budget_selects_nothing(self) -> None:
        pool = (_candidate("a", probability=0.9),)
        selection = select_within_budget(pool, budget=0)
        self.assertEqual(selection.selected, ())
        self.assertEqual(selection.spent_cost, 0)
        self.assertEqual(len(selection.deferred), 1)

    def test_unaffordable_candidates_are_all_deferred(self) -> None:
        pool = (_candidate("a", probability=0.9, cost=50),)
        selection = select_within_budget(pool, budget=10)
        self.assertEqual(selection.selected, ())
        self.assertEqual(len(selection.deferred), 1)

    def test_every_candidate_is_selected_or_deferred_exactly_once(self) -> None:
        pool = tuple(
            _candidate(f"c{index}", probability=0.4, cost=2, group=f"g{index % 3}")
            for index in range(9)
        )
        selection = select_within_budget(pool, budget=7)
        accounted = {item.candidate_id for item in selection.selected} | {
            item.candidate_id for item in selection.deferred
        }
        self.assertEqual(accounted, {item.candidate_id for item in pool})
        self.assertEqual(
            len(selection.selected) + len(selection.deferred),
            len(pool),
        )


class BestSingleGuardTests(unittest.TestCase):
    def test_one_expensive_prize_beats_many_cheap_crumbs(self) -> None:
        """Density greedy alone fills the budget with crumbs and never affords
        the prize. The best-single arm is what makes the bound hold."""

        crumbs = tuple(
            _candidate(
                f"crumb{index}",
                probability=0.02,
                severity=1.0,
                cost=1,
                group=f"crumb{index}",
            )
            for index in range(10)
        )
        prize = _candidate(
            "prize", probability=0.99, severity=100.0, cost=10, group="prize"
        )
        selection = select_within_budget((*crumbs, prize), budget=10)
        self.assertEqual(
            [item.candidate_id for item in selection.selected], ["prize"]
        )

    def test_reported_ratio_depends_on_the_discount(self) -> None:
        pool = (_candidate("a", probability=0.5),)
        self.assertAlmostEqual(
            select_within_budget(pool, budget=5, discount=1.0).approximation_ratio,
            MODULAR_APPROXIMATION_RATIO,
        )
        self.assertAlmostEqual(
            select_within_budget(pool, budget=5, discount=0.5).approximation_ratio,
            SUBMODULAR_APPROXIMATION_RATIO,
        )


class ApproximationBoundTests(unittest.TestCase):
    """The claimed bound checked against exhaustive search."""

    def _random_pool(
        self,
        generator: random.Random,
        size: int,
    ) -> tuple[DecisionCandidate, ...]:
        return tuple(
            DecisionCandidate(
                candidate_id=f"c{index}",
                family="SQLI",
                probability=generator.uniform(0.05, 0.95),
                severity=generator.uniform(1.0, 10.0),
                verification_cost=generator.randint(1, 6),
                redundancy_key=f"g{generator.randint(0, 2)}",
            )
            for index in range(size)
        )

    def test_submodular_bound_holds_against_brute_force(self) -> None:
        generator = random.Random(4242)
        for _trial in range(150):
            pool = self._random_pool(generator, generator.randint(1, 9))
            budget = generator.randint(1, 14)
            achieved = select_within_budget(
                pool, budget=budget, discount=0.5
            ).utility
            optimum = _brute_force_optimum(pool, budget=budget, discount=0.5)
            self.assertGreaterEqual(
                achieved + 1e-9,
                SUBMODULAR_APPROXIMATION_RATIO * optimum,
            )

    def test_modular_bound_holds_against_brute_force(self) -> None:
        generator = random.Random(99)
        for _trial in range(150):
            pool = self._random_pool(generator, generator.randint(1, 9))
            budget = generator.randint(1, 14)
            achieved = select_within_budget(
                pool, budget=budget, discount=1.0
            ).utility
            optimum = _brute_force_optimum(pool, budget=budget, discount=1.0)
            self.assertGreaterEqual(
                achieved + 1e-9,
                MODULAR_APPROXIMATION_RATIO * optimum,
            )

    def test_greedy_is_usually_far_better_than_its_worst_case(self) -> None:
        generator = random.Random(2026)
        ratios: list[float] = []
        for _trial in range(80):
            pool = self._random_pool(generator, 8)
            budget = generator.randint(4, 12)
            optimum = _brute_force_optimum(pool, budget=budget, discount=0.5)
            if optimum <= 0.0:
                continue
            achieved = select_within_budget(
                pool, budget=budget, discount=0.5
            ).utility
            ratios.append(achieved / optimum)
        self.assertGreater(sum(ratios) / len(ratios), 0.95)


class RedundancyTests(unittest.TestCase):
    def test_discount_spreads_the_budget_across_code_paths(self) -> None:
        crowded = tuple(
            _candidate(f"crowd{index}", probability=0.80, cost=1, group="shared")
            for index in range(5)
        )
        lone = _candidate("lone", probability=0.60, cost=1, group="isolated")
        pool = (*crowded, lone)

        discounted = select_within_budget(pool, budget=2, discount=0.3)
        flat = select_within_budget(pool, budget=2, discount=1.0)

        self.assertIn("lone", [item.candidate_id for item in discounted.selected])
        self.assertNotIn("lone", [item.candidate_id for item in flat.selected])


class DeterminismTests(unittest.TestCase):
    def test_repeated_runs_agree(self) -> None:
        generator = random.Random(5)
        pool = tuple(
            DecisionCandidate(
                candidate_id=f"c{index}",
                family="SQLI",
                probability=generator.uniform(0.1, 0.9),
                severity=generator.uniform(1.0, 9.0),
                verification_cost=generator.randint(1, 4),
                redundancy_key=f"g{index % 3}",
            )
            for index in range(12)
        )
        first = select_within_budget(pool, budget=9)
        second = select_within_budget(tuple(reversed(pool)), budget=9)
        self.assertEqual(
            [item.candidate_id for item in first.selected],
            [item.candidate_id for item in second.selected],
        )

    def test_ties_break_on_candidate_id(self) -> None:
        pool = (
            _candidate("zebra", probability=0.5, group="g1"),
            _candidate("alpha", probability=0.5, group="g2"),
        )
        selection = select_within_budget(pool, budget=1)
        self.assertEqual(
            [item.candidate_id for item in selection.selected], ["alpha"]
        )


class ValidationTests(unittest.TestCase):
    def test_duplicate_candidate_ids_are_rejected(self) -> None:
        pool = (
            _candidate("same", probability=0.5, group="g1"),
            _candidate("same", probability=0.6, group="g2"),
        )
        with self.assertRaises(BudgetedSelectionError):
            select_within_budget(pool, budget=5)

    def test_negative_budget_is_rejected(self) -> None:
        with self.assertRaises(BudgetedSelectionError):
            select_within_budget((), budget=-1)

    def test_boolean_budget_is_rejected(self) -> None:
        with self.assertRaises(BudgetedSelectionError):
            select_within_budget((), budget=True)

    def test_discount_outside_the_unit_interval_is_rejected(self) -> None:
        for discount in (0.0, 1.5, -0.2):
            with self.assertRaises(BudgetedSelectionError):
                select_within_budget((), budget=5, discount=discount)

    def test_certain_probability_is_rejected(self) -> None:
        with self.assertRaises(DecisionCandidateError):
            _candidate("a", probability=1.0)

    def test_zero_cost_is_rejected(self) -> None:
        with self.assertRaises(DecisionCandidateError):
            _candidate("a", probability=0.5, cost=0)

    def test_expected_findings_counts_probability_not_utility(self) -> None:
        pool = (
            _candidate("a", probability=0.8, severity=9.8, cost=1, group="g1"),
            _candidate("b", probability=0.4, severity=6.1, cost=1, group="g2"),
        )
        selection = select_within_budget(pool, budget=2)
        self.assertAlmostEqual(selection.expected_findings, 1.2)


if __name__ == "__main__":
    unittest.main()
