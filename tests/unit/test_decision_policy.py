from __future__ import annotations

import unittest

from vulnspider.decision.candidate import (
    DecisionCandidate,
    DecisionCandidateError,
    decision_candidate_from_context,
)
from vulnspider.decision.conformal import (
    ConformalCalibrationGroup,
    ConformalCalibrationItem,
    calibrate_conformal_threshold,
)
from vulnspider.decision.cost import (
    DEFAULT_FAMILY_COSTS,
    DEFAULT_FAMILY_SEVERITY,
    DecisionPolicyError,
    SeverityPolicy,
    VerificationCostPolicy,
)
from vulnspider.decision.policy import (
    DecisionPolicyRunError,
    run_decision_layer,
)
from vulnspider.decision.voi import ProbeOption
from vulnspider.domain import FeatureObservation, FeatureVector
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.scoring import SQLiScorer, XSSScorer
from vulnspider.scoring.calibration import (
    CalibratedScorer,
    heuristic_prior_for_family,
)
from vulnspider.selection import (
    build_mutation_handoff,
    select_combined_top_k,
    select_top_k,
)
from vulnspider.access.selection import select_top_k_access


def _candidate(
    identifier: str,
    *,
    probability: float,
    cost: int = 2,
    group: str | None = None,
    family: str = "SQLI",
) -> DecisionCandidate:
    return DecisionCandidate(
        candidate_id=identifier,
        family=family,
        probability=probability,
        severity=9.8,
        verification_cost=cost,
        redundancy_key=group or identifier,
    )


def _option(
    probe_id: str,
    candidate_id: str,
    *,
    tpr: float = 0.9,
    fpr: float = 0.05,
    cost: int = 1,
) -> ProbeOption:
    return ProbeOption(
        probe_id=probe_id,
        candidate_id=candidate_id,
        feature_name="sql_error_pattern",
        true_positive_rate=tpr,
        false_positive_rate=fpr,
        request_cost=cost,
    )


class CommitOnlyTests(unittest.TestCase):
    def test_without_probes_the_policy_is_a_budgeted_selection(self) -> None:
        pool = (
            _candidate("a", probability=0.8),
            _candidate("b", probability=0.6),
            _candidate("c", probability=0.4),
        )
        outcome = run_decision_layer(pool, verification_budget=4)
        self.assertEqual(outcome.exploration_requests_spent, 0)
        self.assertEqual(outcome.information_gains, ())
        self.assertEqual(outcome.initial_candidates, 3)
        self.assertLessEqual(outcome.selection.spent_cost, 4)

    def test_scored_output_is_ordered_by_probability(self) -> None:
        pool = (
            _candidate("low", probability=0.2),
            _candidate("high", probability=0.9),
            _candidate("mid", probability=0.5),
        )
        outcome = run_decision_layer(pool, verification_budget=6)
        self.assertEqual(
            [item.candidate_id for item in outcome.scored],
            ["high", "mid", "low"],
        )

    def test_total_requests_counts_both_phases(self) -> None:
        pool = (_candidate("a", probability=0.5, cost=3),)
        outcome = run_decision_layer(
            pool,
            verification_budget=3,
            exploration_budget=2,
            probe_options=(_option("p1", "a"),),
            observe=lambda option: True,
        )
        self.assertEqual(
            outcome.total_requests_spent,
            outcome.exploration_requests_spent + outcome.selection.spent_cost,
        )


class ExplorationTests(unittest.TestCase):
    def test_a_positive_observation_raises_the_posterior(self) -> None:
        pool = (_candidate("a", probability=0.3),)
        outcome = run_decision_layer(
            pool,
            verification_budget=2,
            exploration_budget=1,
            probe_options=(_option("p1", "a"),),
            observe=lambda option: True,
        )
        self.assertEqual(outcome.exploration_requests_spent, 1)
        self.assertGreater(float(outcome.scored[0].probability), 0.3)

    def test_a_negative_observation_lowers_the_posterior(self) -> None:
        pool = (_candidate("a", probability=0.7),)
        outcome = run_decision_layer(
            pool,
            verification_budget=2,
            exploration_budget=1,
            probe_options=(_option("p1", "a"),),
            observe=lambda option: False,
        )
        self.assertLess(float(outcome.scored[0].probability), 0.7)

    def test_exploration_never_exceeds_its_budget(self) -> None:
        pool = tuple(
            _candidate(f"c{index}", probability=0.5) for index in range(6)
        )
        options = tuple(
            _option(f"p{index}", f"c{index}", cost=2) for index in range(6)
        )
        outcome = run_decision_layer(
            pool,
            verification_budget=4,
            exploration_budget=5,
            probe_options=options,
            observe=lambda option: True,
        )
        self.assertLessEqual(outcome.exploration_requests_spent, 5)
        self.assertEqual(outcome.exploration_requests_spent, 4)

    def test_each_probe_runs_at_most_once(self) -> None:
        seen: list[str] = []

        def observe(option: ProbeOption) -> bool:
            seen.append(option.probe_id)
            return True

        pool = (_candidate("a", probability=0.5),)
        run_decision_layer(
            pool,
            verification_budget=2,
            exploration_budget=10,
            probe_options=(
                _option("p1", "a"),
                _option("p2", "a"),
            ),
            observe=observe,
        )
        self.assertEqual(sorted(seen), ["p1", "p2"])

    def test_exploration_prefers_the_most_uncertain_candidate(self) -> None:
        """The first request should go where it teaches the most."""

        seen: list[str] = []

        def observe(option: ProbeOption) -> bool:
            seen.append(option.candidate_id)
            return True

        pool = (
            _candidate("certain", probability=0.97),
            _candidate("unsure", probability=0.50),
        )
        run_decision_layer(
            pool,
            verification_budget=2,
            exploration_budget=1,
            probe_options=(
                _option("p_certain", "certain"),
                _option("p_unsure", "unsure"),
            ),
            observe=observe,
        )
        self.assertEqual(seen, ["unsure"])

    def test_uninformative_probes_are_never_run(self) -> None:
        seen: list[str] = []

        def observe(option: ProbeOption) -> bool:
            seen.append(option.probe_id)
            return True

        pool = (_candidate("a", probability=0.5),)
        outcome = run_decision_layer(
            pool,
            verification_budget=2,
            exploration_budget=5,
            probe_options=(_option("useless", "a", tpr=0.5, fpr=0.5),),
            observe=observe,
        )
        self.assertEqual(seen, [])
        self.assertEqual(outcome.exploration_requests_spent, 0)

    def test_exploration_changes_what_gets_verified(self) -> None:
        """The point of sequencing: an early result reorders the commit."""

        pool = (
            _candidate("a", probability=0.55, cost=2),
            _candidate("b", probability=0.50, cost=2),
        )
        without = run_decision_layer(pool, verification_budget=2)
        with_probe = run_decision_layer(
            pool,
            verification_budget=2,
            exploration_budget=1,
            probe_options=(_option("p_a", "a", tpr=0.9, fpr=0.05),),
            observe=lambda option: False,
        )
        self.assertEqual(
            [item.candidate_id for item in without.selection.selected], ["a"]
        )
        self.assertEqual(
            [item.candidate_id for item in with_probe.selection.selected], ["b"]
        )

    def test_probes_without_an_observer_are_rejected(self) -> None:
        pool = (_candidate("a", probability=0.5),)
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer(
                pool,
                verification_budget=2,
                exploration_budget=1,
                probe_options=(_option("p1", "a"),),
            )

    def test_probe_for_an_unknown_candidate_is_rejected(self) -> None:
        pool = (_candidate("a", probability=0.5),)
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer(
                pool,
                verification_budget=2,
                exploration_budget=1,
                probe_options=(_option("p1", "ghost"),),
                observe=lambda option: True,
            )

    def test_non_bool_observation_is_rejected(self) -> None:
        pool = (_candidate("a", probability=0.5),)
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer(
                pool,
                verification_budget=2,
                exploration_budget=1,
                probe_options=(_option("p1", "a"),),
                observe=lambda option: "yes",
            )


class ConformalIntegrationTests(unittest.TestCase):
    def _threshold(self, target_risk: float):
        groups = tuple(
            ConformalCalibrationGroup(
                group_id=f"app{index}",
                items=(
                    ConformalCalibrationItem(f"app{index}_p", 0.85, True),
                    ConformalCalibrationItem(f"app{index}_q", 0.65, True),
                    ConformalCalibrationItem(f"app{index}_r", 0.20, False),
                ),
            )
            for index in range(20)
        )
        return calibrate_conformal_threshold(groups, target_risk=target_risk)

    def test_threshold_trims_the_verification_set(self) -> None:
        threshold = self._threshold(0.2)
        pool = (
            _candidate("high", probability=0.9, cost=1),
            _candidate("low", probability=0.05, cost=1),
        )
        outcome = run_decision_layer(
            pool,
            verification_budget=10,
            conformal=threshold,
        )
        self.assertEqual(outcome.initial_candidates, 2)
        self.assertEqual(outcome.conformal_set_size, 1)
        self.assertEqual(
            [item.candidate_id for item in outcome.selection.selected], ["high"]
        )

    def test_budget_shortfall_against_the_guarantee_is_reported(self) -> None:
        threshold = self._threshold(0.2)
        pool = tuple(
            _candidate(f"c{index}", probability=0.9, cost=5, group=f"g{index}")
            for index in range(5)
        )
        outcome = run_decision_layer(
            pool,
            verification_budget=5,
            conformal=threshold,
        )
        self.assertEqual(outcome.conformal_set_size, 5)
        self.assertFalse(outcome.budget_covers_conformal_set)
        self.assertLessEqual(outcome.selection.spent_cost, 5)

    def test_sufficient_budget_covers_the_guarantee(self) -> None:
        threshold = self._threshold(0.2)
        pool = (_candidate("c0", probability=0.9, cost=2),)
        outcome = run_decision_layer(
            pool,
            verification_budget=10,
            conformal=threshold,
        )
        self.assertTrue(outcome.budget_covers_conformal_set)


class ValidationTests(unittest.TestCase):
    def test_duplicate_candidates_are_rejected(self) -> None:
        pool = (
            _candidate("same", probability=0.5),
            _candidate("same", probability=0.6),
        )
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer(pool, verification_budget=4)

    def test_negative_budget_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((), verification_budget=-1)

    def test_boolean_budget_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((), verification_budget=True)

    def test_wrong_conformal_type_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyRunError):
            run_decision_layer((), verification_budget=2, conformal=object())

    def test_selection_never_introduces_an_unscored_candidate(self) -> None:
        pool = tuple(
            _candidate(f"c{index}", probability=0.5, cost=1) for index in range(5)
        )
        outcome = run_decision_layer(pool, verification_budget=3)
        scored = {item.candidate_id for item in outcome.scored}
        for item in outcome.selection.selected:
            self.assertIn(item.candidate_id, scored)


class PolicyObjectTests(unittest.TestCase):
    def test_default_costs_and_severities_cover_every_family(self) -> None:
        costs = VerificationCostPolicy()
        severities = SeverityPolicy()
        for family in ("SQLI", "REFLECTED_XSS", "BROKEN_ACCESS_CONTROL"):
            self.assertEqual(costs.cost_for(family), DEFAULT_FAMILY_COSTS[family])
            self.assertEqual(
                severities.severity_for(family), DEFAULT_FAMILY_SEVERITY[family]
            )

    def test_unknown_family_falls_back_to_the_default(self) -> None:
        self.assertEqual(VerificationCostPolicy().cost_for("CSRF"), 4)
        self.assertEqual(SeverityPolicy().severity_for("CSRF"), 5.0)

    def test_non_positive_cost_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyError):
            VerificationCostPolicy(family_costs={"SQLI": 0})

    def test_non_positive_severity_is_rejected(self) -> None:
        with self.assertRaises(DecisionPolicyError):
            SeverityPolicy(family_severity={"SQLI": -1.0})


class SelectionContractIntegrationTests(unittest.TestCase):
    """End to end from the real selection handoff into the decision layer."""

    def _feature_vector(self, input_point_id: str, **values: float) -> FeatureVector:
        defaults = {
            STATUS_CODE_CHANGED: 0.0,
            RESPONSE_LENGTH_DIFF_RATIO: 0.0,
            MARKER_REFLECTED: 0.0,
            SQL_ERROR_PATTERN: 0.0,
        }
        defaults.update(values)
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=("pair_1",),
            features={
                name: FeatureObservation(
                    name=name,
                    value=value,
                    observed=True,
                    source="unit-test",
                    extractor_version="unit-v1",
                )
                for name, value in defaults.items()
            },
            feature_schema_version="feature-v0.1",
        )

    def test_handoff_contexts_become_decision_candidates(self) -> None:
        strong = self._feature_vector(
            "ip_strong",
            **{
                STATUS_CODE_CHANGED: 1.0,
                SQL_ERROR_PATTERN: 1.0,
                RESPONSE_LENGTH_DIFF_RATIO: 0.8,
            },
        )
        weak = self._feature_vector(
            "ip_weak", **{RESPONSE_LENGTH_DIFF_RATIO: 0.1}
        )
        results = [
            SQLiScorer().score(strong),
            XSSScorer().score(strong),
            SQLiScorer().score(weak),
            XSSScorer().score(weak),
        ]
        injection = select_top_k(results, k=4)
        access = select_top_k_access((), k=4)
        combined = select_combined_top_k(injection, access, k=4)
        handoff = build_mutation_handoff(combined, selection_run_id="run_1")

        scorers = {
            family: CalibratedScorer.from_prior(heuristic_prior_for_family(family))
            for family in ("SQLI", "REFLECTED_XSS")
        }
        candidates = []
        for context in handoff.contexts:
            source = strong if "strong" in context.candidate_subject_ref else weak
            candidates.append(
                decision_candidate_from_context(
                    context,
                    scorers[context.family].probability(source.features),
                )
            )

        self.assertEqual(len(candidates), len(handoff.contexts))
        for candidate, context in zip(candidates, handoff.contexts):
            self.assertEqual(candidate.candidate_id, context.candidate_id)
            self.assertEqual(candidate.selection_rank, context.rank)
            self.assertEqual(
                candidate.verification_cost,
                DEFAULT_FAMILY_COSTS[context.family],
            )

        outcome = run_decision_layer(tuple(candidates), verification_budget=9)
        self.assertLessEqual(outcome.selection.spent_cost, 9)
        selected = {item.candidate_id for item in outcome.selection.selected}
        self.assertTrue(selected)
        self.assertTrue(
            selected <= {context.candidate_id for context in handoff.contexts}
        )

    def test_family_mismatch_between_score_and_context_is_rejected(self) -> None:
        vector = self._feature_vector("ip_1", **{SQL_ERROR_PATTERN: 1.0})
        injection = select_top_k([SQLiScorer().score(vector)], k=1)
        combined = select_combined_top_k(injection, select_top_k_access((), k=1), k=1)
        handoff = build_mutation_handoff(combined, selection_run_id="run_1")

        xss_probability = CalibratedScorer.from_prior(
            heuristic_prior_for_family("REFLECTED_XSS")
        ).probability(vector.features)
        self.assertEqual(handoff.contexts[0].family, "SQLI")
        with self.assertRaises(DecisionCandidateError):
            decision_candidate_from_context(handoff.contexts[0], xss_probability)


if __name__ == "__main__":
    unittest.main()
