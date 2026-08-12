from __future__ import annotations

import random
import unittest

from vulnspider.decision.voi import (
    InformationGainError,
    ProbeOption,
    binary_entropy,
    evaluate_probe,
    posterior_after_observation,
    probe_options_from_rates,
    rank_probes_by_information_density,
)
from vulnspider.scoring.calibration import (
    CalibrationFeatureSpace,
    TrainingSample,
    fit_naive_bayes_llr,
)


def _option(
    probe_id: str = "p1",
    *,
    candidate_id: str = "c1",
    tpr: float = 0.8,
    fpr: float = 0.1,
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


class EntropyTests(unittest.TestCase):
    def test_maximum_at_one_half(self) -> None:
        self.assertAlmostEqual(binary_entropy(0.5), 1.0)

    def test_certainty_carries_no_entropy(self) -> None:
        self.assertEqual(binary_entropy(0.0), 0.0)
        self.assertEqual(binary_entropy(1.0), 0.0)

    def test_symmetric(self) -> None:
        self.assertAlmostEqual(binary_entropy(0.3), binary_entropy(0.7))

    def test_out_of_range_is_rejected(self) -> None:
        with self.assertRaises(InformationGainError):
            binary_entropy(1.2)


class PosteriorTests(unittest.TestCase):
    def test_positive_observation_raises_belief(self) -> None:
        posterior = posterior_after_observation(
            0.5, true_positive_rate=0.9, false_positive_rate=0.1, observed=True
        )
        self.assertAlmostEqual(posterior, 0.9)

    def test_negative_observation_lowers_belief(self) -> None:
        posterior = posterior_after_observation(
            0.5, true_positive_rate=0.9, false_positive_rate=0.1, observed=False
        )
        self.assertAlmostEqual(posterior, 0.1)

    def test_uninformative_probe_moves_nothing(self) -> None:
        for observed in (True, False):
            self.assertAlmostEqual(
                posterior_after_observation(
                    0.42,
                    true_positive_rate=0.5,
                    false_positive_rate=0.5,
                    observed=observed,
                ),
                0.42,
            )

    def test_impossible_prior_is_rejected(self) -> None:
        with self.assertRaises(InformationGainError):
            posterior_after_observation(
                0.0, true_positive_rate=0.9, false_positive_rate=0.1, observed=True
            )


class InformationGainTests(unittest.TestCase):
    def test_gain_is_never_negative(self) -> None:
        generator = random.Random(31337)
        for _trial in range(500):
            prior = generator.uniform(0.01, 0.99)
            option = _option(
                tpr=generator.uniform(0.01, 0.99),
                fpr=generator.uniform(0.01, 0.99),
            )
            self.assertGreaterEqual(
                evaluate_probe(prior, option).expected_information_gain, 0.0
            )

    def test_gain_is_zero_exactly_when_the_probe_is_uninformative(self) -> None:
        uninformative = evaluate_probe(0.4, _option(tpr=0.5, fpr=0.5))
        self.assertAlmostEqual(uninformative.expected_information_gain, 0.0)
        informative = evaluate_probe(0.4, _option(tpr=0.9, fpr=0.05))
        self.assertGreater(informative.expected_information_gain, 0.0)

    def test_expected_posterior_averages_back_to_the_prior(self) -> None:
        generator = random.Random(17)
        for _trial in range(200):
            prior = generator.uniform(0.05, 0.95)
            gain = evaluate_probe(
                prior,
                _option(
                    tpr=generator.uniform(0.05, 0.95),
                    fpr=generator.uniform(0.05, 0.95),
                ),
            )
            blended = (
                gain.probability_of_observation * gain.posterior_if_observed
                + (1.0 - gain.probability_of_observation)
                * gain.posterior_if_absent
            )
            self.assertAlmostEqual(blended, prior, places=12)

    def test_maximum_uncertainty_yields_the_largest_gain(self) -> None:
        option = _option(tpr=0.9, fpr=0.1)
        at_half = evaluate_probe(0.5, option).expected_information_gain
        for prior in (0.05, 0.2, 0.8, 0.95):
            self.assertLess(
                evaluate_probe(prior, option).expected_information_gain, at_half
            )

    def test_a_sharper_probe_teaches_more(self) -> None:
        blunt = evaluate_probe(0.5, _option(tpr=0.6, fpr=0.4))
        sharp = evaluate_probe(0.5, _option(tpr=0.95, fpr=0.05))
        self.assertGreater(
            sharp.expected_information_gain, blunt.expected_information_gain
        )

    def test_density_divides_gain_by_cost(self) -> None:
        gain = evaluate_probe(0.5, _option(cost=4))
        self.assertAlmostEqual(
            gain.information_density, gain.expected_information_gain / 4.0
        )


class RankingTests(unittest.TestCase):
    def test_cheaper_probe_wins_at_equal_gain(self) -> None:
        ranked = rank_probes_by_information_density(
            {"c1": 0.5},
            (
                _option("expensive", cost=4),
                _option("cheap", cost=1),
            ),
        )
        self.assertEqual(ranked[0].probe_id, "cheap")

    def test_expensive_probe_can_still_win_on_density(self) -> None:
        ranked = rank_probes_by_information_density(
            {"c1": 0.5},
            (
                _option("weak_cheap", tpr=0.55, fpr=0.45, cost=1),
                _option("strong_pricey", tpr=0.99, fpr=0.01, cost=2),
            ),
        )
        self.assertEqual(ranked[0].probe_id, "strong_pricey")

    def test_missing_prior_is_rejected(self) -> None:
        with self.assertRaises(InformationGainError):
            rank_probes_by_information_density({}, (_option(),))

    def test_ranking_is_deterministic_under_ties(self) -> None:
        options = (
            _option("beta", candidate_id="c1"),
            _option("alpha", candidate_id="c1"),
        )
        ranked = rank_probes_by_information_density({"c1": 0.5}, options)
        self.assertEqual([item.probe_id for item in ranked], ["alpha", "beta"])


class OptionValidationTests(unittest.TestCase):
    def test_degenerate_rates_are_rejected(self) -> None:
        for tpr, fpr in ((0.0, 0.5), (1.0, 0.5), (0.5, 0.0), (0.5, 1.0)):
            with self.assertRaises(InformationGainError):
                _option(tpr=tpr, fpr=fpr)

    def test_zero_cost_is_rejected(self) -> None:
        with self.assertRaises(InformationGainError):
            _option(cost=0)


class CalibrationBridgeTests(unittest.TestCase):
    """The Layer 1 to Layer 2 join: learned rates become probe options."""

    def test_options_are_built_from_learned_rates(self) -> None:
        space = CalibrationFeatureSpace(
            "SQLI", ("status_code_changed", "sql_error_pattern")
        )
        samples = [
            TrainingSample(
                features={"status_code_changed": 0.0, "sql_error_pattern": 1.0},
                label=True,
            )
            for _index in range(25)
        ] + [
            TrainingSample(
                features={"status_code_changed": 1.0, "sql_error_pattern": 0.0},
                label=False,
            )
            for _index in range(25)
        ]
        rates = fit_naive_bayes_llr(samples, space)
        options = probe_options_from_rates(rates, candidate_id="c9", request_cost=2)

        self.assertEqual(len(options), 2)
        for option in options:
            self.assertEqual(option.candidate_id, "c9")
            self.assertEqual(option.request_cost, 2)
        sql_option = next(
            item for item in options if item.feature_name == "sql_error_pattern"
        )
        self.assertGreater(
            sql_option.true_positive_rate, sql_option.false_positive_rate
        )
        self.assertGreater(
            evaluate_probe(0.3, sql_option).expected_information_gain, 0.0
        )

    def test_bridge_rejects_a_non_model(self) -> None:
        with self.assertRaises(InformationGainError):
            probe_options_from_rates(object(), candidate_id="c1")


if __name__ == "__main__":
    unittest.main()
