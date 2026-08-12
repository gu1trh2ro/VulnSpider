"""Value of information: which probe to spend the next request on.

The pipeline today is one-shot -- one baseline, one probe, score, rank, stop.
Nothing that comes back from the first probe changes what is asked next, so
"selective verification" currently selects but does not adapt.

This module supplies the missing step. For a candidate currently believed
vulnerable with probability ``p``, and a probe whose outcome has known
class-conditional rates, the expected reduction in uncertainty is

``EIG = H(p) − [ P(o) · H(p | o) + P(¬o) · H(p | ¬o) ]``

in bits, with ``H`` the binary entropy. Probes are then ordered by
``EIG / cost``: information per request, not information alone, because a
probe that halves the uncertainty is worth little if it costs six requests and
a cheaper one gets most of the way for one.

Where the rates come from
-------------------------
``true_positive_rate`` and ``false_positive_rate`` are exactly the
class-conditional feature rates :func:`~vulnspider.scoring.calibration.
fit_naive_bayes_llr` estimates. That is the concrete join between the two
layers: the calibration model is not only what ranks candidates, it is also
what predicts what a probe will reveal. :func:`probe_options_from_rates` does
the conversion.

Two properties worth knowing, both tested:

* ``EIG`` is never negative -- information cannot be expected to hurt, so a
  probe is never worth skipping for fear of what it might say.
* ``EIG`` is zero exactly when ``tpr == fpr``. A probe whose outcome does not
  depend on the underlying state is worth no requests at all, however strong
  its signal looks.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite, log2

from vulnspider.scoring.calibration import NaiveBayesRates

INFORMATION_GAIN_VERSION = "expected-information-gain-v1"


class InformationGainError(ValueError):
    """Raised when an information gain cannot be computed as stated."""


@dataclass(frozen=True, slots=True)
class ProbeOption:
    """One probe that could be run, and what its outcome would mean."""

    probe_id: str
    candidate_id: str
    feature_name: str
    true_positive_rate: float
    false_positive_rate: float
    request_cost: int = 1

    def __post_init__(self) -> None:
        if not self.probe_id:
            raise InformationGainError("probe_id must not be empty")
        if not self.candidate_id:
            raise InformationGainError("candidate_id must not be empty")
        if not self.feature_name:
            raise InformationGainError("feature_name must not be empty")
        for name, rate in (
            ("true_positive_rate", self.true_positive_rate),
            ("false_positive_rate", self.false_positive_rate),
        ):
            if isinstance(rate, bool) or not isinstance(rate, int | float):
                raise InformationGainError(f"{name} must be numeric")
            if not isfinite(float(rate)) or not 0.0 < float(rate) < 1.0:
                raise InformationGainError(
                    f"{name} must lie strictly inside (0, 1)"
                )
        if isinstance(self.request_cost, bool) or not isinstance(
            self.request_cost, int
        ):
            raise InformationGainError("request_cost must be an integer")
        if self.request_cost <= 0:
            raise InformationGainError("request_cost must be positive")


@dataclass(frozen=True, slots=True, init=False)
class ProbeInformationGain:
    """What one probe is expected to teach, per request spent."""

    method_version: str
    probe_id: str
    candidate_id: str
    prior_probability: float
    probability_of_observation: float
    posterior_if_observed: float
    posterior_if_absent: float
    expected_information_gain: float
    information_density: float
    request_cost: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ProbeInformationGain is produced only by evaluate_probe()")

    @classmethod
    def _from_parts(
        cls,
        *,
        probe_id: str,
        candidate_id: str,
        prior_probability: float,
        probability_of_observation: float,
        posterior_if_observed: float,
        posterior_if_absent: float,
        expected_information_gain: float,
        request_cost: int,
    ) -> ProbeInformationGain:
        instance = object.__new__(cls)
        object.__setattr__(instance, "method_version", INFORMATION_GAIN_VERSION)
        object.__setattr__(instance, "probe_id", probe_id)
        object.__setattr__(instance, "candidate_id", candidate_id)
        object.__setattr__(instance, "prior_probability", prior_probability)
        object.__setattr__(
            instance, "probability_of_observation", probability_of_observation
        )
        object.__setattr__(instance, "posterior_if_observed", posterior_if_observed)
        object.__setattr__(instance, "posterior_if_absent", posterior_if_absent)
        object.__setattr__(
            instance, "expected_information_gain", expected_information_gain
        )
        object.__setattr__(
            instance,
            "information_density",
            expected_information_gain / request_cost,
        )
        object.__setattr__(instance, "request_cost", request_cost)
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.expected_information_gain < -1e-12:
            raise InformationGainError(
                "expected information gain must not be negative"
            )
        for name, value in (
            ("prior_probability", self.prior_probability),
            ("probability_of_observation", self.probability_of_observation),
            ("posterior_if_observed", self.posterior_if_observed),
            ("posterior_if_absent", self.posterior_if_absent),
        ):
            if not 0.0 < value < 1.0:
                raise InformationGainError(
                    f"{name} must lie strictly inside (0, 1)"
                )
        blended = (
            self.probability_of_observation * self.posterior_if_observed
            + (1.0 - self.probability_of_observation) * self.posterior_if_absent
        )
        if abs(blended - self.prior_probability) > 1e-9:
            raise InformationGainError(
                "expected posterior must average back to the prior"
            )


def binary_entropy(probability: float) -> float:
    """Shannon entropy of a Bernoulli variable, in bits."""

    if not isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise InformationGainError("probability must lie inside [0, 1]")
    if probability <= 0.0 or probability >= 1.0:
        return 0.0
    return -(
        probability * log2(probability)
        + (1.0 - probability) * log2(1.0 - probability)
    )


def posterior_after_observation(
    prior: float,
    *,
    true_positive_rate: float,
    false_positive_rate: float,
    observed: bool,
) -> float:
    """Bayes update of ``prior`` given one probe outcome."""

    if not 0.0 < prior < 1.0:
        raise InformationGainError("prior must lie strictly inside (0, 1)")
    if observed:
        positive = prior * true_positive_rate
        negative = (1.0 - prior) * false_positive_rate
    else:
        positive = prior * (1.0 - true_positive_rate)
        negative = (1.0 - prior) * (1.0 - false_positive_rate)
    total = positive + negative
    if total <= 0.0:
        raise InformationGainError("observation has zero predictive probability")
    return positive / total


def evaluate_probe(prior: float, option: ProbeOption) -> ProbeInformationGain:
    """Expected information gain, and gain per request, for one probe."""

    if not isinstance(option, ProbeOption):
        raise InformationGainError("option must be a ProbeOption")
    if not 0.0 < prior < 1.0:
        raise InformationGainError("prior must lie strictly inside (0, 1)")

    observation_probability = (
        prior * option.true_positive_rate
        + (1.0 - prior) * option.false_positive_rate
    )
    posterior_observed = posterior_after_observation(
        prior,
        true_positive_rate=option.true_positive_rate,
        false_positive_rate=option.false_positive_rate,
        observed=True,
    )
    posterior_absent = posterior_after_observation(
        prior,
        true_positive_rate=option.true_positive_rate,
        false_positive_rate=option.false_positive_rate,
        observed=False,
    )
    expected_posterior_entropy = (
        observation_probability * binary_entropy(posterior_observed)
        + (1.0 - observation_probability) * binary_entropy(posterior_absent)
    )
    gain = binary_entropy(prior) - expected_posterior_entropy
    return ProbeInformationGain._from_parts(
        probe_id=option.probe_id,
        candidate_id=option.candidate_id,
        prior_probability=prior,
        probability_of_observation=observation_probability,
        posterior_if_observed=posterior_observed,
        posterior_if_absent=posterior_absent,
        expected_information_gain=max(gain, 0.0),
        request_cost=option.request_cost,
    )


def rank_probes_by_information_density(
    priors: dict[str, float],
    options: Sequence[ProbeOption],
) -> tuple[ProbeInformationGain, ...]:
    """Order the available probes by expected bits learned per request."""

    evaluated: list[ProbeInformationGain] = []
    for option in options:
        prior = priors.get(option.candidate_id)
        if prior is None:
            raise InformationGainError(
                f"no prior probability for candidate {option.candidate_id!r}"
            )
        evaluated.append(evaluate_probe(prior, option))
    return tuple(
        sorted(
            evaluated,
            key=lambda item: (-item.information_density, item.probe_id),
        )
    )


def probe_options_from_rates(
    rates: NaiveBayesRates,
    *,
    candidate_id: str,
    request_cost: int = 1,
    probe_id_prefix: str = "probe",
) -> tuple[ProbeOption, ...]:
    """Turn learned class-conditional rates into runnable probe options.

    This is the Layer 1 to Layer 2 bridge: whatever the calibration corpus
    taught about how often each feature fires on vulnerable versus safe input
    points is exactly what predicts the value of measuring it again.
    """

    if not isinstance(rates, NaiveBayesRates):
        raise InformationGainError("rates must be a NaiveBayesRates")
    if not candidate_id:
        raise InformationGainError("candidate_id must not be empty")
    return tuple(
        ProbeOption(
            probe_id=f"{probe_id_prefix}:{candidate_id}:{feature_name}",
            candidate_id=candidate_id,
            feature_name=feature_name,
            true_positive_rate=rates.rates_for(feature_name)[0],
            false_positive_rate=rates.rates_for(feature_name)[1],
            request_cost=request_cost,
        )
        for feature_name in rates.feature_space.feature_names
    )
