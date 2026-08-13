"""Verification cost and severity policy for the decision layer.

The v0.1/v0.2 pipeline has no cost model: ``select_top_k()`` treats every
candidate as costing the same and being worth the same, which is why a fixed
``k`` was the only available control. A budget allocator needs both numbers, so
they are made explicit -- and versioned -- here rather than left implicit in a
ranking rule.

Both policies are *policy*, not measurement. The defaults are documented
starting points that the evaluation harness is expected to replace with
measured request counts and the project's own severity weighting.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from math import isfinite

VERIFICATION_COST_POLICY_VERSION = "verification-cost-v1"
SEVERITY_POLICY_VERSION = "severity-cvss-base-v1"

FAMILY_SQLI = "SQLI"
FAMILY_REFLECTED_XSS = "REFLECTED_XSS"
FAMILY_BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"

# Requests one focused verification attempt is expected to spend.
#
# SQLi is the most expensive: distinguishing a real injection from an
# incidental error page needs a boolean-true/boolean-false pair plus at least
# one syntax-error probe, and each is sent against the same baseline.
# Reflected XSS is cheapest: the reflection is already observed, so
# verification is a small number of context-specific encodings.
# BAC sits in between because every check runs the same request under two
# subject contexts (ADR-014).
DEFAULT_FAMILY_COSTS: dict[str, int] = {
    FAMILY_SQLI: 6,
    FAMILY_REFLECTED_XSS: 3,
    FAMILY_BROKEN_ACCESS_CONTROL: 4,
}

# Family order used to break ties between candidates of equal probability:
# SQLi first, then Reflected XSS, then BAC. Lower sorts first.
FAMILY_PRIORITY: dict[str, int] = {
    FAMILY_SQLI: 0,
    FAMILY_REFLECTED_XSS: 1,
    FAMILY_BROKEN_ACCESS_CONTROL: 2,
}
DEFAULT_FAMILY_PRIORITY = 99

# Relative severity of each class, tracking CVSS v3.1 base scores for the
# archetypal instance.
#
# This is **display metadata only**. It does not enter the ranking: "취약도"
# is the probability of being vulnerable, and severity only breaks ties -- and
# it breaks them through FAMILY_PRIORITY above, not by multiplication.
# Multiplying probability by severity would let a 0.5 SQLi outrank a 0.7 XSS,
# which is not what "the K most vulnerable input points" means.
DEFAULT_FAMILY_SEVERITY: dict[str, float] = {
    FAMILY_SQLI: 9.8,
    FAMILY_REFLECTED_XSS: 6.1,
    FAMILY_BROKEN_ACCESS_CONTROL: 8.1,
}


class DecisionPolicyError(ValueError):
    """Raised when a cost or severity policy is not usable as stated."""


@dataclass(frozen=True, slots=True)
class VerificationCostPolicy:
    """How many verification requests one candidate of each family costs."""

    family_costs: Mapping[str, int] = field(
        default_factory=lambda: dict(DEFAULT_FAMILY_COSTS)
    )
    default_cost: int = 4
    policy_version: str = VERIFICATION_COST_POLICY_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.default_cost, bool) or not isinstance(
            self.default_cost, int
        ):
            raise DecisionPolicyError("default_cost must be an integer")
        if self.default_cost <= 0:
            raise DecisionPolicyError("default_cost must be a positive integer")
        for family, cost in self.family_costs.items():
            if not family:
                raise DecisionPolicyError("family names must not be empty")
            if isinstance(cost, bool) or not isinstance(cost, int):
                raise DecisionPolicyError(f"cost for {family!r} must be an integer")
            if cost <= 0:
                raise DecisionPolicyError(f"cost for {family!r} must be positive")
        if not self.policy_version:
            raise DecisionPolicyError("policy_version must not be empty")

    def cost_for(self, family: str) -> int:
        """Requests to spend verifying one candidate of this family."""

        return self.family_costs.get(family, self.default_cost)


@dataclass(frozen=True, slots=True)
class SeverityPolicy:
    """Relative value of confirming one finding of each family."""

    family_severity: Mapping[str, float] = field(
        default_factory=lambda: dict(DEFAULT_FAMILY_SEVERITY)
    )
    default_severity: float = 5.0
    policy_version: str = SEVERITY_POLICY_VERSION

    def __post_init__(self) -> None:
        if not isfinite(self.default_severity) or self.default_severity <= 0.0:
            raise DecisionPolicyError("default_severity must be positive and finite")
        for family, severity in self.family_severity.items():
            if not family:
                raise DecisionPolicyError("family names must not be empty")
            if isinstance(severity, bool) or not isinstance(severity, int | float):
                raise DecisionPolicyError(
                    f"severity for {family!r} must be numeric"
                )
            if not isfinite(float(severity)) or float(severity) <= 0.0:
                raise DecisionPolicyError(
                    f"severity for {family!r} must be positive and finite"
                )
        if not self.policy_version:
            raise DecisionPolicyError("policy_version must not be empty")

    def severity_for(self, family: str) -> float:
        """Value of confirming one candidate of this family."""

        return float(self.family_severity.get(family, self.default_severity))
