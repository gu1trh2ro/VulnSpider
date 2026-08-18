from __future__ import annotations

import unittest

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import run_decision_layer
from vulnspider.domain import VulnerabilityType
from vulnspider.reporting.decision_html_report import render_decision_html_report
from vulnspider.verification import ResultStatus, VerificationSignal
from vulnspider.verification.focused import CandidateVerification


def _candidate(probability: float = 0.4) -> DecisionCandidate:
    return DecisionCandidate(
        candidate_id="cand_1",
        family="SQLI",
        probability=probability,
        selection_rank=1,
        subject_ref="inp_1",
        feature_vector_ref="fv_1",
    )


def _verification(
    prior: float,
    final: float,
    outcome: ResultStatus,
    signal: VerificationSignal,
) -> dict[str, CandidateVerification]:
    return {
        "cand_1": CandidateVerification(
            candidate_id="cand_1",
            input_point_id="inp_1",
            vulnerability_type=VulnerabilityType.SQLI,
            selection_rank=1,
            prior_probability=prior,
            final_outcome=outcome,
            final_signal=signal,
            final_confidence=final,
            results=(),
        )
    }


class VerificationReportTests(unittest.TestCase):
    def test_headline_uses_updated_confidence_when_verified(self) -> None:
        outcome = run_decision_layer((_candidate(0.4),), top_k=1)
        html = render_decision_html_report(
            outcome,
            verification=_verification(
                0.4, 0.7, ResultStatus.SUPPORTED, VerificationSignal.SUPPORT_NEW
            ),
        )
        # The final (verified) confidence is the headline; the prior is shown as
        # context, not as the lead number.
        self.assertIn('class="prio high">70%', html)
        self.assertIn("검증 결과", html)
        self.assertIn("검증 후 최종 신뢰도", html)
        self.assertIn("검증 전 40%", html)
        self.assertIn("검증으로 뒷받침됨", html)

    def test_weakened_lowers_the_headline(self) -> None:
        outcome = run_decision_layer((_candidate(0.6),), top_k=1)
        html = render_decision_html_report(
            outcome,
            verification=_verification(
                0.6, 0.3, ResultStatus.WEAKENED, VerificationSignal.WEAKEN
            ),
        )
        self.assertIn('class="prio low">30%', html)
        self.assertIn("검증으로 약화됨", html)

    def test_without_verification_headline_is_the_prior(self) -> None:
        outcome = run_decision_layer((_candidate(0.4),), top_k=1)
        html = render_decision_html_report(outcome)
        self.assertIn('class="prio', html)
        self.assertIn("40%", html)
        self.assertIn("취약 확률", html)
        self.assertNotIn("검증 결과", html)
        self.assertNotIn("검증 후 최종 신뢰도", html)


if __name__ == "__main__":
    unittest.main()
