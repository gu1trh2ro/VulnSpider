from __future__ import annotations

import unittest

from vulnspider.domain import (
    AccessCandidate,
    AccessCheckKind,
    AccessPlanningError,
    AccessProbePlan,
    AccessScoreEvidence,
    AccessScoringResult,
    AccessSubjectContext,
    HttpMethod,
    RequestInstance,
)


class AccessProbePlanTests(unittest.TestCase):
    def _requests(self) -> tuple[RequestInstance, RequestInstance]:
        reference = RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1/account",
            cookies={"session": "abc"},
        )
        comparison = RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1/account",
        )
        return reference, comparison

    def test_plan_requires_get_requests(self) -> None:
        reference, comparison = self._requests()
        post_reference = RequestInstance(method=HttpMethod.POST, url=reference.url)
        with self.assertRaisesRegex(AccessPlanningError, "GET"):
            AccessProbePlan(
                endpoint_id="ep",
                endpoint_fingerprint="fp",
                request_template_id="rt",
                check_kind=AccessCheckKind.CREDENTIAL_STRIP,
                reference_request=post_reference,
                comparison_request=comparison,
                reference_subject=AccessSubjectContext.ORIGINAL,
                comparison_subject=AccessSubjectContext.ANONYMOUS,
                changed_aspect="credentials",
            )

    def test_plan_identity_is_deterministic_and_distinguishes_check_kind(self) -> None:
        reference, comparison = self._requests()
        first = AccessProbePlan(
            endpoint_id="ep",
            endpoint_fingerprint="fp",
            request_template_id="rt",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            reference_request=reference,
            comparison_request=comparison,
            reference_subject=AccessSubjectContext.ORIGINAL,
            comparison_subject=AccessSubjectContext.ANONYMOUS,
            changed_aspect="credentials",
        )
        again = AccessProbePlan(
            endpoint_id="ep",
            endpoint_fingerprint="fp",
            request_template_id="rt",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            reference_request=reference,
            comparison_request=comparison,
            reference_subject=AccessSubjectContext.ORIGINAL,
            comparison_subject=AccessSubjectContext.ANONYMOUS,
            changed_aspect="credentials",
        )
        different_kind = AccessProbePlan(
            endpoint_id="ep",
            endpoint_fingerprint="fp",
            request_template_id="rt",
            check_kind=AccessCheckKind.IDENTIFIER_SUBSTITUTION,
            reference_request=reference,
            comparison_request=comparison,
            reference_subject=AccessSubjectContext.ORIGINAL,
            comparison_subject=AccessSubjectContext.ORIGINAL,
            changed_aspect="query.id",
            input_point_id="inp_1",
        )
        self.assertEqual(first.id, again.id)
        self.assertNotEqual(first.id, different_kind.id)
        self.assertTrue((first.id or "").startswith("accplan_"))

    def test_plan_rejects_empty_required_fields(self) -> None:
        reference, comparison = self._requests()
        with self.assertRaisesRegex(AccessPlanningError, "endpoint_id"):
            AccessProbePlan(
                endpoint_id="",
                endpoint_fingerprint="fp",
                request_template_id="rt",
                check_kind=AccessCheckKind.CREDENTIAL_STRIP,
                reference_request=reference,
                comparison_request=comparison,
                reference_subject=AccessSubjectContext.ORIGINAL,
                comparison_subject=AccessSubjectContext.ANONYMOUS,
                changed_aspect="credentials",
            )


class AccessCandidateTests(unittest.TestCase):
    def test_identity_ignores_rank_score_but_includes_resource_reference(self) -> None:
        without_score = AccessCandidate(
            endpoint_id="ep",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            subject_context=AccessSubjectContext.ANONYMOUS,
            resource_reference="GET /account",
            resource_owner_context="original session",
            access_probe_plan_id="accplan_1",
        )
        with_score = AccessCandidate(
            endpoint_id="ep",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            subject_context=AccessSubjectContext.ANONYMOUS,
            resource_reference="GET /account",
            resource_owner_context="original session",
            access_probe_plan_id="accplan_1",
            rank_score=75.0,
            scorer_version="access-control-weighted-v1",
        )
        different_resource = AccessCandidate(
            endpoint_id="ep",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            subject_context=AccessSubjectContext.ANONYMOUS,
            resource_reference="GET /admin",
            resource_owner_context="original session",
            access_probe_plan_id="accplan_1",
        )
        self.assertEqual(without_score.id, with_score.id)
        self.assertNotEqual(without_score.id, different_resource.id)
        self.assertTrue((without_score.id or "").startswith("acand_"))

    def test_rejects_empty_resource_reference(self) -> None:
        with self.assertRaisesRegex(AccessPlanningError, "resource_reference"):
            AccessCandidate(
                endpoint_id="ep",
                check_kind=AccessCheckKind.CREDENTIAL_STRIP,
                subject_context=AccessSubjectContext.ANONYMOUS,
                resource_reference="",
                resource_owner_context="original session",
                access_probe_plan_id="accplan_1",
            )


class AccessScoreEvidenceTests(unittest.TestCase):
    def test_observed_evidence_requires_value_and_contribution(self) -> None:
        with self.assertRaisesRegex(AccessPlanningError, "observed access score evidence"):
            AccessScoreEvidence(
                candidate_id="acand_1",
                access_probe_plan_id="accplan_1",
                feature_name="access_unauthorized_success",
                feature_value=None,
                weight=55.0,
                contribution=None,
                reason="x",
                observed=True,
            )

    def test_unobserved_evidence_must_not_fabricate_a_value(self) -> None:
        with self.assertRaisesRegex(AccessPlanningError, "unavailable access score evidence"):
            AccessScoreEvidence(
                candidate_id="acand_1",
                access_probe_plan_id="accplan_1",
                feature_name="access_unauthorized_success",
                feature_value=1.0,
                weight=55.0,
                contribution=55.0,
                reason="x",
                observed=False,
            )


class AccessScoringResultOwnershipTests(unittest.TestCase):
    def _plan(self) -> AccessProbePlan:
        return AccessProbePlan(
            endpoint_id="ep",
            endpoint_fingerprint="fp",
            request_template_id="rt",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            reference_request=RequestInstance(
                method=HttpMethod.GET,
                url="http://127.0.0.1/account",
                cookies={"session": "abc"},
            ),
            comparison_request=RequestInstance(
                method=HttpMethod.GET, url="http://127.0.0.1/account"
            ),
            reference_subject=AccessSubjectContext.ORIGINAL,
            comparison_subject=AccessSubjectContext.ANONYMOUS,
            changed_aspect="credentials",
        )

    def test_direct_construction_is_closed(self) -> None:
        with self.assertRaisesRegex(TypeError, "from_objects"):
            AccessScoringResult(
                access_probe_plan_id="accplan_1",
                candidate=object(),
                evidence=(),
            )

    def test_from_objects_rejects_candidate_ownership_mismatch(self) -> None:
        plan = self._plan()
        other_plan_candidate = AccessCandidate(
            endpoint_id="ep",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            subject_context=AccessSubjectContext.ANONYMOUS,
            resource_reference="GET /account",
            resource_owner_context="original session",
            access_probe_plan_id="accplan_other",
        )
        with self.assertRaisesRegex(AccessPlanningError, "ownership mismatch"):
            AccessScoringResult.from_objects(plan, other_plan_candidate, ())

    def test_from_objects_rejects_evidence_check_kind_mismatch(self) -> None:
        plan = self._plan()
        candidate = AccessCandidate(
            endpoint_id="ep",
            check_kind=AccessCheckKind.CREDENTIAL_STRIP,
            subject_context=AccessSubjectContext.ANONYMOUS,
            resource_reference="GET /account",
            resource_owner_context="original session",
            access_probe_plan_id=plan.id or "",
        )
        wrong_kind_evidence = AccessScoreEvidence(
            candidate_id=candidate.id or "",
            access_probe_plan_id=plan.id or "",
            feature_name="access_unauthorized_success",
            feature_value=1.0,
            weight=55.0,
            contribution=55.0,
            reason="x",
            observed=True,
            check_kind=AccessCheckKind.IDENTIFIER_SUBSTITUTION,
        )
        with self.assertRaisesRegex(AccessPlanningError, "check_kind mismatch"):
            AccessScoringResult.from_objects(plan, candidate, (wrong_kind_evidence,))


if __name__ == "__main__":
    unittest.main()
