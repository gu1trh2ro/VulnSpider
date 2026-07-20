from __future__ import annotations

import unittest

from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_UNAUTHORIZED_SUCCESS,
)
from vulnspider.access.scoring import (
    ACCESS_MAX_RANK_SCORE,
    ACCESS_SCORER_VERSION,
    AccessScoringError,
    score_access_plan,
)
from vulnspider.domain import (
    AccessCheckKind,
    AccessProbePlan,
    AccessSubjectContext,
    FeatureObservation,
    HttpMethod,
    RequestInstance,
)


def _credential_strip_plan() -> AccessProbePlan:
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


def _identifier_plan() -> AccessProbePlan:
    return AccessProbePlan(
        endpoint_id="ep",
        endpoint_fingerprint="fp",
        request_template_id="rt",
        check_kind=AccessCheckKind.IDENTIFIER_SUBSTITUTION,
        reference_request=RequestInstance(
            method=HttpMethod.GET, url="http://127.0.0.1/product?id=1"
        ),
        comparison_request=RequestInstance(
            method=HttpMethod.GET, url="http://127.0.0.1/product?id=2"
        ),
        reference_subject=AccessSubjectContext.ORIGINAL,
        comparison_subject=AccessSubjectContext.ORIGINAL,
        changed_aspect="query.id",
        input_point_id="inp_1",
    )


def _observation(name: str, value: float) -> FeatureObservation:
    return FeatureObservation(
        name=name,
        value=value,
        observed=True,
        source="unit-test",
        extractor_version="unit-v1",
    )


def _missing(name: str) -> FeatureObservation:
    return FeatureObservation.missing(
        name, source="unit-test", extractor_version="unit-v1", details={"reason": "x"}
    )


class ScoreAccessPlanTests(unittest.TestCase):
    def test_full_signal_reaches_max_rank_score(self) -> None:
        plan = _credential_strip_plan()
        features = {
            ACCESS_UNAUTHORIZED_SUCCESS: _observation(ACCESS_UNAUTHORIZED_SUCCESS, 1.0),
            ACCESS_BODY_SIZE_SIMILARITY_RATIO: _observation(
                ACCESS_BODY_SIZE_SIMILARITY_RATIO, 1.0
            ),
        }
        result = score_access_plan(plan, features)
        self.assertEqual(result.candidate.rank_score, ACCESS_MAX_RANK_SCORE)
        self.assertEqual(result.candidate.scorer_version, ACCESS_SCORER_VERSION)
        self.assertEqual(ACCESS_MAX_RANK_SCORE, 75.0)

    def test_zero_signal_is_still_rankable_zero(self) -> None:
        plan = _credential_strip_plan()
        features = {
            ACCESS_UNAUTHORIZED_SUCCESS: _observation(ACCESS_UNAUTHORIZED_SUCCESS, 0.0),
            ACCESS_BODY_SIZE_SIMILARITY_RATIO: _observation(
                ACCESS_BODY_SIZE_SIMILARITY_RATIO, 0.0
            ),
        }
        result = score_access_plan(plan, features)
        self.assertEqual(result.candidate.rank_score, 0.0)
        self.assertTrue(all(item.observed for item in result.evidence))
        self.assertTrue(all(item.contribution == 0.0 for item in result.evidence))

    def test_missing_feature_produces_no_contribution_but_no_fabrication(self) -> None:
        plan = _credential_strip_plan()
        features = {
            ACCESS_UNAUTHORIZED_SUCCESS: _missing(ACCESS_UNAUTHORIZED_SUCCESS),
            ACCESS_BODY_SIZE_SIMILARITY_RATIO: _missing(ACCESS_BODY_SIZE_SIMILARITY_RATIO),
        }
        result = score_access_plan(plan, features)
        self.assertEqual(result.candidate.rank_score, 0.0)
        self.assertTrue(all(not item.observed for item in result.evidence))
        self.assertTrue(all(item.feature_value is None for item in result.evidence))
        self.assertTrue(all(item.contribution is None for item in result.evidence))

    def test_out_of_range_feature_value_is_rejected(self) -> None:
        plan = _credential_strip_plan()
        features = {
            ACCESS_UNAUTHORIZED_SUCCESS: _observation(ACCESS_UNAUTHORIZED_SUCCESS, 1.2),
            ACCESS_BODY_SIZE_SIMILARITY_RATIO: _observation(
                ACCESS_BODY_SIZE_SIMILARITY_RATIO, 0.0
            ),
        }
        with self.assertRaisesRegex(AccessScoringError, "between 0.0 and 1.0"):
            score_access_plan(plan, features)

    def test_resource_description_differs_by_check_kind(self) -> None:
        credential_result = score_access_plan(
            _credential_strip_plan(),
            {
                ACCESS_UNAUTHORIZED_SUCCESS: _observation(ACCESS_UNAUTHORIZED_SUCCESS, 1.0),
                ACCESS_BODY_SIZE_SIMILARITY_RATIO: _observation(
                    ACCESS_BODY_SIZE_SIMILARITY_RATIO, 1.0
                ),
            },
        )
        identifier_result = score_access_plan(
            _identifier_plan(),
            {
                ACCESS_UNAUTHORIZED_SUCCESS: _observation(ACCESS_UNAUTHORIZED_SUCCESS, 1.0),
                ACCESS_BODY_SIZE_SIMILARITY_RATIO: _observation(
                    ACCESS_BODY_SIZE_SIMILARITY_RATIO, 1.0
                ),
            },
        )
        self.assertEqual(credential_result.candidate.resource_reference, "GET /account")
        self.assertEqual(
            identifier_result.candidate.resource_reference, "query.id on GET /product"
        )
        self.assertNotEqual(
            credential_result.candidate.id, identifier_result.candidate.id
        )
        self.assertEqual(
            identifier_result.candidate.input_point_id, "inp_1"
        )
        self.assertIsNone(credential_result.candidate.input_point_id)

    def test_scoring_is_deterministic(self) -> None:
        plan = _credential_strip_plan()
        features = {
            ACCESS_UNAUTHORIZED_SUCCESS: _observation(ACCESS_UNAUTHORIZED_SUCCESS, 1.0),
            ACCESS_BODY_SIZE_SIMILARITY_RATIO: _observation(
                ACCESS_BODY_SIZE_SIMILARITY_RATIO, 0.5
            ),
        }
        first = score_access_plan(plan, features)
        second = score_access_plan(plan, features)
        self.assertEqual(first.candidate.id, second.candidate.id)
        self.assertEqual(first.candidate.rank_score, second.candidate.rank_score)
        self.assertEqual(first.candidate.rank_score, 65.0)


if __name__ == "__main__":
    unittest.main()
