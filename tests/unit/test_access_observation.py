from __future__ import annotations

import unittest
from dataclasses import dataclass, field

from vulnspider.access.executor import (
    AccessRequestExecutionError,
    execute_access_plan,
)
from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_UNAUTHORIZED_SUCCESS,
    extract_access_features,
)
from vulnspider.domain import (
    ACCESS_REQUEST_ROLE_COMPARISON,
    ACCESS_REQUEST_ROLE_REFERENCE,
    AccessCheckKind,
    AccessProbePlan,
    AccessSubjectContext,
    HttpMethod,
    RequestInstance,
    ResponseSnapshot,
)
from vulnspider.observation import TransportResponse


def _plan() -> AccessProbePlan:
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


@dataclass
class ScriptedTransport:
    responses: dict[str, TransportResponse]
    seen: list[RequestInstance] = field(default_factory=list)

    def send(self, request: RequestInstance, *, timeout_seconds: float) -> TransportResponse:
        self.seen.append(request)
        key = "cookie" if request.cookies else "no-cookie"
        return self.responses[key]


class ExecuteAccessPlanTests(unittest.TestCase):
    def test_executes_both_sides_with_correct_role_provenance(self) -> None:
        transport = ScriptedTransport(
            responses={
                "cookie": TransportResponse(status_code=200, body=b"secret", elapsed_ms=1.0),
                "no-cookie": TransportResponse(status_code=200, body=b"secret", elapsed_ms=1.0),
            }
        )
        plan = _plan()
        result = execute_access_plan(plan, transport=transport)
        self.assertEqual(len(transport.seen), 2)
        self.assertEqual(result.access_probe_plan_id, plan.id)
        self.assertEqual(result.reference_response.probe_plan_id, plan.id)
        self.assertEqual(result.reference_response.request_role, ACCESS_REQUEST_ROLE_REFERENCE)
        self.assertEqual(result.comparison_response.request_role, ACCESS_REQUEST_ROLE_COMPARISON)
        self.assertEqual(result.reference_response.request_id, plan.reference_request.id)
        self.assertEqual(result.comparison_response.request_id, plan.comparison_request.id)

    def test_rejects_non_plan_argument(self) -> None:
        with self.assertRaisesRegex(AccessRequestExecutionError, "AccessProbePlan"):
            execute_access_plan(object(), transport=ScriptedTransport(responses={}))  # type: ignore[arg-type]


class ExtractAccessFeaturesTests(unittest.TestCase):
    def _snapshot(
        self,
        *,
        status_code: int,
        body_length: int,
        execution_error: str | None = None,
    ) -> ResponseSnapshot:
        return ResponseSnapshot(
            request_id="req_1",
            status_code=status_code,
            elapsed_ms=1.0,
            body_bytes_hash="hash",
            body_length_bytes=body_length,
            execution_error=execution_error,
        )

    def test_missing_when_reference_did_not_succeed(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=403, body_length=10)
        comparison = self._snapshot(status_code=403, body_length=10)
        features = extract_access_features(plan, reference, comparison)
        for observation in features.values():
            self.assertFalse(observation.observed)
            self.assertIsNone(observation.value)

    def test_missing_when_reference_has_execution_error(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=0, body_length=0, execution_error="timeout")
        comparison = self._snapshot(status_code=200, body_length=10)
        features = extract_access_features(plan, reference, comparison)
        for observation in features.values():
            self.assertFalse(observation.observed)

    def test_unauthorized_success_is_one_when_comparison_also_succeeds(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=200, body_length=100)
        comparison = self._snapshot(status_code=200, body_length=95)
        features = extract_access_features(plan, reference, comparison)
        self.assertEqual(features[ACCESS_UNAUTHORIZED_SUCCESS].value, 1.0)
        self.assertTrue(features[ACCESS_UNAUTHORIZED_SUCCESS].observed)

    def test_unauthorized_success_is_zero_when_comparison_is_denied(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=200, body_length=100)
        comparison = self._snapshot(status_code=403, body_length=12)
        features = extract_access_features(plan, reference, comparison)
        self.assertEqual(features[ACCESS_UNAUTHORIZED_SUCCESS].value, 0.0)

    def test_body_size_similarity_ratio_formula(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=200, body_length=100)
        comparison = self._snapshot(status_code=200, body_length=80)
        features = extract_access_features(plan, reference, comparison)
        observation = features[ACCESS_BODY_SIZE_SIMILARITY_RATIO]
        self.assertTrue(observation.observed)
        self.assertAlmostEqual(observation.value, 0.8)

    def test_body_size_similarity_ratio_clips_at_zero(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=200, body_length=10)
        comparison = self._snapshot(status_code=200, body_length=10_000)
        features = extract_access_features(plan, reference, comparison)
        self.assertEqual(features[ACCESS_BODY_SIZE_SIMILARITY_RATIO].value, 0.0)

    def test_body_size_similarity_missing_when_comparison_execution_errors(self) -> None:
        plan = _plan()
        reference = self._snapshot(status_code=200, body_length=100)
        comparison = self._snapshot(status_code=0, body_length=0, execution_error="timeout")
        features = extract_access_features(plan, reference, comparison)
        self.assertFalse(features[ACCESS_BODY_SIZE_SIMILARITY_RATIO].observed)
        # unauthorized_success is still observed (and correctly 0) even though
        # the comparison side failed to execute at all.
        self.assertTrue(features[ACCESS_UNAUTHORIZED_SUCCESS].observed)
        self.assertEqual(features[ACCESS_UNAUTHORIZED_SUCCESS].value, 0.0)


if __name__ == "__main__":
    unittest.main()
