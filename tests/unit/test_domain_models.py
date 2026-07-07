from __future__ import annotations

import unittest

from spiderman.domain import (
    Endpoint,
    FeatureObservation,
    HttpMethod,
    InputLocation,
    InputPoint,
    ProbeFamily,
    ProbePlan,
    RequestInstance,
    VulnerabilityCandidate,
    VulnerabilityType,
)


class DomainModelTests(unittest.TestCase):
    def test_endpoint_identity_ignores_query_values(self) -> None:
        first = Endpoint(
            method=HttpMethod.GET,
            scheme="HTTP",
            host="Example.test",
            path="/search?q=book",
        )
        second = Endpoint(
            method=HttpMethod.GET,
            scheme="http",
            host="example.test",
            path="/search?q=chair&page=2",
        )
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.path, "/search")

    def test_two_parameters_on_same_endpoint_are_distinct_inputs(self) -> None:
        endpoint = Endpoint(
            method=HttpMethod.GET,
            scheme="http",
            host="127.0.0.1",
            path="/search",
        )
        q_input = InputPoint(
            endpoint_id=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="book",
        )
        page_input = InputPoint(
            endpoint_id=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="page",
            baseline_value="1",
        )
        self.assertNotEqual(q_input.fingerprint, page_input.fingerprint)

    def test_same_normalized_input_point_produces_same_fingerprint(self) -> None:
        first = InputPoint(
            endpoint_id="ep",
            location=InputLocation.QUERY,
            name=" Q ",
            baseline_value="book",
        )
        second = InputPoint(
            endpoint_id="ep",
            location=InputLocation.QUERY,
            name="q",
            baseline_value="other",
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_query_and_form_parameters_with_same_name_are_distinct(self) -> None:
        query = InputPoint(
            endpoint_id="ep",
            location=InputLocation.QUERY,
            name="id",
        )
        form = InputPoint(
            endpoint_id="ep",
            location=InputLocation.FORM,
            name="id",
        )
        self.assertNotEqual(query.fingerprint, form.fingerprint)

    def test_missing_feature_is_distinct_from_observed_zero(self) -> None:
        missing = FeatureObservation.missing(
            "marker_reflected",
            source="not_run",
            extractor_version="reflection-v1",
        )
        observed_zero = FeatureObservation(
            name="marker_reflected",
            value=0.0,
            observed=True,
            source="reflection_marker_probe",
            extractor_version="reflection-v1",
        )
        self.assertFalse(missing.observed)
        self.assertIsNone(missing.value)
        self.assertTrue(observed_zero.observed)
        self.assertEqual(observed_zero.value, 0.0)

    def test_candidate_identity_differs_by_vulnerability_type(self) -> None:
        sqli = VulnerabilityCandidate(
            input_point_id="inp",
            vulnerability_type=VulnerabilityType.SQLI,
        )
        xss = VulnerabilityCandidate(
            input_point_id="inp",
            vulnerability_type=VulnerabilityType.REFLECTED_XSS,
        )
        self.assertNotEqual(sqli.id, xss.id)

    def test_probe_plan_rejects_multi_field_mutation(self) -> None:
        baseline = RequestInstance(method=HttpMethod.GET, url="http://example.test/search")
        probe = RequestInstance(method=HttpMethod.GET, url="http://example.test/search")
        with self.assertRaises(ValueError):
            ProbePlan(
                input_point_id="inp",
                probe_family=ProbeFamily.REFLECTION_MARKER,
                baseline_request=baseline,
                probe_request=probe,
                changed_fields=("query.q", "query.page"),
            )


if __name__ == "__main__":
    unittest.main()

