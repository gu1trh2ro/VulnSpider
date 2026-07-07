from __future__ import annotations

import unittest

from spiderman.domain import (
    Endpoint,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ProbeFamily,
    ProbePlan,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
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
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="book",
        )
        page_input = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="page",
            baseline_value="1",
        )
        self.assertNotEqual(q_input.fingerprint, page_input.fingerprint)

    def test_same_normalized_input_point_produces_same_fingerprint(self) -> None:
        first = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name=" Q ",
            baseline_value="book",
        )
        second = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="q",
            baseline_value="other",
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_query_and_form_parameters_with_same_name_are_distinct(self) -> None:
        query = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="id",
        )
        form = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.FORM,
            name="id",
        )
        self.assertNotEqual(query.fingerprint, form.fingerprint)

    def test_same_parameter_name_on_different_endpoints_is_distinct(self) -> None:
        first = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        second = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/items")
        first_input = InputPoint(
            endpoint_id=first.id or "",
            endpoint_fingerprint=first.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        second_input = InputPoint(
            endpoint_id=second.id or "",
            endpoint_fingerprint=second.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        self.assertNotEqual(first_input.fingerprint, second_input.fingerprint)

    def test_same_parameter_name_under_different_methods_is_distinct(self) -> None:
        get_endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        post_endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/search")
        get_input = InputPoint(
            endpoint_id=get_endpoint.id or "",
            endpoint_fingerprint=get_endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        post_input = InputPoint(
            endpoint_id=post_endpoint.id or "",
            endpoint_fingerprint=post_endpoint.fingerprint,
            location=InputLocation.FORM,
            name="q",
        )
        self.assertNotEqual(get_input.fingerprint, post_input.fingerprint)

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

    def test_request_template_identity_is_deterministic_and_context_sensitive(self) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/update")
        first = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/update",
            form=(("email", "a@example.test"),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/profile:POST:/update",
        )
        equivalent = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/update",
            form=(("email", "a@example.test"),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/profile:POST:/update",
        )
        different_context = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/update",
            form=(("password", "secret"),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/security:POST:/update",
        )
        self.assertEqual(first.id, equivalent.id)
        self.assertNotEqual(first.id, different_context.id)

    def test_request_template_mapping_input_order_is_canonical(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        first = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            query={"q": "book", "page": "1"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="query",
        )
        second = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            query={"page": "1", "q": "book"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="query",
        )
        self.assertEqual(first.query, second.query)
        self.assertEqual(first.id, second.id)

    def test_input_point_request_context_identity_is_deterministic(self) -> None:
        first = InputPointRequestContext("inp_1", "rt_1")
        second = InputPointRequestContext("inp_1", "rt_1")
        different = InputPointRequestContext("inp_1", "rt_2")
        self.assertEqual(first.id, second.id)
        self.assertNotEqual(first.id, different.id)

    def test_feature_vector_identity_includes_probe_runs_and_observations(self) -> None:
        observed_zero = FeatureObservation(
            name="marker_reflected",
            value=0.0,
            observed=True,
            source="reflection_marker_probe",
            extractor_version="reflection-v1",
        )
        observed_one = FeatureObservation(
            name="marker_reflected",
            value=1.0,
            observed=True,
            source="reflection_marker_probe",
            extractor_version="reflection-v1",
        )
        first = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a", "probe-b"),
            features={"marker_reflected": observed_zero},
        )
        equivalent = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-b", "probe-a"),
            features={"marker_reflected": observed_zero},
        )
        different_value = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a", "probe-b"),
            features={"marker_reflected": observed_one},
        )
        different_probe = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-c",),
            features={"marker_reflected": observed_zero},
        )
        self.assertEqual(first.id, equivalent.id)
        self.assertNotEqual(first.id, different_value.id)
        self.assertNotEqual(first.id, different_probe.id)

    def test_feature_vector_feature_mapping_order_is_canonical(self) -> None:
        first = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "a": FeatureObservation("a", 1.0, True, "s", "v"),
                "b": FeatureObservation("b", 0.0, True, "s", "v"),
            },
        )
        second = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "b": FeatureObservation("b", 0.0, True, "s", "v"),
                "a": FeatureObservation("a", 1.0, True, "s", "v"),
            },
        )
        self.assertEqual(first.id, second.id)


if __name__ == "__main__":
    unittest.main()
