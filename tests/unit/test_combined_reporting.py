from __future__ import annotations

import json
import unittest

from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_UNAUTHORIZED_SUCCESS,
)
from vulnspider.access.scoring import score_access_plan
from vulnspider.access.selection import select_top_k_access
from vulnspider.domain import (
    AccessCheckKind,
    AccessProbePlan,
    AccessSubjectContext,
    Endpoint,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
    RequestInstance,
)
from vulnspider.features import MARKER_REFLECTED, RESPONSE_LENGTH_DIFF_RATIO
from vulnspider.reporting import (
    build_combined_json_report,
    render_combined_html_report,
    render_combined_json_report,
)
from vulnspider.scoring import XSSScorer
from vulnspider.selection import select_top_k
from vulnspider.selection.combined import select_combined_top_k


def _endpoint() -> Endpoint:
    return Endpoint(
        method=HttpMethod.GET,
        scheme="http",
        host="127.0.0.1",
        path="/account",
        discovered_by="unit-test",
    )


def _access_result_and_plan() -> tuple[AccessProbePlan, object]:
    plan = AccessProbePlan(
        endpoint_id=_endpoint().id or "",
        endpoint_fingerprint=_endpoint().fingerprint,
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
    features = {
        ACCESS_UNAUTHORIZED_SUCCESS: FeatureObservation(
            name=ACCESS_UNAUTHORIZED_SUCCESS,
            value=1.0,
            observed=True,
            source="unit-test",
            extractor_version="unit-v1",
        ),
        ACCESS_BODY_SIZE_SIMILARITY_RATIO: FeatureObservation(
            name=ACCESS_BODY_SIZE_SIMILARITY_RATIO,
            value=1.0,
            observed=True,
            source="unit-test",
            extractor_version="unit-v1",
        ),
    }
    return plan, score_access_plan(plan, features)


class CombinedJsonReportTests(unittest.TestCase):
    def test_contains_both_categories_ranked_together(self) -> None:
        input_point = InputPoint(
            endpoint_id="ep_search",
            endpoint_fingerprint="fp_search",
            location=InputLocation.QUERY,
            name="q",
            baseline_value="a",
        )
        xss_vector = FeatureVector(
            input_point_id=input_point.id or "",
            probe_run_ids=("pair_1",),
            features={
                MARKER_REFLECTED: FeatureObservation(
                    name=MARKER_REFLECTED,
                    value=1.0,
                    observed=True,
                    source="unit-test",
                    extractor_version="unit-v1",
                ),
                RESPONSE_LENGTH_DIFF_RATIO: FeatureObservation(
                    name=RESPONSE_LENGTH_DIFF_RATIO,
                    value=0.0,
                    observed=True,
                    source="unit-test",
                    extractor_version="unit-v1",
                ),
            },
        )
        xss_result = XSSScorer().score(xss_vector)
        _plan, access_result = _access_result_and_plan()

        injection_outcome = select_top_k((xss_result,), k=2)
        access_outcome = select_top_k_access((access_result,), k=2)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=2)

        report = build_combined_json_report(combined)
        self.assertEqual(report["schema_version"], "0.1")
        self.assertEqual(
            set(report["categories"]),
            {"SQLI", "REFLECTED_XSS", "BROKEN_ACCESS_CONTROL"},
        )
        categories = {item["category"] for item in report["candidates"]}
        self.assertEqual(categories, {"INJECTION", "BROKEN_ACCESS_CONTROL"})
        access_record = next(
            item for item in report["candidates"] if item["category"] == "BROKEN_ACCESS_CONTROL"
        )
        self.assertEqual(access_record["check_kind"], "CREDENTIAL_STRIP")
        self.assertEqual(access_record["raw_rank_score"], 75.0)
        self.assertTrue(access_record["evidence"])

    def test_rendered_json_is_deterministic_and_serializable(self) -> None:
        _plan, access_result = _access_result_and_plan()
        access_outcome = select_top_k_access((access_result,), k=1)
        injection_outcome = select_top_k((), k=1)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=1)

        first = render_combined_json_report(combined, warnings=("z", "a", "z"))
        second = render_combined_json_report(combined, warnings=("a", "z"))
        self.assertEqual(first, second)
        parsed = json.loads(first)
        self.assertEqual(parsed["warnings"], ["a", "z"])
        for misleading_name in ("confidence", "probability", "confirmed"):
            self.assertNotIn(misleading_name, first.lower())


class CombinedHtmlReportTests(unittest.TestCase):
    def test_renders_access_card_with_endpoint_and_requests(self) -> None:
        plan, access_result = _access_result_and_plan()
        access_outcome = select_top_k_access((access_result,), k=1)
        injection_outcome = select_top_k((), k=1)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=1)

        endpoint = _endpoint()
        from vulnspider.domain import ResponseSnapshot

        reference_response = ResponseSnapshot(
            request_id=plan.reference_request.id or "",
            status_code=200,
            elapsed_ms=1.0,
            body_bytes_hash="a" * 64,
            body_length_bytes=100,
        )
        comparison_response = ResponseSnapshot(
            request_id=plan.comparison_request.id or "",
            status_code=200,
            elapsed_ms=1.0,
            body_bytes_hash="b" * 64,
            body_length_bytes=100,
        )
        candidate_id = access_result.candidate.id or ""
        html_text = render_combined_html_report(
            combined,
            endpoints={endpoint.id or "": endpoint},
            access_probe_runs={candidate_id: (plan, reference_response, comparison_response)},
            target="http://127.0.0.1/",
        )
        self.assertIn("Broken Access Control", html_text)
        self.assertIn("GET /account", html_text)
        self.assertIn("Executed requests", html_text)
        self.assertIn(candidate_id, html_text)
        for misleading_name in ("confidence", "probability", "confirmed"):
            self.assertNotIn(misleading_name, html_text.lower())

    def test_renders_empty_state_with_no_selected_candidates(self) -> None:
        injection_outcome = select_top_k((), k=1)
        access_outcome = select_top_k_access((), k=1)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=1)
        html_text = render_combined_html_report(combined)
        self.assertIn("No rankable candidates were selected.", html_text)


if __name__ == "__main__":
    unittest.main()
