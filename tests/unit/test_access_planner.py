from __future__ import annotations

import unittest

from vulnspider.access.planner import (
    plan_credential_strip,
    plan_identifier_substitution,
)
from vulnspider.domain import (
    AccessCheckKind,
    AccessSubjectContext,
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    RequestContextCompleteness,
    RequestTemplate,
)


def _endpoint(path: str = "/account") -> Endpoint:
    return Endpoint(
        method=HttpMethod.GET,
        scheme="http",
        host="127.0.0.1",
        path=path,
        discovered_by="unit-test",
    )


class CredentialStripPlanningTests(unittest.TestCase):
    def _template(
        self,
        *,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        method: HttpMethod = HttpMethod.GET,
        completeness: RequestContextCompleteness = RequestContextCompleteness.COMPLETE,
    ) -> RequestTemplate:
        endpoint = _endpoint()
        return RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=method,
            url="http://127.0.0.1/account?tab=overview",
            query=(("tab", "overview"),),
            cookies=cookies or {},
            headers=headers or {},
            completeness=completeness,
        )

    def test_plans_when_cookies_present(self) -> None:
        plan = plan_credential_strip(self._template(cookies={"session": "abc"}))
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.check_kind, AccessCheckKind.CREDENTIAL_STRIP)
        self.assertEqual(plan.reference_subject, AccessSubjectContext.ORIGINAL)
        self.assertEqual(plan.comparison_subject, AccessSubjectContext.ANONYMOUS)
        self.assertEqual(plan.comparison_request.cookies, {})
        self.assertEqual(plan.reference_request.cookies, {"session": "abc"})
        self.assertEqual(plan.changed_aspect, "credentials")
        self.assertIsNone(plan.input_point_id)

    def test_plans_when_authorization_header_present(self) -> None:
        plan = plan_credential_strip(
            self._template(headers={"Authorization": "Bearer token"})
        )
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertNotIn("Authorization", plan.comparison_request.headers)
        self.assertEqual(
            plan.reference_request.headers.get("Authorization"), "Bearer token"
        )

    def test_no_plan_without_any_credentials(self) -> None:
        self.assertIsNone(plan_credential_strip(self._template()))

    def test_no_plan_for_post_requests(self) -> None:
        template = self._template(cookies={"session": "abc"}, method=HttpMethod.POST)
        self.assertIsNone(plan_credential_strip(template))

    def test_no_plan_when_not_probe_ready(self) -> None:
        template = self._template(
            cookies={"session": "abc"},
            completeness=RequestContextCompleteness.PARTIAL,
        )
        self.assertIsNone(plan_credential_strip(template))

    def test_other_headers_are_preserved_when_stripping(self) -> None:
        template = self._template(
            cookies={"session": "abc"},
            headers={"Accept": "text/html", "Authorization": "Bearer token"},
        )
        plan = plan_credential_strip(template)
        assert plan is not None
        self.assertEqual(plan.comparison_request.headers.get("Accept"), "text/html")
        self.assertNotIn("Authorization", plan.comparison_request.headers)


class IdentifierSubstitutionPlanningTests(unittest.TestCase):
    def _template_and_point(
        self,
        *,
        baseline_value: str = "1",
        method: HttpMethod = HttpMethod.GET,
        completeness: RequestContextCompleteness = RequestContextCompleteness.COMPLETE,
        location: InputLocation = InputLocation.QUERY,
    ) -> tuple[RequestTemplate, InputPoint]:
        endpoint = _endpoint("/product")
        if location == InputLocation.QUERY:
            template = RequestTemplate(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                method=method,
                url=f"http://127.0.0.1/product?id={baseline_value}",
                query=(("id", baseline_value),),
                completeness=completeness,
            )
        else:
            template = RequestTemplate(
                endpoint_id=endpoint.id or "",
                endpoint_fingerprint=endpoint.fingerprint,
                method=method,
                url="http://127.0.0.1/product",
                form=(("id", baseline_value),),
                completeness=completeness,
            )
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=location,
            name="id",
            baseline_value=baseline_value,
        )
        return template, input_point

    def test_increments_numeric_query_identifier(self) -> None:
        template, input_point = self._template_and_point(baseline_value="41")
        plan = plan_identifier_substitution(input_point, template)
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.check_kind, AccessCheckKind.IDENTIFIER_SUBSTITUTION)
        self.assertEqual(plan.comparison_request.query, (("id", "42"),))
        self.assertIn("id=42", plan.comparison_request.url)
        self.assertEqual(plan.changed_aspect, "query.id")
        self.assertEqual(plan.input_point_id, input_point.id)
        self.assertEqual(
            plan.reference_subject,
            plan.comparison_subject,
        )

    def test_increments_numeric_form_identifier_without_changing_url(self) -> None:
        template, input_point = self._template_and_point(
            baseline_value="7", location=InputLocation.FORM
        )
        plan = plan_identifier_substitution(input_point, template)
        assert plan is not None
        self.assertEqual(plan.comparison_request.form, (("id", "8"),))
        self.assertEqual(plan.comparison_request.url, template.url)
        self.assertEqual(plan.changed_aspect, "form.id")

    def test_no_plan_for_non_numeric_identifier(self) -> None:
        template, input_point = self._template_and_point(baseline_value="abc-uuid")
        self.assertIsNone(plan_identifier_substitution(input_point, template))

    def test_no_plan_for_post_requests(self) -> None:
        template, input_point = self._template_and_point(
            baseline_value="1", method=HttpMethod.POST
        )
        self.assertIsNone(plan_identifier_substitution(input_point, template))

    def test_no_plan_when_baseline_value_is_none(self) -> None:
        endpoint = _endpoint("/product")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/product?id=1",
            query=(("id", "1"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="id",
            baseline_value=None,
        )
        self.assertIsNone(plan_identifier_substitution(input_point, template))

    def test_no_plan_when_not_probe_ready(self) -> None:
        template, input_point = self._template_and_point(
            baseline_value="1",
            completeness=RequestContextCompleteness.PARTIAL,
        )
        self.assertIsNone(plan_identifier_substitution(input_point, template))

    def test_non_target_query_pairs_are_preserved(self) -> None:
        endpoint = _endpoint("/product")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/product?id=1&view=full",
            query=(("id", "1"), ("view", "full")),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="id",
            baseline_value="1",
        )
        plan = plan_identifier_substitution(input_point, template)
        assert plan is not None
        self.assertEqual(plan.comparison_request.query, (("id", "2"), ("view", "full")))


if __name__ == "__main__":
    unittest.main()
