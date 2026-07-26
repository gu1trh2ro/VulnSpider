from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unittest

from vulnspider.discovery import (
    CollectorKind,
    ProbeReadyStatus,
    StaticExtractionResult,
    extract_static_html,
)
from vulnspider.domain import (
    HttpMethod,
    InputLocation,
    RequestContextCompleteness,
    validate_input_point_request_context,
)


SOURCE_URL = "http://example.test/app/index.html"


class StaticHtmlExtractorTests(unittest.TestCase):
    def test_extracts_links_queries_and_forms_into_canonical_contract(self) -> None:
        html = """
        <html><body>
          <a href="../items?id=7">item</a>
          <form action="/search">
            <input name="q" value="books">
            <input type="hidden" name="token" value="abc">
            <textarea name="bio">hello world</textarea>
            <select name="category">
              <option value="a">A</option>
              <option value="b" selected>B</option>
            </select>
          </form>
          <form method="POST" action="submit">
            <input type="email" name="email" value="a@example.test">
            <input type="password" name="password" value="correct horse">
            <input type="checkbox" name="remember" value="yes" checked>
          </form>
        </body></html>
        """

        result = extract_static_html(html, SOURCE_URL)

        self.assertIsInstance(result, StaticExtractionResult)
        self.assertEqual(
            tuple(link.crawl_url for link in result.navigable_links),
            ("http://example.test/items?id=7",),
        )
        self.assertEqual(
            result.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_STATIC,
        )
        result.discovery.validate()

        form_templates = [
            item
            for item in result.discovery.request_templates
            if item.metadata.get("context_kind") == "form"
        ]
        self.assertEqual(len(form_templates), 2)
        get_form = next(item for item in form_templates if item.method == HttpMethod.GET)
        post_form = next(
            item for item in form_templates if item.method == HttpMethod.POST
        )
        self.assertEqual(
            get_form.query,
            (
                ("q", "books"),
                ("token", "abc"),
                ("bio", "hello world"),
                ("category", "b"),
            ),
        )
        self.assertEqual(get_form.form, ())
        self.assertEqual(
            get_form.url,
            (
                "http://example.test/search?q=books&token=abc&"
                "bio=hello+world&category=b"
            ),
        )
        self.assertEqual(
            dict(get_form.provenance)["form_method"],
            "html_default_get",
        )
        self.assertEqual(
            post_form.form,
            (
                ("email", "a@example.test"),
                ("password", "correct horse"),
                ("remember", "yes"),
            ),
        )
        self.assertEqual(post_form.url, "http://example.test/app/submit")
        self.assertEqual(
            post_form.completeness,
            RequestContextCompleteness.COMPLETE,
        )

        hidden = next(
            point
            for point in result.discovery.input_points
            if point.name == "token"
        )
        self.assertEqual(hidden.location, InputLocation.QUERY)
        self.assertEqual(hidden.type_hint, "hidden")
        self.assertTrue(hidden.metadata["hidden"])
        self.assertTrue(
            all(
                item.status == ProbeReadyStatus.READY
                for item in result.discovery.probe_readiness
            )
        )
        self.assertEqual(
            len(result.discovery.ready_contexts()),
            len(result.discovery.input_point_request_contexts),
        )

        points = {item.id: item for item in result.discovery.input_points}
        templates = {
            item.id: item for item in result.discovery.request_templates
        }
        for context in result.discovery.input_point_request_contexts:
            validate_input_point_request_context(
                points[context.input_point_id],
                templates[context.request_template_id],
            )

    def test_select_uses_first_option_and_preserves_textarea_blank(self) -> None:
        result = extract_static_html(
            """
            <form method="post" action="/profile">
              <textarea name="note"></textarea>
              <select name="theme">
                <option>light</option>
                <option value="dark">Dark</option>
              </select>
            </form>
            """,
            SOURCE_URL,
        )
        template = next(
            item
            for item in result.discovery.request_templates
            if item.metadata.get("context_kind") == "form"
        )
        self.assertEqual(template.form, (("note", ""), ("theme", "light")))

    def test_result_is_immutable_and_deterministic(self) -> None:
        html = """
        <a href="/b?q=2">b</a>
        <a href="/a?q=1">a</a>
        <form method="post" action="/submit">
          <input name="q" value="">
        </form>
        """
        first = extract_static_html(html, SOURCE_URL)
        second = extract_static_html(html, SOURCE_URL)
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first.to_dict(), sort_keys=True),
            json.dumps(second.to_dict(), sort_keys=True),
        )
        with self.assertRaises(FrozenInstanceError):
            first.source_url = "http://changed.test/"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            first.discovery.input_points[0].metadata["changed"] = True  # type: ignore[index]

    def test_password_value_never_appears_in_warning_payloads(self) -> None:
        secret = "do-not-log-this"
        result = extract_static_html(
            f"""
            <form method="post" action="/login">
              <input type="password" name="password" value="{secret}">
              <input disabled name="ignored" value="{secret}">
            </form>
            """,
            SOURCE_URL,
        )
        warning_payload = json.dumps(
            [
                {
                    "code": item.code,
                    "message": item.message,
                    "details": dict(item.details),
                }
                for item in result.warnings
            ],
            sort_keys=True,
        )
        self.assertNotIn(secret, warning_payload)


if __name__ == "__main__":
    unittest.main()
