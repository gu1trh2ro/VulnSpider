from __future__ import annotations

import json
import unittest
from pathlib import Path

from spiderman.discovery import LegacyCrawlerAdapter
from spiderman.domain import HttpMethod, InputLocation, RequestContextCompleteness

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_crawl_records.json"


def load_fixture(name: str) -> list[dict[str, object]]:
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return list(fixtures[name])


class LegacyCrawlerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = LegacyCrawlerAdapter()

    def assertWarningContains(self, warnings: tuple[str, ...], text: str) -> None:
        self.assertTrue(
            any(text in warning for warning in warnings),
            f"expected warning containing {text!r}, got {warnings!r}",
        )

    def test_multiple_query_params_become_separate_input_points(self) -> None:
        result = self.adapter.convert(load_fixture("query_multi"))
        names = sorted(point.name for point in result.input_points)
        self.assertEqual(names, ["page", "q"])
        self.assertTrue(
            all(point.location == InputLocation.QUERY for point in result.input_points)
        )
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(result.request_templates[0].query, (("q", "book"), ("page", "1")))
        self.assertEqual(len(result.input_point_request_contexts), 2)

    def test_repeated_url_with_different_values_deduplicates_input_point(self) -> None:
        result = self.adapter.convert(load_fixture("query_repeated_values"))
        self.assertEqual(len(result.input_points), 1)
        self.assertEqual(result.input_points[0].name, "q")
        self.assertEqual(result.input_points[0].baseline_value, "book")
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(len(result.input_point_request_contexts), 2)
        self.assertWarningContains(result.warnings, "no canonical baseline selected")

    def test_get_form_creates_form_input_on_resolved_action_endpoint(self) -> None:
        result = self.adapter.convert(load_fixture("form_get"))
        self.assertEqual(len(result.input_points), 1)
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.method, HttpMethod.GET)
        self.assertEqual(endpoint.path, "/find")
        self.assertEqual(result.input_points[0].name, "term")
        self.assertEqual(result.input_points[0].location, InputLocation.FORM)
        self.assertEqual(result.request_templates[0].completeness, RequestContextCompleteness.PARTIAL)
        self.assertEqual(result.request_templates[0].form, (("term", ""),))
        self.assertWarningContains(result.warnings, "hidden inputs may have been omitted")

    def test_post_form_creates_one_input_point_per_named_field(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        self.assertEqual(sorted(point.name for point in result.input_points), ["password", "username"])
        self.assertEqual({endpoint.method for endpoint in result.endpoints}, {HttpMethod.POST})
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(
            result.request_templates[0].form,
            (("username", ""), ("password", "")),
        )
        self.assertEqual(len(result.input_point_request_contexts), 2)

    def test_same_parameter_name_in_query_and_form_stays_distinct(self) -> None:
        result = self.adapter.convert(load_fixture("same_name_query_and_form"))
        self.assertEqual(len(result.input_points), 2)
        locations = {point.location for point in result.input_points}
        self.assertEqual(locations, {InputLocation.QUERY, InputLocation.FORM})
        self.assertEqual(len(result.input_point_request_contexts), 2)

    def test_duplicate_records_deduplicate_deterministically(self) -> None:
        result = self.adapter.convert(load_fixture("duplicate_records"))
        self.assertEqual(len(result.input_points), 1)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(len(result.input_point_request_contexts), 1)

    def test_missing_or_partial_legacy_fields_warn_without_guessing(self) -> None:
        result = self.adapter.convert(load_fixture("partial_fields"))
        self.assertEqual(result.input_points, ())
        self.assertGreaterEqual(len(result.warnings), 2)

    def test_hidden_input_is_preserved_when_legacy_record_exposes_it(self) -> None:
        result = self.adapter.convert(load_fixture("hidden_input"))
        self.assertEqual(len(result.input_points), 1)
        point = result.input_points[0]
        self.assertEqual(point.name, "csrf")
        self.assertEqual(point.type_hint, "hidden")
        self.assertTrue(point.metadata["hidden"])
        self.assertEqual(point.metadata["visibility"], "hidden")

    def test_same_action_method_distinct_forms_do_not_overwrite_templates(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/profile",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "email",
                                "type": "text",
                                "value": "a@example.test",
                                "form_method": "POST",
                                "form_action": "/update",
                            }
                        ]
                    ),
                },
                {
                    "link": "http://127.0.0.1/security",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "password",
                                "type": "password",
                                "value": "secret",
                                "form_method": "POST",
                                "form_action": "/update",
                            }
                        ]
                    ),
                },
            ]
        )
        self.assertEqual(sorted(point.name for point in result.input_points), ["email", "password"])
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(
            sorted(template.form for template in result.request_templates),
            [(("email", "a@example.test"),), (("password", "secret"),)],
        )
        self.assertEqual(len(result.input_point_request_contexts), 2)
        self.assertEqual(
            len({template.id for template in result.request_templates}),
            2,
        )

    def test_missing_form_method_warns_and_marks_provenance(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [{"name": "term", "type": "text", "form_action": "/find"}]
                    ),
                }
            ]
        )
        point = result.input_points[0]
        template = result.request_templates[0]
        self.assertEqual(template.method, HttpMethod.GET)
        self.assertEqual(point.metadata["form_method_provenance"], "unknown_assumed_get")
        self.assertEqual(template.metadata["form_method_provenance"], "unknown_assumed_get")
        self.assertWarningContains(result.warnings, "missing form_method")

    def test_missing_form_action_warns_and_marks_provenance(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [{"name": "term", "type": "text", "form_method": "GET"}]
                    ),
                }
            ]
        )
        point = result.input_points[0]
        template = result.request_templates[0]
        self.assertEqual(template.url, "http://127.0.0.1/search")
        self.assertEqual(
            point.metadata["form_action_provenance"],
            "unknown_assumed_current_page",
        )
        self.assertEqual(
            template.metadata["form_action_provenance"],
            "unknown_assumed_current_page",
        )
        self.assertWarningContains(result.warnings, "missing form_action")

    def test_missing_form_method_and_action_warns_for_both(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search",
                    "query_params": "{}",
                    "input_fields": json.dumps([{"name": "term", "type": "text"}]),
                }
            ]
        )
        self.assertWarningContains(result.warnings, "missing form_method")
        self.assertWarningContains(result.warnings, "missing form_action")
        self.assertEqual(
            result.request_templates[0].metadata["form_method_provenance"],
            "unknown_assumed_get",
        )
        self.assertEqual(
            result.request_templates[0].metadata["form_action_provenance"],
            "unknown_assumed_current_page",
        )

    def test_explicit_form_method_and_action_have_explicit_provenance(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        template = result.request_templates[0]
        self.assertEqual(template.metadata["form_method_provenance"], "explicit")
        self.assertEqual(template.metadata["form_action_provenance"], "explicit")
        self.assertFalse(any("missing form_method" in item for item in result.warnings))
        self.assertFalse(any("missing form_action" in item for item in result.warnings))

    def test_visible_form_context_surfaces_hidden_input_loss(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        template = result.request_templates[0]
        self.assertEqual(template.completeness, RequestContextCompleteness.PARTIAL)
        self.assertEqual(
            template.metadata["hidden_input_policy"],
            "legacy_collector_may_omit_hidden_inputs",
        )
        self.assertWarningContains(result.warnings, "hidden inputs may have been omitted")

    def test_repeated_query_parameters_are_preserved_losslessly(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&tag=b&q=x",
                    "query_params": json.dumps({"tag": ["a", "b"], "q": "x"}),
                    "input_fields": "[]",
                }
            ]
        )
        template = result.request_templates[0]
        tag = next(point for point in result.input_points if point.name == "tag")
        self.assertEqual(template.query, (("tag", "a"), ("tag", "b"), ("q", "x")))
        self.assertEqual(tag.baseline_value, None)
        self.assertEqual(tag.baseline_values, ("a", "b"))
        self.assertTrue(tag.metadata["repeated_parameter"])
        self.assertEqual(template.metadata["repeated_parameters"], ("tag",))

    def test_duplicate_baseline_variants_are_explicitly_associated(self) -> None:
        result = self.adapter.convert(load_fixture("query_repeated_values"))
        input_point = result.input_points[0]
        associated_template_ids = {
            binding.request_template_id
            for binding in result.input_point_request_contexts
            if binding.input_point_id == input_point.id
        }
        self.assertEqual(associated_template_ids, {template.id for template in result.request_templates})
        self.assertEqual(len(associated_template_ids), 2)
        self.assertWarningContains(result.warnings, "no canonical baseline selected")

    def test_request_template_identity_is_deterministic_from_adapter(self) -> None:
        records = load_fixture("form_post")
        first = self.adapter.convert(records)
        second = self.adapter.convert(list(reversed(records)))
        self.assertEqual(
            [template.id for template in first.request_templates],
            [template.id for template in second.request_templates],
        )
        self.assertEqual(
            [binding.id for binding in first.input_point_request_contexts],
            [binding.id for binding in second.input_point_request_contexts],
        )

    def test_adapter_does_not_import_legacy_runtime_modules(self) -> None:
        adapter_source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "spiderman"
            / "discovery"
            / "legacy_adapter.py"
        ).read_text(encoding="utf-8")
        forbidden = ("reference.whspider_legacy", "local_llm", "rag", "playwright")
        self.assertFalse(any(item in adapter_source for item in forbidden))


if __name__ == "__main__":
    unittest.main()
