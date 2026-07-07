from __future__ import annotations

import json
import unittest
from pathlib import Path

from spiderman.discovery import LegacyCrawlerAdapter
from spiderman.domain import HttpMethod, InputLocation

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_crawl_records.json"


def load_fixture(name: str) -> list[dict[str, object]]:
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return list(fixtures[name])


class LegacyCrawlerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = LegacyCrawlerAdapter()

    def test_multiple_query_params_become_separate_input_points(self) -> None:
        result = self.adapter.convert(load_fixture("query_multi"))
        names = sorted(point.name for point in result.input_points)
        self.assertEqual(names, ["page", "q"])
        self.assertTrue(
            all(point.location == InputLocation.QUERY for point in result.input_points)
        )

    def test_repeated_url_with_different_values_deduplicates_input_point(self) -> None:
        result = self.adapter.convert(load_fixture("query_repeated_values"))
        self.assertEqual(len(result.input_points), 1)
        self.assertEqual(result.input_points[0].name, "q")
        self.assertEqual(result.input_points[0].baseline_value, "book")

    def test_get_form_creates_form_input_on_resolved_action_endpoint(self) -> None:
        result = self.adapter.convert(load_fixture("form_get"))
        self.assertEqual(len(result.input_points), 1)
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.method, HttpMethod.GET)
        self.assertEqual(endpoint.path, "/find")
        self.assertEqual(result.input_points[0].name, "term")
        self.assertEqual(result.input_points[0].location, InputLocation.FORM)

    def test_post_form_creates_one_input_point_per_named_field(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        self.assertEqual(sorted(point.name for point in result.input_points), ["password", "username"])
        self.assertEqual({endpoint.method for endpoint in result.endpoints}, {HttpMethod.POST})
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(
            result.request_templates[0].form,
            {"password": "", "username": ""},
        )

    def test_same_parameter_name_in_query_and_form_stays_distinct(self) -> None:
        result = self.adapter.convert(load_fixture("same_name_query_and_form"))
        self.assertEqual(len(result.input_points), 2)
        locations = {point.location for point in result.input_points}
        self.assertEqual(locations, {InputLocation.QUERY, InputLocation.FORM})

    def test_duplicate_records_deduplicate_deterministically(self) -> None:
        result = self.adapter.convert(load_fixture("duplicate_records"))
        self.assertEqual(len(result.input_points), 1)
        self.assertEqual(len(result.endpoints), 1)

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


if __name__ == "__main__":
    unittest.main()
