"""DemoShop: the labeled target the live ranking evaluation is measured on.

These are not tests of a scanner feature. They guard the two properties the
evaluation depends on and that are easy to break by editing the site: the
committed ground truth still describes the site, and the storefront still
exposes the input surface a crawl has to find. A drift in either silently
turns every ``Precision@K`` into a number about a different application.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools import demo_shop
from vulnspider.corpus.ground_truth import read_ground_truth

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH_FILE = REPO_ROOT / "data" / "demo" / "demoshop-ground-truth.json"


class DemoShopSpecTests(unittest.TestCase):
    def test_the_site_has_one_hundred_input_points(self) -> None:
        self.assertEqual(demo_shop.INPUT_POINTS, 100)
        self.assertEqual(
            demo_shop.INPUT_POINTS,
            sum(len(page.inputs) for page in demo_shop.PAGES),
        )

    def test_the_mix_covers_every_family_and_both_hard_directions(self) -> None:
        families = demo_shop.counts_by_family()
        for family, count in families.items():
            self.assertGreater(count, 0, family)
        self.assertEqual(sum(families.values()), demo_shop.VULNERABLE_INPUT_POINTS)
        kinds = {item.kind for page in demo_shop.PAGES for item in page.inputs}
        # Hard negatives (look vulnerable, are not) and hard positives (look
        # safe, are not) are what keep the metrics away from 1.000.
        for kind in ("safe_validated", "safe_stripped", "safe_type_error"):
            self.assertIn(kind, kinds)
        for kind in ("sqli_blind", "xss_conditional"):
            self.assertIn(kind, kinds)

    def test_parameter_names_are_unique_per_route(self) -> None:
        for page in demo_shop.PAGES:
            names = [item.name for item in page.inputs]
            self.assertEqual(len(names), len(set(names)), page.path)


class DemoShopGroundTruthTests(unittest.TestCase):
    def test_every_input_point_is_labeled_for_both_injection_families(self) -> None:
        store = demo_shop.ground_truth()
        keys = set(store.labels)
        for page in demo_shop.PAGES:
            for item in page.inputs:
                for family in ("SQLI", "REFLECTED_XSS"):
                    self.assertIn(
                        demo_shop.GroundTruthKey(
                            application_id=demo_shop.APPLICATION_ID,
                            method="GET",
                            canonical_path=page.path,
                            parameter_location="QUERY",
                            parameter_name=item.name,
                            vulnerability_type=family,
                        ),
                        keys,
                    )

    def test_only_numeric_seeds_carry_an_access_control_label(self) -> None:
        # The access layer plans an IDENTIFIER_SUBSTITUTION probe only for a
        # numeric identifier, so labeling the rest would invent ground truth
        # for candidates that are never generated.
        labeled = {
            (key.canonical_path, key.parameter_name)
            for key in demo_shop.ground_truth().labels
            if key.vulnerability_type == "BROKEN_ACCESS_CONTROL"
        }
        expected = {
            (page.path, item.name)
            for page in demo_shop.PAGES
            for item in page.inputs
            if item.numeric_seed
        }
        self.assertEqual(labeled, expected)

    def test_a_label_is_true_exactly_for_its_own_family(self) -> None:
        for key, label in demo_shop.ground_truth().labels.items():
            page = demo_shop.PAGES_BY_PATH[key.canonical_path]
            item = next(
                entry for entry in page.inputs if entry.name == key.parameter_name
            )
            self.assertEqual(
                label,
                item.info.vulnerability == key.vulnerability_type,
                f"{key.canonical_path}?{key.parameter_name} {key.vulnerability_type}",
            )

    def test_the_committed_file_matches_the_site(self) -> None:
        self.assertTrue(
            GROUND_TRUTH_FILE.is_file(),
            "regenerate with: python demo_target_server.py "
            f"--ground-truth {GROUND_TRUTH_FILE} --ground-truth-only",
        )
        on_disk = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, demo_shop.ground_truth_document())

    def test_the_committed_file_supports_a_false_positive_measurement(self) -> None:
        store = read_ground_truth(GROUND_TRUTH_FILE)
        store.validate_usable()
        self.assertEqual(store.applications, (demo_shop.APPLICATION_ID,))


class DemoShopRenderingTests(unittest.TestCase):
    def test_the_index_links_every_route_and_never_the_lab(self) -> None:
        index = demo_shop.render_index().decode("utf-8")
        for page in demo_shop.PAGES:
            self.assertIn(f'href="{page.path}"', index)
        # Crawling the lab would seed input points with payload values and
        # corrupt the baseline the scan measures against.
        self.assertNotIn(demo_shop.LAB_PATH, index)

    def test_every_route_serves_its_whole_input_surface_as_a_get_form(self) -> None:
        for page in demo_shop.PAGES:
            status, body = demo_shop.render_route(page, {})
            text = body.decode("utf-8")
            self.assertEqual(status, 200, page.path)
            self.assertIn(f'action="{page.path}"', text)
            for item in page.inputs:
                self.assertIn(f'name="{item.name}"', text)

    def test_a_metacharacter_value_only_breaks_the_routes_that_are_broken(self) -> None:
        payload = "1' OR '1'='1"
        for page in demo_shop.PAGES:
            for item in page.inputs:
                status, _body = demo_shop.render_route(page, {item.name: payload})
                if item.kind in ("sqli_error", "safe_type_error"):
                    self.assertEqual(status, 500, f"{page.path}?{item.name}")
                elif item.kind == "safe_validated":
                    self.assertEqual(status, 400, f"{page.path}?{item.name}")
                else:
                    self.assertEqual(status, 200, f"{page.path}?{item.name}")

    def test_the_sanitiser_preserves_length(self) -> None:
        # Deleting the characters instead of substituting them made every
        # sanitised route's response systematically shorter, which turned
        # response_length_diff_ratio into a label lookup.
        raw = "VULNSPIDER_ABCDZ<>\"'Z"
        self.assertEqual(len(demo_shop._strip_dangerous(raw)), len(raw))
        self.assertNotIn("<", demo_shop._strip_dangerous(raw))

    def test_the_lab_lists_every_input_point(self) -> None:
        lab = demo_shop.render_lab().decode("utf-8")
        for page in demo_shop.PAGES:
            self.assertIn(page.path, lab)
            for item in page.inputs:
                self.assertIn(f"<code>{item.name}</code>", lab)


if __name__ == "__main__":
    unittest.main()
