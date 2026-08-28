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
        # for candidates that are never generated. The authenticated account
        # routes (all numeric) add their own BAC labels.
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
        } | {(route.path, route.param) for route in demo_shop.ACCOUNT_ROUTES}
        self.assertEqual(labeled, expected)

    def test_a_label_is_true_exactly_for_its_own_family(self) -> None:
        account_params = {
            (route.path, route.param): route for route in demo_shop.ACCOUNT_ROUTES
        }
        for key, label in demo_shop.ground_truth().labels.items():
            route = account_params.get((key.canonical_path, key.parameter_name))
            if route is not None:
                expected = (
                    key.vulnerability_type == "BROKEN_ACCESS_CONTROL"
                    and route.vulnerable
                )
                self.assertEqual(label, expected, key.canonical_path)
                continue
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


class DemoShopAccountAreaTests(unittest.TestCase):
    """The authenticated area the BAC pipeline is demonstrated on."""

    def _session(self, role: str = "admin") -> tuple[str, int]:
        parsed = demo_shop.parse_session(
            f"{demo_shop.SESSION_COOKIE}={demo_shop.session_token(role)}"
        )
        assert parsed is not None
        return parsed

    def test_a_valid_token_round_trips_and_a_forged_one_is_rejected(self) -> None:
        self.assertEqual(self._session("admin"), ("admin", 1))
        self.assertEqual(self._session("user"), ("user", 1042))
        self.assertIsNone(demo_shop.parse_session(None))
        self.assertIsNone(
            demo_shop.parse_session(f"{demo_shop.SESSION_COOKIE}=admin.1.badsig")
        )
        self.assertIsNone(demo_shop.parse_session("other=value"))

    def test_protected_routes_require_a_session(self) -> None:
        for route in demo_shop.ACCOUNT_ROUTES:
            status, _body = demo_shop.render_account_route(route, {}, None)
            self.assertEqual(status, 403, route.path)

    def test_idor_route_serves_a_substituted_identifier(self) -> None:
        session = self._session("admin")
        idor = next(r for r in demo_shop.ACCOUNT_ROUTES if r.kind == "idor")
        seed_status, _ = demo_shop.render_account_route(
            idor, {idor.param: idor.seed}, session
        )
        substituted = str(int(idor.seed) + 1)
        sub_status, _ = demo_shop.render_account_route(
            idor, {idor.param: substituted}, session
        )
        # No ownership check: both the owned and the substituted identifier are
        # served, which is exactly the IDOR the access probe should flag.
        self.assertEqual(seed_status, 200)
        self.assertEqual(sub_status, 200)

    def test_owned_route_denies_a_substituted_identifier(self) -> None:
        session = self._session("admin")
        owned = next(r for r in demo_shop.ACCOUNT_ROUTES if r.kind == "owned")
        seed_status, _ = demo_shop.render_account_route(
            owned, {owned.param: owned.seed}, session
        )
        substituted = str(int(owned.seed) + 1)
        sub_status, _ = demo_shop.render_account_route(
            owned, {owned.param: substituted}, session
        )
        # Proper access control: the resource is served to its owner and denied
        # for a substituted identifier -- the true negative.
        self.assertEqual(seed_status, 200)
        self.assertEqual(sub_status, 403)

    def test_the_account_area_is_not_linked_from_the_public_index(self) -> None:
        index = demo_shop.render_index().decode("utf-8")
        self.assertNotIn(demo_shop.ACCOUNT_INDEX_PATH, index)
        for route in demo_shop.ACCOUNT_ROUTES:
            self.assertNotIn(route.path, index)

    def test_the_account_dashboard_links_every_protected_route(self) -> None:
        dashboard = demo_shop.render_account_index(self._session()).decode("utf-8")
        for route in demo_shop.ACCOUNT_ROUTES:
            self.assertIn(f'href="{route.path}"', dashboard)


if __name__ == "__main__":
    unittest.main()
