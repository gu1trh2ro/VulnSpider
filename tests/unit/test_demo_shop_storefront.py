"""Guard storefront asset isolation and the existing discovery surface."""

from __future__ import annotations

import unittest
from html.parser import HTMLParser
from http.client import HTTPConnection
from threading import Thread
from urllib.parse import urlsplit

from tools import demo_shop, demo_shop_storefront


class Links(HTMLParser):
    def __init__(self, body: bytes) -> None:
        super().__init__()
        self.links: list[str] = []
        self.named_controls: list[str] = []
        self.in_form = False
        self.markers: list[str] = []
        self.marker_buttons: list[dict[str, str | None]] = []
        self.control_ids: list[str] = []
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("data-input-point"):
            self.markers.append(values["data-input-point"] or "")
        if tag == "button" and values.get("class") == "input-marker":
            self.marker_buttons.append(values)
        if tag in ("input", "select", "textarea") and values.get("id"):
            self.control_ids.append(values["id"] or "")
        if tag == "form":
            self.in_form = True
        if tag == "a" and values.get("href"):
            self.links.append(values["href"] or "")
        if self.in_form and tag in ("input", "select", "textarea") and values.get("name"):
            self.named_controls.append(values["name"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.in_form = False


class StorefrontContractTests(unittest.TestCase):
    def test_all_one_hundred_inputs_have_unique_stable_non_submitting_markers(self) -> None:
        numbers: list[str] = []
        for page in demo_shop.PAGES:
            baseline = Links(demo_shop.render_route(page, {})[1])
            changed = Links(demo_shop.render_route(page, {page.inputs[0].name: "different"})[1])
            self.assertEqual(baseline.markers, changed.markers)
            self.assertEqual(len(baseline.markers), len(page.inputs))
            self.assertEqual(len(baseline.marker_buttons), len(page.inputs))
            for number, marker in zip(baseline.markers, baseline.marker_buttons, strict=True):
                self.assertEqual(marker["type"], "button")
                self.assertNotIn("name", marker)
                self.assertEqual(marker["aria-describedby"], f"input-hint-{number}")
                self.assertIn(f"input-point-{number}", baseline.control_ids)
            numbers.extend(baseline.markers)
        self.assertEqual(numbers, [f"{number:03d}" for number in range(1, 101)])

    def test_hidden_inputs_keep_their_type_and_get_an_explanatory_marker(self) -> None:
        hidden = [(page, item) for page in demo_shop.PAGES for item in page.inputs if item.control == "hidden"]
        self.assertTrue(hidden)
        for page, item in hidden:
            number = demo_shop.INPUT_POINT_NUMBERS[(page.path, item.name)]
            control = demo_shop._control(item, item.seed, number=number)
            self.assertIn(f'type="hidden" id="input-point-{number:03d}" name="{item.name}"', control)
            self.assertIn("페이지에 포함된 숨김 입력", control)

    def test_navigation_never_adds_query_seeds_or_unknown_routes(self) -> None:
        documents = [demo_shop.render_index()]
        documents.extend(demo_shop.render_route(page, {})[1] for page in demo_shop.PAGES)
        allowed = {"", "/"} | set(demo_shop.PAGES_BY_PATH)
        for body in documents:
            for link in Links(body).links:
                parsed = urlsplit(link)
                self.assertIn(parsed.path, allowed, link)
                self.assertEqual(parsed.query, "", link)
                self.assertEqual(parsed.netloc, "", link)

    def test_presentation_does_not_add_named_inputs(self) -> None:
        self.assertEqual(Links(demo_shop.render_index()).named_controls, [])
        for page in demo_shop.PAGES:
            actual = Links(demo_shop.render_route(page, {})[1]).named_controls
            self.assertCountEqual(actual, [item.name for item in page.inputs], page.path)

    def test_all_four_product_photos_are_bundled_and_referenced(self) -> None:
        body = demo_shop.render_index().decode("utf-8")
        for _, photo, _, _, _, _, _ in demo_shop_storefront.PRODUCTS:
            route = f"/assets/{photo}.png"
            self.assertIn(route, body)
            path, mime = demo_shop_storefront.ASSETS[route]
            self.assertEqual(mime, "image/png")
            self.assertEqual(path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        self.assertIn('name="viewport"', body)
        self.assertIn("실제 결제·주문·배송은 이루어지지 않습니다", body)


class StorefrontAssetHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = demo_shop.build_server(0)
        cls.worker = Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)

    def test_only_exact_allowlisted_assets_are_served(self) -> None:
        for route, (path, mime) in demo_shop_storefront.ASSETS.items():
            connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
            try:
                connection.request("GET", route)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Content-Type"), mime)
                self.assertEqual(response.read(), path.read_bytes())
            finally:
                connection.close()
        for route in ("/assets/../demo_shop.py", "/assets/%2e%2e/demo_shop.py", "/assets/README.md", "/assets/missing.png", "/assets/shop.css/extra"):
            connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
            try:
                connection.request("GET", route)
                response = connection.getresponse()
                self.assertEqual(response.status, 404, route)
                response.read()
            finally:
                connection.close()
