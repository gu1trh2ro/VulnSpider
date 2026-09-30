"""Real, bounded SQLite price injection and its live demonstration evidence."""

from __future__ import annotations

import re
import unittest
from http.client import HTTPConnection
from threading import Thread
from urllib.parse import parse_qsl, urlencode, urlsplit

from tools import demo_shop


class SearchSQLiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.query = dict(demo_shop.PAGES_BY_PATH['/search'].seeds)

    def test_normal_filters_and_real_boolean_bypass(self) -> None:
        self.assertEqual(demo_shop._search_products(self.query)[:2], (200, ('101', '105', '106')))
        self.assertEqual(demo_shop._search_products({**self.query, 'min_price': '100000'})[:2], (200, ('106',)))
        attack = {**self.query, 'min_price': "1' OR '1'='1"}
        status, ids, _ = demo_shop._search_products(attack)
        self.assertEqual(status, 200)
        self.assertEqual(set(ids), set(demo_shop.storefront.PRODUCTS_BY_ID))
        self.assertEqual(demo_shop._search_products(attack, bind_price=True)[:2], (200, ()))
        self.assertEqual(demo_shop._search_products({**self.query, 'min_price': "1' AND '1'='2"})[:2], (200, ()))

    def test_normal_values_and_sql_errors_are_not_confirmed(self) -> None:
        page = demo_shop.PAGES_BY_PATH['/search']
        for value, expected_status in [('0', 200), ('100000', 200), ("'", 500), ("1' AND '1'='2", 200)]:
            with self.subTest(value=value):
                status, body = demo_shop.render_route(page, {**self.query, 'min_price': value, 'vs_confirm': 'min_price'})
                self.assertEqual(status, expected_status)
                self.assertNotIn(b'class="poc-banner poc-confirmed"', body)
                self.assertIn(b'class="poc-banner poc-pending"', body)

    def test_manual_form_and_dashboard_launcher_use_the_same_database_result(self) -> None:
        page = demo_shop.PAGES_BY_PATH['/search']
        location, cookie = demo_shop.verify_redirect({'path': '/search', 'param': 'min_price'})
        self.assertIsNone(cookie)
        self.assertIsNotNone(location)
        query = dict(parse_qsl(urlsplit(location).query))
        self.assertEqual(query['min_price'], "1' OR '1'='1")
        for confirm in (True, False):
            with self.subTest(confirm=confirm):
                request = dict(query)
                if not confirm:
                    request.pop('vs_confirm')
                status, body = demo_shop.render_route(page, request)
                text = body.decode('utf-8')
                self.assertEqual(status, 200)
                ids = re.search(r'data-search-result-ids="([^"]*)"', text).group(1).split(',')
                self.assertEqual(set(ids), set(demo_shop.storefront.PRODUCTS_BY_ID))
                self.assertEqual('class="poc-banner poc-confirmed"' in text, confirm)
                self.assertNotIn('이 입력점은 안전하게 방어되어 있습니다', text)
                self.assertNotIn('유출된 회원 정보', text)

    def test_database_is_bounded_and_not_modified_by_payloads(self) -> None:
        for value in ["'; DROP TABLE products; --", "0'; UPDATE products SET price=0; --", 'x' * 5000]:
            with self.subTest(value=value[:30]):
                self.assertEqual(demo_shop._search_products({**self.query, 'min_price': value})[0], 500)
                self.assertEqual(demo_shop._search_products(self.query)[1], ('101', '105', '106'))

    def test_other_input_points_keep_their_defenses_and_sql_is_html_escaped(self) -> None:
        self.assertEqual(demo_shop._search_products({**self.query, 'max_price': "0' OR '1'='1"})[0], 400)
        self.assertEqual(demo_shop._search_products({**self.query, 'q': "1' OR '1'='1"})[:2], (200, ()))
        page = demo_shop.PAGES_BY_PATH['/search']
        _, body = demo_shop.render_route(page, {**self.query, 'min_price': "'<script>alert(1)</script>", 'vs_confirm': 'min_price'})
        self.assertNotIn(b'<script>alert(1)</script>', body)

    def test_live_http_launcher_reaches_confirmed_product_bypass(self) -> None:
        server = demo_shop.build_server(0)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = HTTPConnection('127.0.0.1', server.server_address[1], timeout=5)
        try:
            connection.request('GET', '/_verify?' + urlencode({'path': '/search', 'param': 'min_price'}))
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            location = response.getheader('Location')
            response.read()
            connection.request('GET', location)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            text = response.read().decode('utf-8')
            self.assertIn('class="poc-banner poc-confirmed"', text)
            self.assertIn('12행 조회', text)
            self.assertIn('3행 조회', text)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
