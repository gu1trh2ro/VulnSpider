from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest

from vulnspider.discovery import DynamicCrawler, DynamicCrawlPolicy, DynamicRequestAuthority


class SearchActionNavigationTests(unittest.TestCase):
    def test_full_document_search_navigation_survives_supervised_browser(self) -> None:
        requests: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                body = (
                    b'<input type="search" id="search">'
                    b'<script>search.addEventListener("keydown", e => {'
                    b'if(e.key === "Enter") location.href="/lab/search?q="+encodeURIComponent(search.value);'
                    b'});</script>'
                    if self.path == "/lab/" else
                    b'<form action="/lab/search"><input name="q" value="seed"></form>'
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            root = f"http://127.0.0.1:{server.server_port}/lab/"
            for max_depth in (0, 2):
                with self.subTest(max_depth=max_depth):
                    requests.clear()
                    result = DynamicCrawler().crawl(
                        root, DynamicCrawlPolicy(max_depth=max_depth, max_route_actions=1),
                        DynamicRequestAuthority(root, allow_rendered_navigation=True),
                    )
                    self.assertIn("/lab/search?q=vulnspider-probe", requests)
                    self.assertEqual(
                        any(point.name == "q" for point in result.discovery.input_points),
                        max_depth > 0,
                    )
                    if max_depth == 0:
                        self.assertEqual(result.termination_reason.value, "DEPTH_BUDGET_EXHAUSTED")
                    self.assertFalse(any(w.code == "DYNAMIC_OPERATIONAL_FAILURE" for w in result.warnings))
                    self.assertTrue(result.browser_audit.cleanup_complete)
                    self.assertLessEqual(result.navigation_attempts, 8)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
