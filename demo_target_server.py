"""Minimal stdlib-only loopback test target for manually exercising the
real `vulnspider analyze` CLI end-to-end. Not part of the repo -- just a
throwaway fixture server, mirroring what tests/integration's fake
transport does but as an actual listening HTTP server.

Run:  python demo_target_server.py
Serves on http://127.0.0.1:8899

- GET /product?id=...   -> looks SQLi-ish: a marker value makes the
  "backend" blow up with a SQL-error-looking 500 response.
- GET /search?q=...     -> looks XSS-ish: the query value is reflected
  back into the page without escaping.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

HOST, PORT = "127.0.0.1", 8899


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # keep the console quiet

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)

        if parts.path == "/product":
            value = query.get("id", [""])[0]
            if value.isdigit():
                body = f"<html><body>Product #{value}</body></html>".encode()
                self._respond(200, body)
            else:
                body = (
                    f"<html><body>Warning: SQL syntax error near '{value}' "
                    "in query</body></html>"
                ).encode()
                self._respond(500, body)
            return

        if parts.path == "/search":
            value = query.get("q", [""])[0]
            body = f"<html><body>Results for: {value}</body></html>".encode()
            self._respond(200, body)
            return

        self._respond(404, b"not found")

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(f"demo target listening on http://{HOST}:{PORT} (Ctrl+C to stop)")
    server.serve_forever()
