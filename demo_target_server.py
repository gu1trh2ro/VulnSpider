"""Minimal stdlib-only loopback test target for manually exercising the real
`vulnspider` CLI end-to-end. Not part of the repo -- a throwaway fixture
server, mirroring what tests/integration's fake transport does but as an actual
listening HTTP server.

Run:  python demo_target_server.py     ->  http://127.0.0.1:8899

It advertises realistic-looking routes with a mix of vulnerability flavours so
the scan is not one-note. Each query parameter's ``kind`` drives its behaviour:

- ``sqli_error`` -> a non-numeric value blows up with a DB-specific SQL error
  (MySQL / PostgreSQL / Oracle / MSSQL / SQLite / SQLSTATE, chosen per route).
- ``sqli_blind`` -> no error, but the row count (and body length) changes with
  the value, so only the length signal separates it.
- ``xss_raw``    -> value reflected un-escaped in element text.
- ``xss_attr``   -> value reflected un-escaped inside an HTML attribute.
- ``xss_escaped``/``safe`` -> value reflected but HTML-escaped (not exploitable).
- ``bac``        -> returns private data with no auth check (IDOR). The scanner
  has no BAC observation/scoring pipeline yet (ADR-014), so these input points
  emit no injection signal and stay unranked -- realistic for the app, but a
  known blind spot for the tool.

The index page links every input point so the static crawler discovers them.
"""
from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

HOST, PORT = "127.0.0.1", 8899

# route -> {query parameter: kind}
_SPEC: dict[str, dict[str, str]] = {
    "/search": {"q": "xss_raw", "sort": "sqli_blind", "lang": "safe"},
    "/product": {"id": "sqli_error", "ref": "xss_attr", "qty": "safe"},
    "/login": {"return_to": "xss_raw", "user": "sqli_error"},
    "/profile": {"name": "xss_escaped", "uid": "sqli_error"},
    "/orders": {"order_id": "sqli_blind", "status": "safe"},
    "/comment": {"text": "xss_raw", "post_id": "sqli_error"},
    "/report": {"year": "sqli_blind", "format": "safe"},
    "/article": {"title": "xss_attr", "id": "sqli_error"},
    "/catalog": {"price": "sqli_blind", "tag": "xss_raw", "color": "safe"},
    "/feedback": {"message": "xss_raw", "email": "safe"},
    "/news": {"q": "xss_attr", "id": "sqli_error", "category": "safe"},
    "/download": {"file": "sqli_error", "type": "safe"},
    "/settings": {"redirect": "xss_raw", "theme": "safe"},
    "/admin/user": {"id": "bac"},
    "/account": {"owner": "bac"},
}

_SEED = {
    "sqli_error": "1",
    "sqli_blind": "1",
    "xss_raw": "hello",
    "xss_attr": "hello",
    "xss_escaped": "hello",
    "safe": "en",
    "bac": "2",
}
_VULN_KINDS = frozenset({"sqli_error", "sqli_blind", "xss_raw", "xss_attr"})

# One phrasing per SQL dialect; the scanner's sql_error_pattern matches them all.
_SQL_ERRORS = (
    "You have an error in your SQL syntax near '{v}'",
    "SQLSTATE[42000]: syntax error at or near '{v}'",
    "PostgreSQL: unterminated quoted string at or near '{v}'",
    "ORA-00933: SQL command not properly ended near '{v}'",
    "Microsoft SQL Server: Unclosed quotation mark after '{v}'",
    "SQLite error: near '{v}': syntax error",
)

INPUT_POINTS = sum(len(params) for params in _SPEC.values())
VULNERABLE_INPUT_POINTS = sum(
    kind in _VULN_KINDS for params in _SPEC.values() for kind in params.values()
)
BAC_INPUT_POINTS = sum(
    kind == "bac" for params in _SPEC.values() for kind in params.values()
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # keep the console quiet

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)

        if parts.path in ("/", "/index.html"):
            self._respond(200, self._index())
            return

        route = _SPEC.get(parts.path)
        if route is None:
            self._respond(404, b"not found")
            return

        present = sorted(param for param in route if param in query)
        if not present:
            self._respond(200, b"<html><body>ok</body></html>")
            return

        param = present[0]
        status, body = self._render(
            route[param], query[param][0], salt=f"{parts.path}:{param}"
        )
        self._respond(status, body)

    def _render(self, kind: str, value: str, *, salt: str) -> tuple[int, bytes]:
        if kind == "sqli_error":
            if value.isdigit():
                return 200, f"<html><body>item {escape(value)}</body></html>".encode()
            phrasing = _SQL_ERRORS[sum(map(ord, salt)) % len(_SQL_ERRORS)]
            message = phrasing.format(v=escape(value))
            return 500, f"<html><body>Warning: {message}</body></html>".encode()
        if kind == "sqli_blind":
            # No error text; the row count (hence body length) depends on the
            # value, so only response_length_diff_ratio separates it.
            rows = 6 if value.isdigit() else 1
            listing = "".join(f"<li>result {index}</li>" for index in range(rows))
            return 200, f"<html><body><ul>{listing}</ul></body></html>".encode()
        if kind == "xss_raw":
            return 200, f"<html><body>Results for: {value}</body></html>".encode()
        if kind == "xss_attr":
            return 200, (
                f'<html><body><input type="text" value="{value}"></body></html>'
            ).encode()
        if kind == "bac":
            # IDOR: private data returned with no authentication check. No
            # injection signal (no reflection, no error), so the scanner does
            # not rank it -- realistic app bug, tool blind spot (ADR-014).
            return 200, (
                "<html><body>account alice: alice@corp.example, role=admin "
                "(no authorization check)</body></html>"
            ).encode()
        # xss_escaped / safe: reflected but HTML-escaped.
        return 200, f"<html><body>Results for: {escape(value)}</body></html>".encode()

    def _index(self) -> bytes:
        items = []
        for path in sorted(_SPEC):
            for param in sorted(_SPEC[path]):
                seed = _SEED[_SPEC[path][param]]
                items.append(
                    f'<li><a href="{path}?{param}={seed}">'
                    f"{escape(path)}?{escape(param)}</a></li>"
                )
        return (
            "<html><body><h1>demo target</h1><ul>"
            + "".join(items)
            + "</ul></body></html>"
        ).encode()

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(
        f"demo target on http://{HOST}:{PORT} "
        f"({INPUT_POINTS} input points, {VULNERABLE_INPUT_POINTS} injection-"
        f"vulnerable, {BAC_INPUT_POINTS} BAC/IDOR) (Ctrl+C to stop)"
    )
    server.serve_forever()
