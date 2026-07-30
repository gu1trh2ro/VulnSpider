"""Deterministic loopback-only browser fixture for Dynamic Discovery tests."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Lock, Thread
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class LoopbackRequest:
    method: str
    path: str


class _QuietThreadingHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return


class _ServerHandle:
    def __init__(
        self,
        server: _QuietThreadingHttpServer,
        *,
        name: str,
    ) -> None:
        self.server = server
        self.ready = Event()
        self.thread = Thread(
            target=self._serve,
            name=name,
            daemon=True,
        )
        self.closed = False

    def _serve(self) -> None:
        self.ready.set()
        self.server.serve_forever(poll_interval=0.01)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=1.0):
            self.close()
            raise RuntimeError("loopback server did not become ready")

    def close(self) -> bool:
        if self.closed:
            return not self.thread.is_alive()
        self.closed = True
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)
        return not self.thread.is_alive()


class DynamicLoopbackSite:
    """Two loopback servers: one authorized site and one blocked sentinel."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._primary_requests: list[LoopbackRequest] = []
        self._sentinel_requests: list[LoopbackRequest] = []
        self.slow_started = Event()
        self.release_slow = Event()
        self._primary: _ServerHandle | None = None
        self._sentinel: _ServerHandle | None = None
        self.root_url = ""
        self.allowed_script_url = ""
        self.slow_url = ""
        self.websocket_budget_url = ""
        self.sentinel_origin = ""
        self.cleanup_complete = False

    @property
    def primary_requests(self) -> tuple[LoopbackRequest, ...]:
        with self._lock:
            return tuple(self._primary_requests)

    @property
    def sentinel_requests(self) -> tuple[LoopbackRequest, ...]:
        with self._lock:
            return tuple(self._sentinel_requests)

    @property
    def primary_port(self) -> int:
        if self._primary is None:
            raise RuntimeError("loopback site is not started")
        return self._primary.server.server_port

    @property
    def sentinel_port(self) -> int:
        if self._sentinel is None:
            raise RuntimeError("loopback site is not started")
        return self._sentinel.server.server_port

    @property
    def server_threads_alive(self) -> tuple[bool, bool]:
        return (
            self._primary is not None and self._primary.thread.is_alive(),
            self._sentinel is not None and self._sentinel.thread.is_alive(),
        )

    def __enter__(self) -> "DynamicLoopbackSite":
        site = self

        class SentinelHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site._record(site._sentinel_requests, "GET", self.path)
                self._send(500, b"sentinel must not be reached", "text/plain")

            def do_POST(self) -> None:
                site._record(site._sentinel_requests, "POST", self.path)
                self._send(500, b"sentinel must not be reached", "text/plain")

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        sentinel_server = _QuietThreadingHttpServer(
            ("127.0.0.1", 0),
            SentinelHandler,
        )
        self._sentinel = _ServerHandle(
            sentinel_server,
            name="vulnspider-dynamic-sentinel",
        )
        self._sentinel.start()
        self.sentinel_origin = f"http://127.0.0.1:{self.sentinel_port}"

        class PrimaryHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site._record(site._primary_requests, "GET", self.path)
                route = urlsplit(self.path).path
                if route == "/":
                    html = f"""<!doctype html>
                    <html>
                      <head><meta charset="utf-8"></head>
                      <body>
                        <div id="initial-marker">initial</div>
                        <script src="/allowed.js"></script>
                        <script>
                          const blocked = document.createElement("script");
                          blocked.src = "{site.sentinel_origin}/blocked.js";
                          document.head.appendChild(blocked);
                          window.blockedSocket = new WebSocket(
                            "ws://127.0.0.1:{site.sentinel_port}/socket"
                          );
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/allowed.js":
                    script = b"""
                    const marker = document.createElement("div");
                    marker.id = "dynamic-marker";
                    marker.textContent = "javascript-executed";
                    document.body.appendChild(marker);
                    """
                    self._send(
                        200,
                        script,
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route == "/websocket-budget":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          for (let index = 0; index < 1000; index += 1) {{
                            new WebSocket(
                              "ws://127.0.0.1:{site.sentinel_port}/budget-" +
                              index
                            );
                          }}
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/slow":
                    site.slow_started.set()
                    site.release_slow.wait(timeout=5.0)
                    self._send(
                        200,
                        b"<html><body>released</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                self._send(404, b"missing", "text/plain")

            def do_POST(self) -> None:
                site._record(site._primary_requests, "POST", self.path)
                self._send(500, b"POST must not execute", "text/plain")

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        primary_server = _QuietThreadingHttpServer(
            ("127.0.0.1", 0),
            PrimaryHandler,
        )
        self._primary = _ServerHandle(
            primary_server,
            name="vulnspider-dynamic-primary",
        )
        try:
            self._primary.start()
        except Exception:
            self._sentinel.close()
            raise
        self.root_url = f"http://127.0.0.1:{self.primary_port}/"
        self.allowed_script_url = (
            f"http://127.0.0.1:{self.primary_port}/allowed.js"
        )
        self.slow_url = f"http://127.0.0.1:{self.primary_port}/slow"
        self.websocket_budget_url = (
            f"http://127.0.0.1:{self.primary_port}/websocket-budget"
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool:
        self.close()
        if exc_type is None and not self.cleanup_complete:
            raise RuntimeError("loopback server cleanup did not complete")
        return False

    def close(self) -> None:
        if self.cleanup_complete:
            return
        self.release_slow.set()
        primary_closed = self._primary is None or self._primary.close()
        sentinel_closed = self._sentinel is None or self._sentinel.close()
        self.cleanup_complete = primary_closed and sentinel_closed

    def _record(
        self,
        log: list[LoopbackRequest],
        method: str,
        path: str,
    ) -> None:
        with self._lock:
            log.append(LoopbackRequest(method=method, path=path))
