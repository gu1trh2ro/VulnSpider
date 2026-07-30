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
        errors: list[Exception] = []
        try:
            self.server.shutdown()
        except Exception as exc:  # noqa: BLE001 - continue deterministic cleanup.
            errors.append(exc)
        try:
            self.server.server_close()
        except Exception as exc:  # noqa: BLE001 - continue deterministic cleanup.
            errors.append(exc)
        self.thread.join(timeout=2.0)
        if errors:
            raise RuntimeError("loopback server cleanup failed") from errors[0]
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
        self.eventsource_url = ""
        self.iframe_url = ""
        self.popup_url = ""
        self.redirect_same_url = ""
        self.redirect_target_url = ""
        self.redirect_relative_script_url = ""
        self.redirect_cross_url = ""
        self.redirect_cross_intermediate_url = ""
        self.location_same_url = ""
        self.location_target_url = ""
        self.location_cross_url = ""
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
                if route == "/eventsource":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          let failures = 0;
                          function recordFailure() {{
                            failures += 1;
                            if (failures === 2) {{
                              const marker = document.createElement("div");
                              marker.id = "eventsource-marker";
                              marker.textContent = "both-blocked";
                              document.body.appendChild(marker);
                            }}
                          }}
                          const same = new EventSource("/event-stream");
                          same.onerror = recordFailure;
                          const cross = new EventSource(
                            "{site.sentinel_origin}/event-stream"
                          );
                          cross.onerror = recordFailure;
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/event-stream":
                    self._send(
                        200,
                        b"data: unexpected-transport\n\n",
                        "text/event-stream; charset=utf-8",
                    )
                    return
                if route == "/iframe":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <iframe id="same-frame" src="/frame-child"></iframe>
                        <iframe
                          id="cross-frame"
                          src="{site.sentinel_origin}/frame-child"
                        ></iframe>
                        <script>
                          window.addEventListener("load", () => {{
                            document.querySelectorAll("iframe").forEach(
                              (frame) => frame.remove()
                            );
                            const marker = document.createElement("div");
                            marker.id = "iframe-marker";
                            marker.textContent = "children-blocked";
                            document.body.appendChild(marker);
                          }});
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/frame-child":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='child-marker'>"
                            b"unexpected-child</div></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/popup":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          const popup = window.open("about:blank", "_blank");
                          if (popup !== null) {{
                            popup.location.href =
                              "{site.sentinel_origin}/popup-target";
                          }}
                          const marker = document.createElement("div");
                          marker.id = "popup-marker";
                          marker.textContent = "popup-attempted";
                          document.body.appendChild(marker);
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/redirect-same":
                    self._send_redirect("/redirect/final")
                    return
                if route == "/redirect/final":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='redirect-marker'>"
                            b"same-authority</div>"
                            b"<script src='relative.js'></script>"
                            b"</body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/redirect/relative.js":
                    self._send(
                        200,
                        (
                            b"const marker = document.createElement('div');"
                            b"marker.id = 'redirect-relative-marker';"
                            b"marker.textContent = 'target-relative';"
                            b"document.body.appendChild(marker);"
                        ),
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route == "/redirect-cross":
                    self._send_redirect("/redirect/intermediate")
                    return
                if route == "/redirect/intermediate":
                    self._send_redirect(
                        f"{site.sentinel_origin}/redirect-target"
                    )
                    return
                if route == "/location-same":
                    self._send(
                        200,
                        (
                            b"<html><body><script>"
                            b"window.location.replace('/location-target');"
                            b"</script></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/location-target":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='location-marker'>"
                            b"same-authority</div></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/location-cross":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          window.location.replace(
                            "{site.sentinel_origin}/location-target"
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

            def _send_redirect(self, location: str) -> None:
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        try:
            primary_server = _QuietThreadingHttpServer(
                ("127.0.0.1", 0),
                PrimaryHandler,
            )
            self._primary = _ServerHandle(
                primary_server,
                name="vulnspider-dynamic-primary",
            )
            self._primary.start()
        except Exception:
            self._sentinel.close()
            raise
        self.root_url = f"http://127.0.0.1:{self.primary_port}/"
        self.allowed_script_url = (
            f"http://127.0.0.1:{self.primary_port}/allowed.js"
        )
        self.eventsource_url = (
            f"http://127.0.0.1:{self.primary_port}/eventsource"
        )
        self.iframe_url = f"http://127.0.0.1:{self.primary_port}/iframe"
        self.popup_url = f"http://127.0.0.1:{self.primary_port}/popup"
        self.redirect_same_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect-same"
        )
        self.redirect_target_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect/final"
        )
        self.redirect_relative_script_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect/relative.js"
        )
        self.redirect_cross_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect-cross"
        )
        self.redirect_cross_intermediate_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect/intermediate"
        )
        self.location_same_url = (
            f"http://127.0.0.1:{self.primary_port}/location-same"
        )
        self.location_target_url = (
            f"http://127.0.0.1:{self.primary_port}/location-target"
        )
        self.location_cross_url = (
            f"http://127.0.0.1:{self.primary_port}/location-cross"
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
        try:
            self.close()
        except RuntimeError:
            if exc_type is None:
                raise
        if exc_type is None and not self.cleanup_complete:
            raise RuntimeError("loopback server cleanup did not complete")
        return False

    def close(self) -> None:
        if self.cleanup_complete:
            return
        self.release_slow.set()
        errors: list[RuntimeError] = []
        try:
            primary_closed = self._primary is None or self._primary.close()
        except RuntimeError as exc:
            primary_closed = False
            errors.append(exc)
        try:
            sentinel_closed = self._sentinel is None or self._sentinel.close()
        except RuntimeError as exc:
            sentinel_closed = False
            errors.append(exc)
        self.cleanup_complete = primary_closed and sentinel_closed
        if errors:
            raise RuntimeError("loopback site cleanup failed") from errors[0]

    def _record(
        self,
        log: list[LoopbackRequest],
        method: str,
        path: str,
    ) -> None:
        route = urlsplit(path).path
        with self._lock:
            log.append(LoopbackRequest(method=method, path=route))
