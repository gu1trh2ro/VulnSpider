from __future__ import annotations

import socket
import unittest
from urllib.request import urlopen

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
from vulnspider.discovery import (
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicBrowserPolicy,
    DynamicCapabilityError,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    DynamicResourceGrant,
    DynamicResourceKind,
    PlaywrightDynamicBrowser,
    preflight_dynamic_browser,
)


class DynamicLoopbackHarnessTests(unittest.TestCase):
    def test_binds_ephemeral_loopback_port_records_requests_and_closes(self) -> None:
        site = DynamicLoopbackSite()
        with site:
            primary_port = site.primary_port
            sentinel_port = site.sentinel_port
            self.assertGreater(primary_port, 0)
            self.assertGreater(sentinel_port, 0)
            self.assertNotEqual(primary_port, sentinel_port)
            self.assertTrue(all(site.server_threads_alive))
            with urlopen(site.root_url, timeout=1.0) as response:
                body = response.read().decode("utf-8")
            self.assertIn("initial-marker", body)
            self.assertEqual(
                [(item.method, item.path) for item in site.primary_requests],
                [("GET", "/")],
            )
            self.assertEqual(site.sentinel_requests, ())

        self.assertTrue(site.cleanup_complete)
        self.assertEqual(site.server_threads_alive, (False, False))
        for port in (primary_port, sentinel_port):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            finally:
                probe.close()

    def test_test_exception_still_closes_both_servers(self) -> None:
        site = DynamicLoopbackSite()
        with self.assertRaisesRegex(RuntimeError, "test failure"):
            with site:
                raise RuntimeError("test failure")
        self.assertTrue(site.cleanup_complete)
        self.assertEqual(site.server_threads_alive, (False, False))


class DynamicBrowserLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            preflight_dynamic_browser()
        except DynamicCapabilityError as exc:
            raise unittest.SkipTest(
                f"real Chromium unavailable: {exc.code.value}"
            ) from None

    def test_real_chromium_executes_javascript_and_blocks_external_transports(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.root_url,
                resource_grants=(
                    DynamicResourceGrant(
                        DynamicResourceKind.SCRIPT,
                        site.allowed_script_url,
                    ),
                ),
            )

            def operation(session):
                navigated_url = session.navigate()
                session.wait_for_selector("#dynamic-marker")
                return navigated_url, session.text_content("#dynamic-marker")

            result = PlaywrightDynamicBrowser().run(authority, operation)

            self.assertEqual(result.value, (site.root_url, "javascript-executed"))
            primary_paths = [item.path for item in site.primary_requests]
            self.assertIn("/", primary_paths)
            self.assertIn("/allowed.js", primary_paths)
            self.assertEqual(site.sentinel_requests, ())

        audit = result.audit
        self.assertTrue(audit.cleanup_complete)
        self.assertEqual(audit.playwright_started, 1)
        self.assertEqual(audit.playwright_stopped, 1)
        self.assertEqual(audit.browsers_launched, 1)
        self.assertEqual(audit.browsers_closed, 1)
        self.assertEqual(audit.contexts_created, 1)
        self.assertEqual(audit.contexts_closed, 1)
        self.assertEqual(audit.pages_created, 1)
        self.assertEqual(audit.pages_closed, 1)
        self.assertGreaterEqual(audit.http_allowed_count, 2)
        self.assertGreaterEqual(audit.http_blocked_count, 1)
        self.assertEqual(audit.websocket_attempt_count, 1)
        self.assertEqual(audit.websocket_blocked_count, 1)
        self.assertEqual(audit.websocket_connected_count, 0)
        self.assertTrue(
            any(
                event.decision == DynamicNetworkDecisionKind.BLOCK
                and event.reason == DynamicNetworkReason.REQUEST_NOT_AUTHORIZED
                and event.path == "/blocked.js"
                for event in audit.events
            )
        )
        self.assertTrue(
            any(
                event.reason == DynamicNetworkReason.WEBSOCKET_DENIED
                and event.path == "/socket"
                for event in audit.events
            )
        )

    def test_real_navigation_timeout_preserves_error_and_cleanup_audit(
        self,
    ) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(root_url=site.slow_url)
            try:
                with self.assertRaises(DynamicBrowserError) as raised:
                    PlaywrightDynamicBrowser().run(
                        authority,
                        lambda session: session.navigate(),
                        policy=DynamicBrowserPolicy(
                            navigation_timeout_seconds=0.1,
                            request_decision_budget=10,
                        ),
                    )
            finally:
                site.release_slow.set()

            self.assertTrue(site.slow_started.wait(timeout=1.0))
            self.assertIn(
                "/slow",
                [item.path for item in site.primary_requests],
            )

        error = raised.exception
        self.assertEqual(
            error.code,
            DynamicBrowserErrorCode.NAVIGATION_TIMEOUT,
        )
        self.assertEqual(error.cleanup_error_codes, ())
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertEqual(error.audit.pages_closed, 1)
        self.assertEqual(error.audit.contexts_closed, 1)
        self.assertEqual(error.audit.browsers_closed, 1)
        self.assertEqual(error.audit.playwright_stopped, 1)

    def test_real_shared_transport_budget_stops_websocket_flood(self) -> None:
        with DynamicLoopbackSite() as site:
            authority = DynamicRequestAuthority(
                root_url=site.websocket_budget_url,
            )
            with self.assertRaises(DynamicBrowserError) as raised:
                PlaywrightDynamicBrowser().run(
                    authority,
                    lambda session: session.navigate(),
                    policy=DynamicBrowserPolicy(
                        navigation_timeout_seconds=1.0,
                        request_decision_budget=2,
                    ),
                )

            self.assertIn(
                "/websocket-budget",
                [item.path for item in site.primary_requests],
            )
            self.assertEqual(site.sentinel_requests, ())

        error = raised.exception
        self.assertEqual(
            error.code,
            DynamicBrowserErrorCode.REQUEST_DECISION_BUDGET_EXHAUSTED,
        )
        self.assertIsNotNone(error.audit)
        assert error.audit is not None
        self.assertTrue(error.audit.cleanup_complete)
        self.assertEqual(error.audit.pages_created, 1)
        self.assertEqual(error.audit.pages_closed, 1)
        self.assertGreaterEqual(error.audit.websocket_attempt_count, 2)
        self.assertEqual(
            error.audit.websocket_blocked_count,
            error.audit.websocket_attempt_count,
        )
        self.assertEqual(error.audit.websocket_connected_count, 0)
        self.assertEqual(error.audit.request_decision_overflow_count, 1)
        processed_decisions = (
            error.audit.http_allowed_count
            + error.audit.http_blocked_count
            + error.audit.websocket_attempt_count
        )
        self.assertLessEqual(processed_decisions, 3)


if __name__ == "__main__":
    unittest.main()
