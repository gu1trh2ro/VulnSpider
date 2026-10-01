from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
import pickle
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vulnspider.cli as cli
import vulnspider.discovery.dynamic_browser as browser
import vulnspider.discovery.dynamic_crawler as crawler_module
from vulnspider.discovery import (
    DynamicBrowserPolicy, DynamicRequestAuthority,
    DynamicCrawlCompletion, DynamicCrawlTerminationReason,
)
from vulnspider.scope.loopback import (
    LoopbackSafetyError, authorized_http_origin,
    current_authorized_http_origin, require_loopback_http_url,
)
from tests.unit.test_loopback_safety import (
    RecordingCrawlerTransport, RecordingProbeTransport,
)
from tests.unit.test_combined_pipeline_cli import _combined_result
from tests.unit.test_simple_cli import ROOT_URL, _native_analysis, _pipeline_stub


class AuthorizedDemoScopeTests(unittest.TestCase):
    def test_exact_origin_and_reset_even_after_error(self) -> None:
        root = "https://permitted.example/lab/"
        with self.assertRaises(RuntimeError):
            with authorized_http_origin(root):
                require_loopback_http_url("https://PERMITTED.example:443/search?q=x")
                for other in (
                    "http://permitted.example/", "https://permitted.example:444/",
                    "https://sub.permitted.example/", "https://permitted.example.evil/",
                    "http://127.0.0.1/", "https://user@permitted.example/",
                ):
                    with self.subTest(other=other), self.assertRaises(LoopbackSafetyError):
                        require_loopback_http_url(other)
                raise RuntimeError("reset test")
        self.assertIsNone(current_authorized_http_origin())
        with self.assertRaises(LoopbackSafetyError):
            require_loopback_http_url(root)
        require_loopback_http_url("http://127.0.0.1/")

    def test_nested_and_ipv6_scope(self) -> None:
        with authorized_http_origin("https://permitted.example/"):
            with authorized_http_origin("http://[::1]:8080/"):
                self.assertEqual(current_authorized_http_origin(), "http://[::1]:8080/")
            self.assertEqual(current_authorized_http_origin(), "https://permitted.example:443/")

    def test_external_cli_is_opt_in_before_any_transport(self) -> None:
        with TemporaryDirectory() as directory:
            args = ["analyze", "--url", "https://permitted.example/", "--top-k", "1",
                    "--output", str(Path(directory) / "analysis.json")]
            for opt_in, expected in ((False, 2), (True, 0)):
                crawler = RecordingCrawlerTransport()
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    result = cli.main(
                        args + (["--allow-external"] if opt_in else []),
                        crawler_transport=crawler, transport=RecordingProbeTransport(),
                    )
                self.assertEqual(result, expected)
                self.assertEqual(bool(crawler.requests), opt_in)
                self.assertIsNone(current_authorized_http_origin())

    def test_simple_request_budget_default_and_override(self) -> None:
        for value in (None, 350):
            args = cli.build_parser().parse_args(
                ["-u", "http://127.0.0.1/"] + (
                    [] if value is None else ["--dynamic-request-decision-budget", str(value)]
                )
            )
            policy = cli._dynamic_policy_from_args(cli._simple_analysis_args(args), simple_mode=True)
            self.assertEqual(policy.request_decision_budget, value or 200)

    def test_partial_pages_admitted_but_operational_failure_stays_blocked(self) -> None:
        combined = _combined_result()
        dynamic = replace(
            combined.dynamic_crawl, completion=DynamicCrawlCompletion.DEGRADED,
            termination_reason=DynamicCrawlTerminationReason.PAGE_BUDGET_EXHAUSTED,
        )
        partial = replace(combined, dynamic_crawl=dynamic)
        self.assertTrue(cli._bounded_dynamic_partial(partial))
        failure = replace(dynamic, termination_reason=DynamicCrawlTerminationReason.COMPLETED_WITH_FAILURES)
        self.assertFalse(cli._bounded_dynamic_partial(replace(combined, dynamic_crawl=failure)))

    def test_worker_reenters_and_resets_explicit_scope(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.pickle"
            target = Path(directory) / "output.pickle"
            source.write_bytes(pickle.dumps(("https://permitted.example/", None, None,
                                            "https://permitted.example:443/")))

            def run(*args: object) -> str:
                require_loopback_http_url("https://permitted.example/search")
                with self.assertRaises(LoopbackSafetyError):
                    require_loopback_http_url("https://other.example/")
                return "scoped"

            with patch.object(crawler_module.sys, "argv", ["worker", str(source), str(target)]), \
                    patch.object(crawler_module.DynamicCrawler, "crawl", side_effect=run):
                crawler_module._dynamic_worker_main()
            self.assertEqual(pickle.loads(target.read_bytes()), ("ok", "scoped"))
            self.assertIsNone(current_authorized_http_origin())

    def test_bounded_partial_writes_reports_and_opens_requested_dashboard(self) -> None:
        combined = _combined_result()
        partial = replace(combined, dynamic_crawl=replace(
            combined.dynamic_crawl, completion=DynamicCrawlCompletion.DEGRADED,
            termination_reason=DynamicCrawlTerminationReason.PAGE_BUDGET_EXHAUSTED,
        ))
        analysis = replace(
            _native_analysis(), combined_result=partial,
            discovery_result=partial.discovery, crawl_result=partial.static_crawl,
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "analysis.json"
            dashboard = root / "report.html"
            stdout, stderr = StringIO(), StringIO()
            with patch.object(cli, "analyze_url", side_effect=_pipeline_stub(analysis)), \
                    patch.object(cli, "_open_report", return_value=True) as opened, \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main([
                    "-u", ROOT_URL, "--crawl-output", str(root / "crawl.json"),
                    "-o", str(output), "--html-output", str(dashboard), "--open",
                ])
            self.assertEqual(code, 4)
            self.assertTrue(output.is_file())
            self.assertTrue(dashboard.is_file())
            opened.assert_called_once_with(dashboard)
            self.assertIn("[PARTIAL]", stdout.getvalue())
            self.assertIn("partial analysis was written", stderr.getvalue())
            self.assertNotIn("analysis was not written", stderr.getvalue())


class ActionNavigationGuardTests(unittest.TestCase):
    def test_action_grant_is_temporary_get_only_and_scoped(self) -> None:
        cases = (
            ("http://127.0.0.1/lab/search?q=vulnspider-probe", "GET", True, True),
            ("http://127.0.0.1/lab/search?q=vulnspider-probe", "GET", False, False),
            ("http://127.0.0.1/lab/search?q=vulnspider-probe", "POST", True, False),
            ("http://127.0.0.1/outside?q=vulnspider-probe", "GET", True, False),
            ("http://127.0.0.1/lab/logout?q=vulnspider-probe", "GET", True, False),
            ("http://other.example/lab/search?q=vulnspider-probe", "GET", True, False),
            ("http://127.0.0.1/lab/search?q=unrelated", "GET", True, False),
        )
        for url, method, active, allowed in cases:
            with self.subTest(url=url, method=method, active=active):
                page = object()
                guard = browser._RouteGuard(
                    DynamicRequestAuthority("http://127.0.0.1/lab/", allow_rendered_navigation=True),
                    DynamicBrowserPolicy(), browser._AuditRecorder(event_limit=50), lambda: None,
                )
                guard.set_primary_page(page)
                if active:
                    guard.begin_route_action("vulnspider-probe")
                route = SimpleNamespace(fetch=lambda **kwargs: SimpleNamespace(
                    status=200, headers={}, dispose=lambda: None),
                    fulfill=lambda **kwargs: None, abort=lambda **kwargs: None)
                with patch.object(guard, "_fulfill_allowed_http") as fetch:
                    guard.handle_http(route, SimpleNamespace(
                        url=url, method=method, resource_type="document",
                        frame=SimpleNamespace(page=page, parent_frame=None),
                    ))
                self.assertEqual(fetch.called, allowed)
                guard.end_route_action()
                self.assertFalse(guard._allows_action_navigation(url))


if __name__ == "__main__":
    unittest.main()
