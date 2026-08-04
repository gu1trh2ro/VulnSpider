from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from unittest.mock import patch

from tests.integration.dynamic_loopback_site import DynamicLoopbackSite
import vulnspider.cli as cli_module
from vulnspider.discovery import (
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
)
from vulnspider.pipeline import AnalysisResult


SENTINEL = "SIMPLE_SECRET_SENTINEL_51af"


class SimpleDynamicCliLoopbackTests(unittest.TestCase):
    def test_simple_cli_real_chromium_policy(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        captured: list[AnalysisResult] = []
        real_analyze_url = cli_module.analyze_url

        def capture_analysis(*args: Any, **kwargs: Any) -> AnalysisResult:
            analysis = real_analyze_url(*args, **kwargs)
            captured.append(analysis)
            return analysis

        original_cwd = Path.cwd()
        with TemporaryDirectory(prefix="vulnspider-simple-cli-") as workdir:
            os.chdir(workdir)
            try:
                with DynamicLoopbackSite() as site:
                    with (
                        patch.object(
                            cli_module,
                            "analyze_url",
                            new=capture_analysis,
                        ),
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                    ):
                        exit_code = cli_module.main(["-u", site.simple_cli_url])
                    primary_requests = site.primary_requests
                    sentinel_requests = site.sentinel_requests
                    follow_url = site.simple_cli_follow_url
                crawl_path = Path(workdir) / "vulnspider-crawl.json"
                analysis_path = Path(workdir) / "vulnspider-analysis.json"
                crawl_text = crawl_path.read_text(encoding="utf-8")
                analysis_text = analysis_path.read_text(encoding="utf-8")
                crawl_report = json.loads(crawl_text)
                analysis_report = json.loads(analysis_text)
            finally:
                os.chdir(original_cwd)

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(stdout.getvalue().splitlines()), 3)
        self.assertIn("mode=dynamic", stdout.getvalue())
        self.assertIn("vulnspider-crawl.json", stdout.getvalue())
        self.assertIn("vulnspider-analysis.json", stdout.getvalue())
        self.assertNotIn(SENTINEL, stdout.getvalue())
        self.assertNotIn(SENTINEL, stderr.getvalue())
        self.assertNotIn(SENTINEL, crawl_text)
        self.assertNotIn(SENTINEL, analysis_text)
        self.assertEqual(crawl_report["report_kind"], "crawl")
        self.assertEqual(crawl_report["crawl_mode"], "combined")
        self.assertEqual(crawl_report["completion"], "COMPLETE")
        self.assertFalse(crawl_report["degraded"])
        self.assertNotIn("probe_observations", crawl_report)
        self.assertNotIn("feature_vectors", crawl_report)
        self.assertNotIn("scoring_results", crawl_report)
        self.assertNotIn("candidates", crawl_report)
        self.assertEqual(analysis_report["report_kind"], "analysis")
        self.assertEqual(analysis_report["summary"]["top_k_requested"], 10)
        self.assertTrue(analysis_report["ready_context_ids"])
        self.assertTrue(analysis_report["executed_input_point_ids"])
        self.assertTrue(analysis_report["probe_observations"])
        self.assertTrue(analysis_report["feature_vectors"])
        self.assertTrue(analysis_report["scoring_results"])

        analysis = captured[0]
        combined = analysis.combined_result
        self.assertIsNotNone(combined)
        assert combined is not None
        self.assertNotIn(SENTINEL, repr(analysis))
        self.assertNotIn(
            SENTINEL,
            json.dumps(combined.to_dict(), sort_keys=True),
        )
        self.assertIn(follow_url, combined.dynamic_crawl.visited_urls)
        crawl_discovery = crawl_report["crawl"]["discovery"]
        crawl_input_ids = {
            item["id"] for item in crawl_discovery["input_points"]
        }
        self.assertEqual(
            set(analysis_report["crawl_reference"]["input_point_ids"]),
            crawl_input_ids,
        )
        self.assertTrue(
            set(analysis_report["executed_input_point_ids"]) <= crawl_input_ids
        )
        for observation in analysis_report["probe_observations"]:
            self.assertIn(observation["input_point_id"], crawl_input_ids)
            self.assertEqual(
                observation["probe_plan"]["input_point_id"],
                observation["input_point_id"],
            )
            self.assertTrue(observation["response_pair_ids"])
        static_names = {
            item["name"]
            for item in crawl_report["crawl"]["static_crawl"]["discovery"][
                "input_points"
            ]
        }
        dynamic_names = {
            item["name"]
            for item in crawl_report["crawl"]["dynamic_crawl"]["discovery"][
                "input_points"
            ]
        }
        self.assertIn("simple_static", static_names)
        self.assertNotIn("simple_dynamic", static_names)
        self.assertIn("simple_dynamic", dynamic_names)
        audit = combined.dynamic_crawl.browser_audit
        self.assertTrue(audit.cleanup_complete)
        self.assertGreaterEqual(audit.websocket_attempt_count, 1)
        self.assertEqual(
            audit.websocket_attempt_count,
            audit.websocket_blocked_count,
        )
        self.assertEqual(audit.websocket_connected_count, 0)
        self.assertGreaterEqual(audit.eventsource_attempt_count, 1)
        self.assertEqual(
            audit.eventsource_attempt_count,
            audit.eventsource_blocked_count,
        )
        self.assertGreaterEqual(audit.popup_attempt_count, 1)
        self.assertGreaterEqual(audit.child_frame_document_blocked_count, 1)
        blocked_reasons = {
            event.reason
            for event in audit.events
            if event.decision == DynamicNetworkDecisionKind.BLOCK
        }
        self.assertIn(DynamicNetworkReason.REQUEST_NOT_AUTHORIZED, blocked_reasons)
        self.assertIn(DynamicNetworkReason.NON_GET_METHOD, blocked_reasons)
        self.assertIn(DynamicNetworkReason.NON_PRIMARY_PAGE, blocked_reasons)
        self.assertIn(DynamicNetworkReason.EVENTSOURCE_DENIED, blocked_reasons)
        self.assertIn(DynamicNetworkReason.WEBSOCKET_DENIED, blocked_reasons)

        requested_paths = {request.path for request in primary_requests}
        self.assertIn("/simple-cli.js", requested_paths)
        self.assertIn("/simple-cli.css", requested_paths)
        self.assertIn("/simple-cli/follow", requested_paths)
        self.assertIn("/simple-cli/static", requested_paths)
        self.assertFalse(
            requested_paths
            & {
                "/simple-denied-fetch",
                "/simple-denied-xhr",
                "/simple-denied-events",
                "/simple-denied-socket",
                "/simple-denied-frame",
                "/simple-denied-post",
                "/simple-denied-popup",
            }
        )
        self.assertFalse(any(request.method == "POST" for request in primary_requests))
        self.assertEqual(sentinel_requests, ())
        self.assertFalse(any(SENTINEL in request.raw_target for request in primary_requests))


if __name__ == "__main__":
    unittest.main()
