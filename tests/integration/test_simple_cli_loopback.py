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
    def test_simple_cli_blocked_post_json_is_not_executed(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        original_cwd = Path.cwd()
        with TemporaryDirectory(prefix="vulnspider-post-json-cli-") as workdir:
            os.chdir(workdir)
            try:
                with DynamicLoopbackSite() as site:
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        exit_code = cli_module.main(
                            ["-u", site.observed_post_json_url]
                        )
                    primary_requests = site.primary_requests
                    sentinel_requests = site.sentinel_requests
                crawl_text = Path("vulnspider-crawl.json").read_text(
                    encoding="utf-8"
                )
                analysis_text = Path("vulnspider-analysis.json").read_text(
                    encoding="utf-8"
                )
            finally:
                os.chdir(original_cwd)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(sentinel_requests, ())
        self.assertFalse(any(item.method == "POST" for item in primary_requests))
        self.assertEqual(
            sum(
                item.method == "GET" and item.path == "/observed-post-json"
                for item in primary_requests
            ),
            2,
        )
        crawl_report = json.loads(crawl_text)
        analysis_report = json.loads(analysis_text)
        discovery = crawl_report["crawl"]["discovery"]
        endpoints = {
            (item["method"], item["path"]): item
            for item in discovery["endpoints"]
        }
        endpoint = endpoints[("POST", "/api/search")]
        points = [
            item
            for item in discovery["input_points"]
            if item["endpoint_id"] == endpoint["id"]
        ]
        self.assertEqual(
            {(item["name"], item["location"]) for item in points},
            {("keyword", "JSON_BODY"), ("page", "JSON_BODY")},
        )
        readiness = {
            item["input_point_id"]: item
            for item in discovery["probe_readiness"]
        }
        self.assertTrue(
            all(readiness[item["id"]]["status"] == "NOT_READY" for item in points)
        )
        self.assertEqual(analysis_report["ready_context_ids"], [])
        self.assertEqual(analysis_report["executed_input_point_ids"], [])
        self.assertEqual(analysis_report["probe_observations"], [])
        self.assertEqual(
            analysis_report["crawl_reference"]["discovery_snapshot_id"],
            discovery["discovery_snapshot_id"],
        )
        for secret in (
            "phone",
            "POST_AUTHORIZATION_VALUE_SENTINEL",
            "POST_PASSWORD_VALUE_SENTINEL",
            "POST_API_KEY_VALUE_SENTINEL",
            "POST_TOKEN_VALUE_SENTINEL",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        ):
            self.assertNotIn(secret, crawl_text)
            self.assertNotIn(secret, analysis_text)
            self.assertNotIn(secret, stdout.getvalue())
            self.assertNotIn(secret, stderr.getvalue())

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
                    start_url = site.simple_cli_url
                    follow_url = site.simple_cli_follow_url
                    page_b_url = site.simple_cli_page_b_url
                    static_url = (
                        site.simple_cli_url.removesuffix("/simple-cli")
                        + "/simple-cli/static?simple_static=source"
                    )
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
        self.assertNotIn("SIMPLE_GET_AUTH_SECRET", crawl_text)
        self.assertNotIn("SIMPLE_GET_AUTH_SECRET", analysis_text)
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
        self.assertEqual(
            combined.dynamic_crawl.visited_urls,
            (start_url, follow_url, static_url, page_b_url),
        )
        self.assertEqual(
            [page.depth for page in combined.dynamic_crawl.pages],
            [0, 1, 1, 2],
        )
        self.assertEqual(
            [page.parent_url for page in combined.dynamic_crawl.pages],
            [None, start_url, start_url, follow_url],
        )
        combined.discovery.validate()
        dynamic_input_ids = {
            point.id for point in combined.dynamic_crawl.discovery.input_points
        }
        self.assertTrue(
            dynamic_input_ids
            <= {point.id for point in combined.discovery.input_points}
        )
        dynamic_source_urls = {
            provenance.source_url
            for provenance in combined.dynamic_crawl.discovery.crawl_provenance
        }
        self.assertTrue({start_url, follow_url, page_b_url} <= dynamic_source_urls)
        crawl_discovery = crawl_report["crawl"]["discovery"]
        crawl_input_ids = {
            item["id"] for item in crawl_discovery["input_points"]
        }
        self.assertEqual(
            set(analysis_report["crawl_reference"]["input_point_ids"]),
            crawl_input_ids,
        )
        self.assertEqual(
            analysis_report["crawl_reference"]["discovery_snapshot_id"],
            crawl_discovery["discovery_snapshot_id"],
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
        self.assertTrue(
            {
                "page_a_form",
                "page_b_form",
                "simple_dynamic",
                "simple_page_b",
            }
            <= dynamic_names
        )
        input_ids_by_name = {
            point.name: point.id for point in combined.discovery.input_points
        }
        multi_page_input_ids = {
            input_ids_by_name["page_a_form"],
            input_ids_by_name["page_b_form"],
            input_ids_by_name["simple_dynamic"],
            input_ids_by_name["simple_page_b"],
        }
        self.assertTrue(
            multi_page_input_ids
            <= set(analysis_report["executed_input_point_ids"])
        )
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
        self.assertIn(
            DynamicNetworkReason.PASSIVE_SAME_ORIGIN_FETCH_XHR,
            {
                event.reason
                for event in audit.events
                if event.decision == DynamicNetworkDecisionKind.ALLOW
            },
        )

        requested_paths = {request.path for request in primary_requests}
        self.assertIn("/simple-cli.js", requested_paths)
        self.assertIn("/simple-cli.css", requested_paths)
        self.assertIn("/simple-cli/follow", requested_paths)
        self.assertIn("/simple-cli/page-b", requested_paths)
        self.assertIn("/simple-cli/static", requested_paths)
        request_counts = {
            (method, path): sum(
                1
                for request in primary_requests
                if request.method == method and request.path == path
            )
            for method, path in (
                ("GET", "/simple-allowed-fetch"),
                ("GET", "/simple-allowed-xhr"),
                ("GET", "/simple-allowed-private"),
                ("HEAD", "/simple-allowed-head"),
                ("POST", "/simple-denied-post-fetch"),
            )
        }
        endpoint_by_id = {item.id: item for item in combined.discovery.endpoints}
        network_points = tuple(
            point
            for point in combined.discovery.input_points
            if endpoint_by_id[point.endpoint_id].path
            in {"/simple-allowed-fetch", "/simple-allowed-xhr"}
        )
        self.assertEqual(
            sorted((point.name, point.occurrence_index) for point in network_points),
            [
                ("category", None),
                ("keyword", None),
                ("page", None),
                ("tag", 0),
                ("tag", 1),
            ],
        )
        network_point_ids_by_path = {
            path: {
                point.id
                for point in network_points
                if endpoint_by_id[point.endpoint_id].path == path
            }
            for path in ("/simple-allowed-fetch", "/simple-allowed-xhr")
        }
        observations_by_path = {
            path: [
                observation
                for observation in analysis.probe_observations
                if observation.input_point_id in point_ids
            ]
            for path, point_ids in network_point_ids_by_path.items()
        }
        self.assertEqual(len(observations_by_path["/simple-allowed-fetch"]), 2)
        self.assertEqual(len(observations_by_path["/simple-allowed-xhr"]), 3)
        for observations in observations_by_path.values():
            for observation in observations:
                plan = observation.probe_plan
                self.assertEqual(
                    observation.baseline_response.request_id,
                    plan.baseline_request.id,
                )
                self.assertEqual(
                    observation.probe_response.request_id,
                    plan.probe_request.id,
                )
                self.assertEqual(observation.baseline_response.request_role, "baseline")
                self.assertEqual(observation.probe_response.request_role, "probe")
                self.assertEqual(observation.baseline_response.probe_plan_id, plan.id)
                self.assertEqual(observation.probe_response.probe_plan_id, plan.id)
        self.assertEqual(
            request_counts[("GET", "/simple-allowed-fetch")],
            1 + 2 * len(observations_by_path["/simple-allowed-fetch"]),
        )
        self.assertEqual(
            request_counts[("GET", "/simple-allowed-xhr")],
            1 + 2 * len(observations_by_path["/simple-allowed-xhr"]),
        )
        self.assertEqual(request_counts[("GET", "/simple-allowed-private")], 1)
        self.assertEqual(request_counts[("HEAD", "/simple-allowed-head")], 1)
        self.assertEqual(request_counts[("POST", "/simple-denied-post-fetch")], 0)
        self.assertFalse(
            requested_paths
            & {
                "/simple-denied-events",
                "/simple-denied-socket",
                "/simple-denied-frame",
                "/simple-denied-post",
                "/simple-denied-post-fetch",
                "/simple-denied-popup",
            }
        )
        self.assertFalse(any(request.method == "POST" for request in primary_requests))
        self.assertEqual(sentinel_requests, ())
        self.assertFalse(any(SENTINEL in request.raw_target for request in primary_requests))
        self.assertTrue(
            {
                "/simple-allowed-fetch",
                "/simple-allowed-xhr",
                "/simple-allowed-private",
            }
            <= {endpoint.path for endpoint in combined.discovery.endpoints}
        )
        self.assertFalse(
            {"/simple-allowed-head", "/simple-denied-post-fetch"}
            & {endpoint.path for endpoint in combined.discovery.endpoints}
        )
        private_endpoint = next(
            item
            for item in combined.discovery.endpoints
            if item.path == "/simple-allowed-private"
        )
        private_point = next(
            item
            for item in combined.discovery.input_points
            if item.endpoint_id == private_endpoint.id
        )
        self.assertEqual((private_point.name, private_point.baseline_value), ("page", None))
        private_readiness = next(
            item
            for item in combined.discovery.probe_readiness
            if item.input_point_id == private_point.id
        )
        self.assertEqual(private_readiness.status.value, "NOT_READY")
        self.assertNotIn(
            private_point.id,
            analysis_report["executed_input_point_ids"],
        )
        self.assertFalse(
            any(
                item["input_point_id"] == private_point.id
                for item in analysis_report["probe_observations"]
            )
        )
        private_crawl_readiness = next(
            item
            for item in crawl_discovery["probe_readiness"]
            if item["input_point_id"] == private_point.id
        )
        self.assertEqual(private_crawl_readiness["status"], "NOT_READY")


if __name__ == "__main__":
    unittest.main()
