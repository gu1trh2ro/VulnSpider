from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnspider import cli
from vulnspider.discovery import (
    StaticCrawlerRequest,
    StaticCrawlerResponse,
    StaticCrawlerTransportError,
    extract_static_html,
)
from vulnspider.domain import HttpMethod, RequestInstance
from vulnspider.observation import TransportResponse
from vulnspider.pipeline import analyze_discovery_result


ROOT_URL = "http://127.0.0.1/"


@dataclass
class SinglePageCrawlerTransport:
    html: str
    requests: list[StaticCrawlerRequest] = field(default_factory=list)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        self.requests.append(request)
        return StaticCrawlerResponse(
            status_code=200,
            body=self.html.encode("utf-8"),
            content_type="text/html",
            encoding="utf-8",
        )


@dataclass
class FailingCrawlerTransport:
    requests: list[StaticCrawlerRequest] = field(default_factory=list)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        self.requests.append(request)
        raise StaticCrawlerTransportError("timeout")


@dataclass
class MarkerTransport:
    requests: list[RequestInstance] = field(default_factory=list)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.requests.append(request)
        marker = next(
            (
                value
                for _name, value in request.query
                if value.startswith("VULNSPIDER_")
            ),
            None,
        )
        body = b"baseline" if marker is None else marker.encode("utf-8")
        return TransportResponse(
            status_code=200,
            body=body,
            elapsed_ms=1.0,
            encoding="utf-8",
        )


class NativePipelineTests(unittest.TestCase):
    def test_canonical_analysis_executes_only_ready_get_contexts(self) -> None:
        discovery = extract_static_html(
            """
            <form method="get" action="/search">
              <input name="q" value="hello">
            </form>
            <form method="post" action="/submit">
              <input name="token" value="one">
            </form>
            <form action="/outer">
              <form action="/nested">
                <input name="incomplete" value="two">
              </form>
            """,
            ROOT_URL,
        ).discovery
        transport = MarkerTransport()

        analysis = analyze_discovery_result(
            discovery,
            top_k=3,
            transport=transport,
        )

        self.assertIsNone(analysis.adapter_result)
        self.assertIs(analysis.discovery_result, discovery)
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(
            {request.method for request in transport.requests},
            {HttpMethod.GET},
        )
        self.assertTrue(
            all("/search?" in request.url for request in transport.requests)
        )
        self.assertTrue(
            any("executes GET request contexts only" in item for item in analysis.warnings)
        )
        self.assertEqual(
            analysis.selection.summary.total_scoring_results,
            2,
        )

    def test_empty_discovery_produces_empty_truthful_selection(self) -> None:
        discovery = extract_static_html(
            '<a href="mailto:test@example.test">mail</a>',
            ROOT_URL,
        ).discovery
        transport = MarkerTransport()

        analysis = analyze_discovery_result(
            discovery,
            top_k=2,
            transport=transport,
        )

        self.assertEqual(transport.requests, [])
        self.assertEqual(analysis.selection.summary.total_scoring_results, 0)
        self.assertEqual(analysis.selection.summary.selected_results, 0)
        self.assertEqual(analysis.selection.selected, ())
        self.assertTrue(
            any(item.startswith("discovery ") for item in analysis.warnings)
        )


class NativeCliTests(unittest.TestCase):
    def _url_args(self, output: Path) -> list[str]:
        return [
            "analyze",
            "--url",
            ROOT_URL,
            "--top-k",
            "2",
            "--output",
            str(output),
        ]

    def test_url_input_writes_json_and_html_without_submitting_post(self) -> None:
        crawler_transport = SinglePageCrawlerTransport(
            """
            <form method="get" action="/search">
              <input name="q" value="hello">
            </form>
            <form method="post" action="/submit">
              <input name="token" value="one">
            </form>
            """
        )
        probe_transport = MarkerTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            json_path = directory / "report.json"
            html_path = directory / "report.html"
            args = self._url_args(json_path)
            args.extend(
                [
                    "--html-output",
                    str(html_path),
                    "--max-pages",
                    "1",
                    "--max-depth",
                    "0",
                    "--max-requests",
                    "1",
                    "--timeout-seconds",
                    "1.5",
                    "--max-redirects",
                    "0",
                ]
            )

            exit_code = cli.main(
                args,
                transport=probe_transport,
                crawler_transport=crawler_transport,
            )

            report = json.loads(json_path.read_text(encoding="utf-8"))
            html = html_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(crawler_transport.requests), 1)
        self.assertEqual(crawler_transport.requests[0].method, HttpMethod.GET)
        self.assertEqual(len(probe_transport.requests), 2)
        self.assertEqual(
            {request.method for request in probe_transport.requests},
            {HttpMethod.GET},
        )
        self.assertEqual(report["summary"]["total_scoring_results"], 2)
        self.assertEqual(report["summary"]["selected_results"], 2)
        self.assertTrue(report["candidates"])
        self.assertIn("VulnSpider report", html)
        for candidate in report["candidates"]:
            self.assertIn(candidate["candidate_id"], html)
            self.assertIn(candidate["feature_vector_id"], html)
        self.assertTrue(
            any("executes GET request contexts only" in item for item in report["warnings"])
        )

    def test_crawler_failure_is_a_warning_not_a_finding(self) -> None:
        crawler_transport = FailingCrawlerTransport()
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"

            exit_code = cli.main(
                self._url_args(output),
                transport=MarkerTransport(),
                crawler_transport=crawler_transport,
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["summary"]["total_scoring_results"], 0)
        self.assertTrue(
            any("TRANSPORT_TIMEOUT" in item for item in report["warnings"])
        )

    def test_cli_rejects_ambiguous_or_missing_source(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as both_sources:
                cli.main(
                    [
                        "analyze",
                        "--input",
                        "records.json",
                        "--url",
                        ROOT_URL,
                        "--top-k",
                        "1",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(both_sources.exception.code, 2)

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing_source:
                cli.main(
                    [
                        "analyze",
                        "--top-k",
                        "1",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(missing_source.exception.code, 2)

    def test_cli_rejects_invalid_url_and_nonpositive_budgets(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "report.json"
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--url",
                        "not-an-absolute-url",
                        "--top-k",
                        "1",
                        "--output",
                        str(output),
                    ],
                    crawler_transport=SinglePageCrawlerTransport(""),
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("absolute HTTP", error_output.getvalue())
            self.assertFalse(output.exists())

        for option in ("--max-pages", "--max-requests", "--timeout-seconds"):
            with self.subTest(option=option), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as invalid_budget:
                    cli.main(
                        [
                            "analyze",
                            "--url",
                            ROOT_URL,
                            "--top-k",
                            "1",
                            "--output",
                            "report.json",
                            option,
                            "0",
                        ]
                    )
            self.assertEqual(invalid_budget.exception.code, 2)

    def test_cli_rejects_native_policy_options_for_legacy_input(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            records = directory / "records.json"
            records.write_text("[]", encoding="utf-8")
            error_output = io.StringIO()

            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(records),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                        "--max-pages",
                        "1",
                    ],
                    transport=MarkerTransport(),
                )

        self.assertEqual(exit_code, 2)
        self.assertIn("require --url", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
