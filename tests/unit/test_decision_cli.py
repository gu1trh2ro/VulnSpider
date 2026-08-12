from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from vulnspider.cli import main
from vulnspider.cli_decision import DecisionCLIError, build_decision_candidates
from vulnspider.corpus.ground_truth import (
    GroundTruthKey,
    ground_truth_from_entries,
    write_ground_truth,
)
from vulnspider.discovery import (
    StaticCrawlerRequest,
    StaticCrawlerResponse,
)
from vulnspider.domain import RequestInstance
from vulnspider.observation.executor import TransportResponse

ROOT_URL = "http://127.0.0.1/"

# One safe route and one route whose probe triggers a SQL error, so the fixture
# exercises both label classes through the real pipeline.
INDEX_HTML = """
<html><body>
  <a href="/product?id=1">product</a>
  <a href="/search?q=hello">search</a>
</body></html>
"""


@dataclass
class FixtureCrawlerTransport:
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
            body=INDEX_HTML.encode("utf-8"),
            content_type="text/html",
            encoding="utf-8",
        )


@dataclass
class FixtureProbeTransport:
    """`/product` looks injectable; `/search` reflects but is otherwise inert."""

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
        if marker is None:
            return TransportResponse(
                status_code=200,
                body=b"<html><body>baseline content here</body></html>",
                elapsed_ms=1.0,
                encoding="utf-8",
            )
        if "/product" in request.url:
            body = (
                "<html><body>You have an error in your SQL syntax near "
                f"'{marker}'</body></html>"
            ).encode("utf-8")
            return TransportResponse(
                status_code=500, body=body, elapsed_ms=1.0, encoding="utf-8"
            )
        body = f"<html><body>Results for {marker}</body></html>".encode("utf-8")
        return TransportResponse(
            status_code=200, body=body, elapsed_ms=1.0, encoding="utf-8"
        )


def _run(argv: list[str]) -> int:
    return main(
        argv,
        transport=FixtureProbeTransport(),
        crawler_transport=FixtureCrawlerTransport(),
    )


def _ground_truth_file(directory: Path) -> Path:
    path = directory / "gt.json"
    entries = []
    for path_name, parameter, sqli, xss in (
        ("/product", "id", True, False),
        ("/search", "q", False, True),
    ):
        for vulnerability_type, label in (
            ("SQLI", sqli),
            ("REFLECTED_XSS", xss),
        ):
            entries.append(
                (
                    GroundTruthKey(
                        application_id="fixture",
                        method="GET",
                        canonical_path=path_name,
                        parameter_location="QUERY",
                        parameter_name=parameter,
                        vulnerability_type=vulnerability_type,
                    ),
                    label,
                )
            )
    write_ground_truth(ground_truth_from_entries(entries), path)
    return path


class FrozenSurfaceTests(unittest.TestCase):
    """ADR-025 adds commands; it must not disturb the frozen ones."""

    def test_analyze_and_simple_mode_still_parse(self) -> None:
        from vulnspider.cli import build_parser

        parser = build_parser()
        simple = parser.parse_args(["-u", ROOT_URL])
        self.assertIsNone(simple.command)
        self.assertEqual(simple.simple_url, ROOT_URL)
        analyze = parser.parse_args(
            ["analyze", "--url", ROOT_URL, "--top-k", "5", "--output", "x.json"]
        )
        self.assertEqual(analyze.command, "analyze")
        self.assertEqual(analyze.top_k, 5)
        self.assertEqual(analyze.url, ROOT_URL)

    def test_analyze_still_requires_its_own_flags(self) -> None:
        from vulnspider.cli import build_parser

        with self.assertRaises(SystemExit):
            build_parser().parse_args(["analyze", "--url", ROOT_URL])

    def test_new_commands_are_registered(self) -> None:
        from vulnspider.cli import build_parser

        parser = build_parser()
        self.assertEqual(
            parser.parse_args(
                ["decide", "--url", ROOT_URL, "-o", "d.json"]
            ).command,
            "decide",
        )
        self.assertEqual(
            parser.parse_args(
                [
                    "corpus",
                    "fit",
                    "--corpus",
                    "c.jsonl",
                    "-o",
                    "m.json",
                ]
            ).corpus_command,
            "fit",
        )


class DecideCommandTests(unittest.TestCase):
    def test_decide_writes_a_report_within_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            self.assertEqual(
                _run(["decide", "--url", ROOT_URL, "--budget", "12", "-o", str(output)]),
                0,
            )
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["report_version"], "decision-report-v1")
        self.assertLessEqual(report["budget"]["verification_spent"], 12)
        self.assertIsNone(report["guarantee"])
        self.assertGreater(report["selection"]["candidates_scored"], 0)
        orders = [entry["order"] for entry in report["verification_order"]]
        self.assertEqual(orders, sorted(orders))

    def test_zero_budget_selects_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            self.assertEqual(
                _run(["decide", "--url", ROOT_URL, "--budget", "0", "-o", str(output)]),
                0,
            )
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["verification_order"], [])
        self.assertEqual(report["budget"]["verification_spent"], 0)

    def test_a_bigger_budget_never_finds_less(self) -> None:
        findings = []
        with tempfile.TemporaryDirectory() as directory:
            for budget in (3, 6, 12, 30):
                output = Path(directory) / f"d{budget}.json"
                _run(
                    [
                        "decide",
                        "--url",
                        ROOT_URL,
                        "--budget",
                        str(budget),
                        "-o",
                        str(output),
                    ]
                )
                report = json.loads(output.read_text(encoding="utf-8"))
                findings.append(report["selection"]["expected_findings"])
        self.assertEqual(findings, sorted(findings))

    def test_negative_budget_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            self.assertEqual(
                _run(
                    ["decide", "--url", ROOT_URL, "--budget", "-1", "-o", str(output)]
                ),
                1,
            )
            self.assertFalse(output.exists())

    def test_discount_outside_range_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            self.assertEqual(
                _run(
                    [
                        "decide",
                        "--url",
                        ROOT_URL,
                        "--discount",
                        "1.5",
                        "-o",
                        str(output),
                    ]
                ),
                1,
            )

    def test_missing_model_file_reports_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decision.json"
            self.assertEqual(
                _run(
                    [
                        "decide",
                        "--url",
                        ROOT_URL,
                        "--model",
                        str(Path(directory) / "absent.json"),
                        "-o",
                        str(output),
                    ]
                ),
                1,
            )


class CorpusCommandTests(unittest.TestCase):
    def test_collect_fit_calibrate_decide_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            ground_truth = _ground_truth_file(workspace)
            corpus = workspace / "corpus.jsonl"

            self.assertEqual(
                _run(
                    [
                        "corpus",
                        "collect",
                        "--url",
                        ROOT_URL,
                        "--application-id",
                        "fixture",
                        "--ground-truth",
                        str(ground_truth),
                        "-o",
                        str(corpus),
                    ]
                ),
                0,
            )
            self.assertTrue(corpus.exists())
            lines = [
                line
                for line in corpus.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(lines), 4)

            model = workspace / "model.json"
            self.assertEqual(
                _run(
                    ["corpus", "fit", "--corpus", str(corpus), "-o", str(model)]
                ),
                0,
            )
            payload = json.loads(model.read_text(encoding="utf-8"))
            self.assertEqual(payload["fitting_version"], "corpus-fitting-v1")

            decision = workspace / "decision.json"
            self.assertEqual(
                _run(
                    [
                        "decide",
                        "--url",
                        ROOT_URL,
                        "--budget",
                        "20",
                        "--model",
                        str(model),
                        "-o",
                        str(decision),
                    ]
                ),
                0,
            )
            report = json.loads(decision.read_text(encoding="utf-8"))
        self.assertGreater(report["models"]["SQLI"]["training_samples"], 0)

    def test_collect_appends_across_applications(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            ground_truth = _ground_truth_file(workspace)
            corpus = workspace / "corpus.jsonl"
            for _run_index in range(2):
                self.assertEqual(
                    _run(
                        [
                            "corpus",
                            "collect",
                            "--url",
                            ROOT_URL,
                            "--application-id",
                            "fixture",
                            "--ground-truth",
                            str(ground_truth),
                            "-o",
                            str(corpus),
                            "--append",
                        ]
                    ),
                    0,
                )
            lines = [
                line
                for line in corpus.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        self.assertEqual(len(lines), 8)

    def test_fit_on_an_empty_corpus_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "corpus.jsonl"
            corpus.write_text("", encoding="utf-8")
            self.assertEqual(
                _run(
                    [
                        "corpus",
                        "fit",
                        "--corpus",
                        str(corpus),
                        "-o",
                        str(Path(directory) / "m.json"),
                    ]
                ),
                1,
            )

    def test_calibrate_needs_multiple_applications(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            ground_truth = _ground_truth_file(workspace)
            corpus = workspace / "corpus.jsonl"
            _run(
                [
                    "corpus",
                    "collect",
                    "--url",
                    ROOT_URL,
                    "--application-id",
                    "fixture",
                    "--ground-truth",
                    str(ground_truth),
                    "-o",
                    str(corpus),
                ]
            )
            self.assertEqual(
                _run(
                    [
                        "corpus",
                        "calibrate",
                        "--corpus",
                        str(corpus),
                        "-o",
                        str(workspace / "conformal.json"),
                    ]
                ),
                1,
            )

    def test_target_recall_outside_range_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            corpus = workspace / "corpus.jsonl"
            corpus.write_text("", encoding="utf-8")
            self.assertEqual(
                _run(
                    [
                        "corpus",
                        "calibrate",
                        "--corpus",
                        str(corpus),
                        "--target-recall",
                        "1.0",
                        "-o",
                        str(workspace / "c.json"),
                    ]
                ),
                1,
            )

    def test_unlabeled_candidates_are_skipped_not_defaulted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            partial = workspace / "gt.json"
            write_ground_truth(
                ground_truth_from_entries(
                    (
                        (
                            GroundTruthKey(
                                application_id="fixture",
                                method="GET",
                                canonical_path="/product",
                                parameter_location="QUERY",
                                parameter_name="id",
                                vulnerability_type="SQLI",
                            ),
                            True,
                        ),
                    )
                ),
                partial,
            )
            corpus = workspace / "corpus.jsonl"
            self.assertEqual(
                _run(
                    [
                        "corpus",
                        "collect",
                        "--url",
                        ROOT_URL,
                        "--application-id",
                        "fixture",
                        "--ground-truth",
                        str(partial),
                        "-o",
                        str(corpus),
                    ]
                ),
                0,
            )
            lines = [
                line
                for line in corpus.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        self.assertEqual(len(lines), 1)


class CandidateProjectionTests(unittest.TestCase):
    def test_redundancy_key_groups_by_endpoint(self) -> None:
        from vulnspider.corpus.fitting import prior_family_scorers
        from vulnspider.discovery import CrawlPolicy
        from vulnspider.pipeline import analyze_url

        analysis = analyze_url(
            ROOT_URL,
            top_k=1,
            crawl_policy=CrawlPolicy(),
            crawler_transport=FixtureCrawlerTransport(),
            transport=FixtureProbeTransport(),
        )
        candidates = build_decision_candidates(
            analysis, prior_family_scorers(("SQLI", "REFLECTED_XSS"))
        )
        self.assertTrue(candidates)
        by_key: dict[str, set[str]] = {}
        for candidate in candidates:
            by_key.setdefault(candidate.redundancy_key, set()).add(candidate.family)
        # Both readings of one input point share that endpoint's fingerprint.
        self.assertTrue(
            any(families == {"SQLI", "REFLECTED_XSS"} for families in by_key.values())
        )

    def test_missing_family_model_is_rejected(self) -> None:
        from vulnspider.corpus.fitting import prior_family_scorers
        from vulnspider.discovery import CrawlPolicy
        from vulnspider.pipeline import analyze_url

        analysis = analyze_url(
            ROOT_URL,
            top_k=1,
            crawl_policy=CrawlPolicy(),
            crawler_transport=FixtureCrawlerTransport(),
            transport=FixtureProbeTransport(),
        )
        with self.assertRaises(DecisionCLIError):
            build_decision_candidates(analysis, prior_family_scorers(("SQLI",)))


if __name__ == "__main__":
    unittest.main()
