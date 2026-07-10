from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from spiderman import cli
from spiderman.domain import RequestInstance
from spiderman.observation import TransportResponse


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
                if value.startswith("SPIDERMAN_")
            ),
            None,
        )
        body = b"baseline"
        if marker is not None:
            body = f"{marker} SQL syntax error".encode("utf-8")
        return TransportResponse(
            status_code=200,
            body=body,
            elapsed_ms=1.0,
            encoding="utf-8",
        )


class V01EndToEndSmokeTests(unittest.TestCase):
    def _write_records(self, directory: Path, records: object) -> Path:
        path = directory / "records.json"
        path.write_text(json.dumps(records), encoding="utf-8")
        return path

    def test_cli_smoke_runs_real_v01_boundaries_to_top_k_json(self) -> None:
        records = [
            {
                "link": "http://127.0.0.1/search?q=book",
                "parent": "http://127.0.0.1/",
                "depth": 1,
                "host": "127.0.0.1",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
                "source": "legacy_fixture",
            }
        ]
        transport = MarkerTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            output_path = directory / "report.json"

            exit_code = cli.main(
                [
                    "analyze",
                    "--input",
                    str(input_path),
                    "--top-k",
                    "1",
                    "--output",
                    str(output_path),
                ],
                transport=transport,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(transport.requests), 2)
            report_text = output_path.read_text(encoding="utf-8")
            report = json.loads(report_text)

        self.assertEqual(report["summary"]["total_scoring_results"], 2)
        self.assertEqual(report["summary"]["rankable_results"], 2)
        self.assertEqual(report["summary"]["unrankable_results"], 0)
        self.assertEqual(report["summary"]["selected_results"], 1)
        self.assertEqual(len(report["candidates"]), 1)
        candidate = report["candidates"][0]
        self.assertEqual(candidate["rank"], 1)
        self.assertEqual(candidate["vulnerability_type"], "REFLECTED_XSS")
        self.assertEqual(candidate["raw_rank_score"], 45.0)
        self.assertEqual(candidate["raw_rank_score_max"], 45.0)
        self.assertEqual(candidate["selection_priority"], 1.0)
        self.assertTrue(candidate["evidence"])
        self.assertTrue(
            all(
                item["candidate_id"] == candidate["candidate_id"]
                and item["feature_vector_id"] == candidate["feature_vector_id"]
                and item["vulnerability_type"] == candidate["vulnerability_type"]
                for item in candidate["evidence"]
            )
        )

    def test_cli_rejects_invalid_top_k_and_missing_required_input(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as invalid_k:
                cli.main(
                    [
                        "analyze",
                        "--input",
                        "records.json",
                        "--top-k",
                        "0",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(invalid_k.exception.code, 2)

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing_input:
                cli.main(
                    [
                        "analyze",
                        "--top-k",
                        "1",
                        "--output",
                        "report.json",
                    ]
                )
        self.assertEqual(missing_input.exception.code, 2)

    def test_cli_rejects_malformed_adapter_input_without_traceback(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = directory / "malformed.json"
            input_path.write_text("not-json", encoding="utf-8")
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                    ],
                    transport=MarkerTransport(),
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("not valid JSON", error_output.getvalue())
        self.assertNotIn("Traceback", error_output.getvalue())

        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, [{"query_params": "{}"}])
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                    ],
                    transport=MarkerTransport(),
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("requires a non-empty link", error_output.getvalue())
        self.assertNotIn("Traceback", error_output.getvalue())

    def test_cli_rejects_non_loopback_record(self) -> None:
        records = [
            {
                "link": "http://example.test/search?q=book",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
            }
        ]
        transport = MarkerTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            error_output = io.StringIO()
            with redirect_stderr(error_output):
                exit_code = cli.main(
                    [
                        "analyze",
                        "--input",
                        str(input_path),
                        "--top-k",
                        "1",
                        "--output",
                        str(directory / "report.json"),
                    ],
                    transport=transport,
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("loopback", error_output.getvalue())
        self.assertEqual(transport.requests, [])

    def test_version_command_regression(self) -> None:
        standard_output = io.StringIO()
        with redirect_stdout(standard_output):
            with self.assertRaises(SystemExit) as version_exit:
                cli.main(["--version"])
        self.assertEqual(version_exit.exception.code, 0)
        self.assertEqual(standard_output.getvalue().strip(), "spiderman 0.1.0")


if __name__ == "__main__":
    unittest.main()
