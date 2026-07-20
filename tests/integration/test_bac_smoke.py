from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnspider import cli
from vulnspider.domain import RequestInstance
from vulnspider.observation import TransportResponse


@dataclass
class BacDemoTransport:
    """Mirrors demo_target_server.py's /account and /product handlers so the
    real CLI end-to-end path is exercised for both BAC check kinds without a
    live socket."""

    requests: list[RequestInstance] = field(default_factory=list)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.requests.append(request)

        if "/account" in request.url:
            # Vulnerable on purpose: identical content regardless of cookies.
            body = b"<html>Account overview: balance $4,821.00</html>"
            return TransportResponse(status_code=200, body=body, elapsed_ms=1.0, encoding="utf-8")

        if "/product" in request.url:
            id_value = dict(request.query).get("id", "")
            if id_value.isdigit():
                body = f"<html>Product #{id_value} full details here</html>".encode()
                return TransportResponse(
                    status_code=200, body=body, elapsed_ms=1.0, encoding="utf-8"
                )
            body = f"{id_value} SQL syntax error".encode()
            return TransportResponse(status_code=500, body=body, elapsed_ms=1.0, encoding="utf-8")

        return TransportResponse(status_code=200, body=b"baseline", elapsed_ms=1.0, encoding="utf-8")


class BrokenAccessControlSmokeTests(unittest.TestCase):
    def _write_records(self, directory: Path, records: object) -> Path:
        path = directory / "records.json"
        path.write_text(json.dumps(records), encoding="utf-8")
        return path

    def test_cli_selects_bac_candidates_alongside_injection_candidates(self) -> None:
        records = [
            {
                "link": "http://127.0.0.1/account?tab=overview",
                "host": "127.0.0.1",
                "query_params": '{"tab":"overview"}',
                "input_fields": "[]",
                "cookies": '{"session":"demo-token"}',
                "source": "bac_fixture",
            },
            {
                "link": "http://127.0.0.1/product?id=41",
                "host": "127.0.0.1",
                "query_params": '{"id":"41"}',
                "input_fields": "[]",
                "source": "bac_fixture",
            },
        ]
        transport = BacDemoTransport()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            input_path = self._write_records(directory, records)
            output_path = directory / "report.json"
            html_output_path = directory / "report.html"

            exit_code = cli.main(
                [
                    "analyze",
                    "--input",
                    str(input_path),
                    "--top-k",
                    "10",
                    "--output",
                    str(output_path),
                    "--html-output",
                    str(html_output_path),
                ],
                transport=transport,
            )

            self.assertEqual(exit_code, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            html_text = html_output_path.read_text(encoding="utf-8")

        self.assertEqual(set(report["categories"]), {"SQLI", "REFLECTED_XSS", "BROKEN_ACCESS_CONTROL"})
        categories = {item["category"] for item in report["candidates"]}
        self.assertIn("BROKEN_ACCESS_CONTROL", categories)
        self.assertIn("INJECTION", categories)

        check_kinds = {
            item["check_kind"]
            for item in report["candidates"]
            if item["category"] == "BROKEN_ACCESS_CONTROL"
        }
        self.assertEqual(check_kinds, {"CREDENTIAL_STRIP", "IDENTIFIER_SUBSTITUTION"})

        top_candidate = report["candidates"][0]
        self.assertEqual(top_candidate["rank"], 1)
        self.assertEqual(top_candidate["category"], "BROKEN_ACCESS_CONTROL")
        self.assertEqual(top_candidate["raw_rank_score"], top_candidate["raw_rank_score_max"])
        self.assertEqual(top_candidate["selection_priority"], 1.0)

        self.assertIn("Broken Access Control", html_text)
        self.assertIn("Executed requests", html_text)
        for misleading_name in ("confidence", "probability", "confirmed"):
            self.assertNotIn(misleading_name, html_text.lower())

    def test_cli_produces_no_access_candidates_when_no_credentials_or_ids(self) -> None:
        records = [
            {
                "link": "http://127.0.0.1/search?q=book",
                "host": "127.0.0.1",
                "query_params": '{"q":"book"}',
                "input_fields": "[]",
                "source": "bac_fixture",
            }
        ]
        transport = BacDemoTransport()
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
                    "5",
                    "--output",
                    str(output_path),
                ],
                transport=transport,
            )
            self.assertEqual(exit_code, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))

        categories = {item["category"] for item in report["candidates"]}
        self.assertEqual(categories, {"INJECTION"})
        self.assertEqual(report["summary"]["total_scoring_results"], 2)

    def test_cli_rejects_non_loopback_record_before_any_bac_probe(self) -> None:
        records = [
            {
                "link": "http://example.test/account?tab=overview",
                "query_params": '{"tab":"overview"}',
                "input_fields": "[]",
                "cookies": '{"session":"demo-token"}',
            }
        ]
        transport = BacDemoTransport()
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


if __name__ == "__main__":
    unittest.main()
