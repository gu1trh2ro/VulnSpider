from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import vulnspider.cli as cli_module
from vulnspider.discovery import DynamicCrawlPolicy, DynamicResourceKind
from vulnspider.pipeline import AnalysisResult
from vulnspider.selection import select_top_k


ROOT_URL = "http://127.0.0.1:8080/"


def _empty_analysis(*, top_k: int = 10) -> AnalysisResult:
    return AnalysisResult(
        adapter_result=None,
        scoring_results=(),
        selection=select_top_k((), k=top_k),
        warnings=(),
        probe_observations=(),
        elapsed_seconds=0.0,
    )


class SimpleCliTests(unittest.TestCase):
    def test_simple_url_calls_dynamic_pipeline_and_writes_default_json(self) -> None:
        stdout = StringIO()
        with TemporaryDirectory() as temporary_directory:
            original_cwd = Path.cwd()
            os.chdir(temporary_directory)
            try:
                with (
                    patch.object(
                        cli_module,
                        "analyze_url",
                        return_value=_empty_analysis(),
                    ) as analyze,
                    redirect_stdout(stdout),
                ):
                    exit_code = cli_module.main(["-u", ROOT_URL])
                output = Path("vulnspider-result.json")
                report = json.loads(output.read_text(encoding="utf-8"))
            finally:
                os.chdir(original_cwd)

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["summary"]["top_k_requested"], 10)
        analyze.assert_called_once()
        args, kwargs = analyze.call_args
        self.assertEqual(args, (ROOT_URL,))
        self.assertEqual(kwargs["top_k"], 10)
        self.assertIsInstance(kwargs["dynamic_policy"], DynamicCrawlPolicy)
        authority = kwargs["dynamic_authority"]
        self.assertTrue(authority.allow_rendered_navigation)
        self.assertTrue(authority.allow_passive_same_origin_resources)
        self.assertIn("mode=dynamic", stdout.getvalue())
        self.assertIn("vulnspider-result.json", stdout.getvalue())

    def test_simple_output_override_and_exact_advanced_grants(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "result.json"
            script = ROOT_URL + "app.js"
            navigation = ROOT_URL + "advanced"
            with patch.object(
                cli_module,
                "analyze_url",
                return_value=_empty_analysis(),
            ) as analyze:
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "-o",
                        str(output),
                        "--dynamic-allow-navigation",
                        navigation,
                        "--dynamic-allow-resource",
                        f"script={script}",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output.is_file())
            authority = analyze.call_args.kwargs["dynamic_authority"]
            self.assertIn(navigation, authority.navigation_urls)
            self.assertIn(
                (DynamicResourceKind.SCRIPT, script),
                {(grant.kind, grant.url) for grant in authority.resource_grants},
            )

    def test_static_only_reuses_native_static_pipeline(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "static.json"
            with patch.object(
                cli_module,
                "analyze_url",
                return_value=_empty_analysis(),
            ) as analyze:
                exit_code = cli_module.main(
                    ["-u", ROOT_URL, "--static-only", "-o", str(output)]
                )

        self.assertEqual(exit_code, 0)
        kwargs = analyze.call_args.kwargs
        self.assertIsNone(kwargs["dynamic_authority"])
        self.assertIsNone(kwargs["dynamic_policy"])
        self.assertIsNone(kwargs["dynamic_crawler"])

    def test_static_only_rejects_dynamic_grants_without_output(self) -> None:
        stderr = StringIO()
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "must-not-exist.json"
            with redirect_stderr(stderr):
                exit_code = cli_module.main(
                    [
                        "-u",
                        ROOT_URL,
                        "--static-only",
                        "--dynamic-allow-navigation",
                        ROOT_URL + "next",
                        "-o",
                        str(output),
                    ]
                )

        self.assertEqual(exit_code, 2)
        self.assertFalse(output.exists())
        self.assertIn("cannot be combined", stderr.getvalue())

    def test_help_displays_simple_usage(self) -> None:
        help_text = cli_module.build_parser().format_help()

        self.assertIn("vulnspider -u http://127.0.0.1:8080/", help_text)
        self.assertIn("-u SIMPLE_URL", help_text)
        self.assertIn("--static-only", help_text)
        self.assertIn("vulnspider-result.json", help_text)


if __name__ == "__main__":
    unittest.main()
