from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, TextIO
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for import_root in (ROOT, SRC):
    import_text = str(import_root)
    if import_text not in sys.path:
        sys.path.insert(0, import_text)

from vulnspider.discovery import (  # noqa: E402
    DynamicBrowserCapability,
    DynamicCapabilityError,
    preflight_dynamic_browser,
)


SUITE_BROWSER_LOOPBACK = "browser-loopback"


@dataclass(frozen=True, slots=True)
class BrowserManifestCase:
    case_id: str
    test_id: str
    invariant: str
    required: bool = True


BROWSER_LOOPBACK_CASES = (
    BrowserManifestCase(
        "base-js-http-ws",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_chromium_executes_javascript_and_blocks_external_transports"
        ),
        "JavaScript executes while unauthorized HTTP and WebSocket stay local.",
    ),
    BrowserManifestCase(
        "eventsource-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_eventsource_attempts_are_blocked"
        ),
        "Same- and cross-authority EventSource attempts are blocked pre-transport.",
    ),
    BrowserManifestCase(
        "child-frame-block",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_child_frames_are_blocked_and_detached"
        ),
        "Child documents never complete and attached frames are detached.",
    ),
    BrowserManifestCase(
        "popup-guard-cleanup",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_popup_is_guarded_and_cleaned"
        ),
        "Popup traffic is guarded and every created page is closed.",
    ),
    BrowserManifestCase(
        "http-redirect-same",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_same_authority_http_redirect_completes"
        ),
        "An explicitly authorized same-authority redirect completes locally.",
    ),
    BrowserManifestCase(
        "http-redirect-cross",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_cross_authority_http_redirect_is_blocked"
        ),
        "A cross-authority redirect is denied before sentinel transport.",
    ),
    BrowserManifestCase(
        "js-location-same",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_same_authority_js_location_completes"
        ),
        "An explicitly authorized same-authority JavaScript location completes.",
    ),
    BrowserManifestCase(
        "js-location-cross",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_cross_authority_js_location_is_blocked"
        ),
        "A cross-authority JavaScript location is denied before transport.",
    ),
    BrowserManifestCase(
        "navigation-timeout-cleanup",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_navigation_timeout_preserves_error_and_cleanup_audit"
        ),
        "Navigation timeout preserves its typed error and complete cleanup audit.",
    ),
    BrowserManifestCase(
        "shared-budget-flood",
        (
            "tests.integration.test_dynamic_browser_loopback."
            "DynamicBrowserLoopbackTests."
            "test_real_shared_transport_budget_stops_websocket_flood"
        ),
        "The shared HTTP/WebSocket decision budget stops a WebSocket flood.",
    ),
)

MANIFESTS = {SUITE_BROWSER_LOOPBACK: BROWSER_LOOPBACK_CASES}


@dataclass(frozen=True, slots=True)
class GateEvaluation:
    required_expected: int
    required_executed: int
    required_skipped: int
    required_failed: int
    manifest_missing: int
    preflight_passed: bool
    passed: bool


def validate_manifest(cases: Sequence[BrowserManifestCase]) -> None:
    if not cases:
        raise ValueError("dynamic gate manifest must not be empty")
    case_ids: set[str] = set()
    test_ids: set[str] = set()
    for case in cases:
        if not case.required:
            raise ValueError("browser-loopback manifest cases must be required")
        if not case.case_id or not case.test_id or not case.invariant:
            raise ValueError("dynamic gate manifest fields must not be empty")
        if case.case_id in case_ids:
            raise ValueError(f"duplicate dynamic gate case id: {case.case_id}")
        if case.test_id in test_ids:
            raise ValueError(f"duplicate dynamic gate test id: {case.test_id}")
        case_ids.add(case.case_id)
        test_ids.add(case.test_id)


def _iter_tests(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


def load_manifest_suite(
    cases: Sequence[BrowserManifestCase],
) -> tuple[unittest.TestSuite, tuple[str, ...]]:
    loader = unittest.TestLoader()
    combined = unittest.TestSuite()
    missing: list[str] = []
    for case in cases:
        loaded = loader.loadTestsFromName(case.test_id)
        tests = tuple(_iter_tests(loaded))
        if len(tests) != 1 or tests[0].id() != case.test_id:
            missing.append(case.test_id)
            continue
        combined.addTest(tests[0])
    return combined, tuple(missing)


def evaluate_gate(
    *,
    preflight_passed: bool,
    required_expected: int,
    tests_run: int,
    required_skipped: int,
    required_failed: int,
    manifest_missing: int,
) -> GateEvaluation:
    required_executed = max(0, tests_run - required_skipped)
    passed = (
        preflight_passed
        and required_expected > 0
        and manifest_missing == 0
        and tests_run == required_expected
        and required_executed == required_expected
        and required_skipped == 0
        and required_failed == 0
    )
    return GateEvaluation(
        required_expected=required_expected,
        required_executed=required_executed,
        required_skipped=required_skipped,
        required_failed=required_failed,
        manifest_missing=manifest_missing,
        preflight_passed=preflight_passed,
        passed=passed,
    )


def _failure_count(result: unittest.TestResult) -> int:
    return (
        len(result.failures)
        + len(result.errors)
        + len(getattr(result, "expectedFailures", ()))
        + len(getattr(result, "unexpectedSuccesses", ()))
    )


def _write_summary(
    stream: TextIO,
    *,
    capability: DynamicBrowserCapability | None,
    preflight_code: str,
    evaluation: GateEvaluation,
) -> None:
    version = (
        capability.playwright_version if capability is not None else "unavailable"
    )
    print(f"PLAYWRIGHT_VERSION={version}", file=stream)
    print(f"PREFLIGHT={preflight_code}", file=stream)
    print(
        f"REQUIRED_EXPECTED={evaluation.required_expected}",
        file=stream,
    )
    print(
        f"REQUIRED_EXECUTED={evaluation.required_executed}",
        file=stream,
    )
    print(
        f"REQUIRED_SKIPPED={evaluation.required_skipped}",
        file=stream,
    )
    print(
        f"REQUIRED_FAILED={evaluation.required_failed}",
        file=stream,
    )
    print(f"MANIFEST_MISSING={evaluation.manifest_missing}", file=stream)
    print(f"FINAL={'PASS' if evaluation.passed else 'FAIL'}", file=stream)


def run_gate(
    cases: Sequence[BrowserManifestCase] = BROWSER_LOOPBACK_CASES,
    *,
    preflight_fn: Callable[[], DynamicBrowserCapability] = (
        preflight_dynamic_browser
    ),
    test_runner: Callable[[unittest.TestSuite], unittest.TestResult] | None = None,
    stream: TextIO | None = None,
) -> GateEvaluation:
    output = stream or sys.stdout
    validate_manifest(cases)
    required_expected = len(cases)
    capability: DynamicBrowserCapability | None = None
    preflight_code = "FAIL:NOT_RUN"
    result: unittest.TestResult | None = None
    missing: tuple[str, ...] = ()

    original_cwd = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="vulnspider-dynamic-gate-") as workdir:
        os.chdir(workdir)
        try:
            try:
                capability = preflight_fn()
            except DynamicCapabilityError as exc:
                preflight_code = f"FAIL:{exc.code.value}"
            except Exception:  # noqa: BLE001 - gate output remains secret-free.
                preflight_code = "FAIL:UNEXPECTED_PREFLIGHT_ERROR"
            else:
                preflight_code = "PASS"
                suite, missing = load_manifest_suite(cases)
                if not missing:
                    if test_runner is None:
                        result = unittest.TextTestRunner(
                            stream=output,
                            verbosity=2,
                        ).run(suite)
                    else:
                        result = test_runner(suite)
        finally:
            os.chdir(original_cwd)

    tests_run = result.testsRun if result is not None else 0
    required_skipped = len(result.skipped) if result is not None else 0
    required_failed = _failure_count(result) if result is not None else 0
    evaluation = evaluate_gate(
        preflight_passed=capability is not None,
        required_expected=required_expected,
        tests_run=tests_run,
        required_skipped=required_skipped,
        required_failed=required_failed,
        manifest_missing=len(missing),
    )
    _write_summary(
        output,
        capability=capability,
        preflight_code=preflight_code,
        evaluation=evaluation,
    )
    return evaluation


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a strict real-Chromium Dynamic Discovery gate.",
    )
    parser.add_argument(
        "--suite",
        choices=tuple(MANIFESTS),
        required=True,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    evaluation = run_gate(MANIFESTS[args.suite])
    return 0 if evaluation.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
