from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnspider.discovery import (
    DynamicCapabilityCode,
    DynamicCapabilityError,
    preflight_dynamic_browser,
)


class FakeBrowserContext:
    def route_web_socket(self) -> None:
        pass


class FakeBrowser:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


@dataclass
class FakeChromium:
    executable_path: str
    launch_error: Exception | None = None
    browser: FakeBrowser | None = None

    def __post_init__(self) -> None:
        self.launch_calls: list[dict[str, object]] = []

    def launch(self, **kwargs: object) -> FakeBrowser:
        self.launch_calls.append(kwargs)
        if self.launch_error is not None:
            raise self.launch_error
        if self.browser is None:
            self.browser = FakeBrowser()
        return self.browser


@dataclass
class FakePlaywright:
    chromium: FakeChromium
    stop_error: Exception | None = None

    def __post_init__(self) -> None:
        self.stop_calls = 0

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error


@dataclass
class FakePlaywrightManager:
    playwright: FakePlaywright | None = None
    start_error: Exception | None = None

    def start(self) -> FakePlaywright:
        if self.start_error is not None:
            raise self.start_error
        if self.playwright is None:
            raise AssertionError("test must provide a fake Playwright runtime")
        return self.playwright


class BrokenChromiumPlaywright:
    def __init__(self, *, stop_error: Exception | None = None) -> None:
        self.stop_calls = 0
        self.stop_error = stop_error

    @property
    def chromium(self) -> object:
        raise RuntimeError("PROVIDER_SECRET_PATH")

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_error is not None:
            raise self.stop_error


def fake_loader(
    manager: FakePlaywrightManager,
    *,
    context_type: type[object] = FakeBrowserContext,
) -> tuple[type[object], object]:
    return context_type, lambda: manager


class DynamicBrowserPreflightTests(unittest.TestCase):
    def test_reports_missing_optional_package_without_importing_playwright(
        self,
    ) -> None:
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                side_effect=metadata.PackageNotFoundError,
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api"
            ) as loader,
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_PACKAGE_MISSING,
        )
        self.assertFalse(raised.exception.cleanup_failed)
        loader.assert_not_called()

    def test_redacts_package_metadata_failure(self) -> None:
        with patch(
            "vulnspider.discovery.dynamic_browser.metadata.version",
            side_effect=RuntimeError("PROVIDER_SECRET_PATH"),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_METADATA_FAILED,
        )
        self.assertNotIn("PROVIDER_SECRET_PATH", str(raised.exception))

    def test_redacts_provider_import_failure(self) -> None:
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.61.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                side_effect=RuntimeError("PROVIDER_SECRET_PATH"),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_IMPORT_FAILED,
        )
        self.assertNotIn("PROVIDER_SECRET_PATH", str(raised.exception))

    def test_rejects_unsupported_or_non_release_versions(self) -> None:
        for version in ("1.47.2", "2.0.0", "1.48.0rc1", "invalid"):
            with self.subTest(version=version):
                with patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value=version,
                ):
                    with self.assertRaises(DynamicCapabilityError) as raised:
                        preflight_dynamic_browser()
                self.assertEqual(
                    raised.exception.code,
                    DynamicCapabilityCode.PLAYWRIGHT_VERSION_UNSUPPORTED,
                )

    def test_requires_callable_context_wide_websocket_guard(self) -> None:
        class MissingGuard:
            pass

        manager = FakePlaywrightManager()
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.48.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                return_value=fake_loader(
                    manager,
                    context_type=MissingGuard,
                ),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.WEBSOCKET_GUARD_UNAVAILABLE,
        )

    def test_reports_missing_chromium_and_stops_playwright(self) -> None:
        chromium = FakeChromium("Z:/missing/playwright/chromium.exe")
        playwright = FakePlaywright(chromium)
        manager = FakePlaywrightManager(playwright)
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.48.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                return_value=fake_loader(manager),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.CHROMIUM_EXECUTABLE_MISSING,
        )
        self.assertEqual(chromium.launch_calls, [])
        self.assertEqual(playwright.stop_calls, 1)

    def test_redacts_chromium_property_failure_and_preserves_cleanup_state(
        self,
    ) -> None:
        playwright = BrokenChromiumPlaywright(
            stop_error=RuntimeError("CLEANUP_SECRET_PATH")
        )
        manager = FakePlaywrightManager(playwright)  # type: ignore[arg-type]
        with (
            patch(
                "vulnspider.discovery.dynamic_browser.metadata.version",
                return_value="1.61.0",
            ),
            patch(
                "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                return_value=fake_loader(manager),
            ),
        ):
            with self.assertRaises(DynamicCapabilityError) as raised:
                preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PLAYWRIGHT_RUNTIME_UNAVAILABLE,
        )
        self.assertTrue(raised.exception.cleanup_failed)
        self.assertNotIn("PROVIDER_SECRET_PATH", str(raised.exception))
        self.assertNotIn("CLEANUP_SECRET_PATH", str(raised.exception))
        self.assertEqual(playwright.stop_calls, 1)

    def test_verifies_headless_launch_and_closes_every_created_resource(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chromium.exe"
            executable.touch()
            browser = FakeBrowser()
            chromium = FakeChromium(str(executable), browser=browser)
            playwright = FakePlaywright(chromium)
            manager = FakePlaywrightManager(playwright)
            with (
                patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value="1.61.0",
                ),
                patch(
                    "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                    return_value=fake_loader(manager),
                ),
            ):
                result = preflight_dynamic_browser()

        self.assertEqual(result.playwright_version, "1.61.0")
        self.assertEqual(result.browser_name, "chromium")
        self.assertTrue(result.websocket_guard_callable)
        self.assertTrue(result.headless_launch_verified)
        self.assertEqual(chromium.launch_calls, [{"headless": True}])
        self.assertEqual(browser.close_calls, 1)
        self.assertEqual(playwright.stop_calls, 1)

    def test_launch_failure_still_stops_playwright(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chromium.exe"
            executable.touch()
            chromium = FakeChromium(
                str(executable),
                launch_error=RuntimeError("provider path and details"),
            )
            playwright = FakePlaywright(chromium)
            manager = FakePlaywrightManager(playwright)
            with (
                patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value="1.61.0",
                ),
                patch(
                    "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                    return_value=fake_loader(manager),
                ),
            ):
                with self.assertRaises(DynamicCapabilityError) as raised:
                    preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
        )
        self.assertNotIn("provider path", str(raised.exception))
        self.assertEqual(playwright.stop_calls, 1)

    def test_cleanup_failure_is_never_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chromium.exe"
            executable.touch()
            browser = FakeBrowser(close_error=RuntimeError("private detail"))
            chromium = FakeChromium(str(executable), browser=browser)
            playwright = FakePlaywright(chromium)
            manager = FakePlaywrightManager(playwright)
            with (
                patch(
                    "vulnspider.discovery.dynamic_browser.metadata.version",
                    return_value="1.61.0",
                ),
                patch(
                    "vulnspider.discovery.dynamic_browser._load_playwright_sync_api",
                    return_value=fake_loader(manager),
                ),
            ):
                with self.assertRaises(DynamicCapabilityError) as raised:
                    preflight_dynamic_browser()

        self.assertEqual(
            raised.exception.code,
            DynamicCapabilityCode.PREFLIGHT_CLEANUP_FAILED,
        )
        self.assertTrue(raised.exception.cleanup_failed)
        self.assertNotIn("private detail", str(raised.exception))
        self.assertEqual(browser.close_calls, 1)
        self.assertEqual(playwright.stop_calls, 1)


if __name__ == "__main__":
    unittest.main()
