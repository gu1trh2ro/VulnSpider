"""Optional browser capability preflight for Native Dynamic Discovery."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import metadata
from pathlib import Path
import re
from typing import Any, Callable


PLAYWRIGHT_REQUIREMENT = "playwright>=1.48,<2"
_PLAYWRIGHT_DISTRIBUTION = "playwright"
_SUPPORTED_MAJOR = 1
_MINIMUM_MINOR = 48
_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class DynamicCapabilityCode(StrEnum):
    """Stable, secret-free failure codes for Dynamic browser preflight."""

    PLAYWRIGHT_PACKAGE_MISSING = "PLAYWRIGHT_PACKAGE_MISSING"
    PLAYWRIGHT_METADATA_FAILED = "PLAYWRIGHT_METADATA_FAILED"
    PLAYWRIGHT_IMPORT_FAILED = "PLAYWRIGHT_IMPORT_FAILED"
    PLAYWRIGHT_VERSION_UNSUPPORTED = "PLAYWRIGHT_VERSION_UNSUPPORTED"
    WEBSOCKET_GUARD_UNAVAILABLE = "WEBSOCKET_GUARD_UNAVAILABLE"
    PLAYWRIGHT_START_FAILED = "PLAYWRIGHT_START_FAILED"
    PLAYWRIGHT_RUNTIME_UNAVAILABLE = "PLAYWRIGHT_RUNTIME_UNAVAILABLE"
    CHROMIUM_EXECUTABLE_MISSING = "CHROMIUM_EXECUTABLE_MISSING"
    CHROMIUM_LAUNCH_FAILED = "CHROMIUM_LAUNCH_FAILED"
    PREFLIGHT_CLEANUP_FAILED = "PREFLIGHT_CLEANUP_FAILED"


class DynamicCapabilityError(RuntimeError):
    """Raised when the optional Dynamic browser runtime is not usable."""

    def __init__(
        self,
        code: DynamicCapabilityCode,
        message: str,
        *,
        setup_hint: str,
        cleanup_failed: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = DynamicCapabilityCode(code)
        self.setup_hint = setup_hint
        self.cleanup_failed = cleanup_failed


@dataclass(frozen=True, slots=True)
class DynamicBrowserCapability:
    """Successful, secret-free result of a strict Chromium preflight."""

    playwright_version: str
    browser_name: str
    websocket_guard_callable: bool
    headless_launch_verified: bool


def _load_playwright_sync_api() -> tuple[type[Any], Callable[[], Any]]:
    # This is intentionally the only production Playwright import. Keeping it
    # inside the explicit preflight preserves Static and legacy importability.
    from playwright.sync_api import BrowserContext, sync_playwright

    return BrowserContext, sync_playwright


def _parse_supported_version(version: str) -> tuple[int, int, int] | None:
    match = _VERSION_PATTERN.fullmatch(version)
    if match is None:
        return None
    parsed = tuple(int(part) for part in match.groups())
    if parsed[0] != _SUPPORTED_MAJOR or parsed[1] < _MINIMUM_MINOR:
        return None
    return parsed


def _error(
    code: DynamicCapabilityCode,
    message: str,
    setup_hint: str,
    *,
    cleanup_failed: bool = False,
) -> DynamicCapabilityError:
    return DynamicCapabilityError(
        code,
        message,
        setup_hint=setup_hint,
        cleanup_failed=cleanup_failed,
    )


def preflight_dynamic_browser() -> DynamicBrowserCapability:
    """Verify the optional Playwright package, WebSocket guard, and Chromium."""

    package_hint = "Install the optional runtime with: pip install -e .[dynamic]"
    browser_hint = "Install the matching browser with: playwright install chromium"
    try:
        version = metadata.version(_PLAYWRIGHT_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_PACKAGE_MISSING,
            "The optional Playwright package is not installed.",
            package_hint,
        ) from None
    except Exception:  # noqa: BLE001 - metadata diagnostics stay private.
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_METADATA_FAILED,
            "Playwright package metadata could not be read.",
            package_hint,
        ) from None
    if type(version) is not str or _parse_supported_version(version) is None:
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_VERSION_UNSUPPORTED,
            f"Playwright does not satisfy {PLAYWRIGHT_REQUIREMENT}.",
            package_hint,
        )

    try:
        browser_context_type, sync_playwright = _load_playwright_sync_api()
    except Exception:  # noqa: BLE001 - import diagnostics stay private.
        raise _error(
            DynamicCapabilityCode.PLAYWRIGHT_IMPORT_FAILED,
            "The installed Playwright synchronous API is unavailable.",
            package_hint,
        ) from None
    if not callable(getattr(browser_context_type, "route_web_socket", None)):
        raise _error(
            DynamicCapabilityCode.WEBSOCKET_GUARD_UNAVAILABLE,
            "The required context-wide WebSocket guard is unavailable.",
            package_hint,
        )

    playwright: Any | None = None
    chromium: Any | None = None
    browser: Any | None = None
    capability: DynamicBrowserCapability | None = None
    failure: DynamicCapabilityError | None = None
    try:
        try:
            playwright = sync_playwright().start()
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            failure = _error(
                DynamicCapabilityCode.PLAYWRIGHT_START_FAILED,
                "The Playwright runtime could not start.",
                package_hint,
            )
        if failure is None:
            try:
                chromium = playwright.chromium
                executable_path = getattr(chromium, "executable_path", None)
                executable_exists = (
                    type(executable_path) is str
                    and bool(executable_path)
                    and Path(executable_path).is_file()
                )
            except Exception:  # noqa: BLE001 - provider diagnostics stay private.
                failure = _error(
                    DynamicCapabilityCode.PLAYWRIGHT_RUNTIME_UNAVAILABLE,
                    "The Playwright Chromium runtime is unavailable.",
                    browser_hint,
                )
            if failure is None and not executable_exists:
                failure = _error(
                    DynamicCapabilityCode.CHROMIUM_EXECUTABLE_MISSING,
                    "The matching Playwright Chromium executable is unavailable.",
                    browser_hint,
                )
        if failure is None:
            try:
                browser = chromium.launch(headless=True)
            except Exception:  # noqa: BLE001 - provider diagnostics stay private.
                failure = _error(
                    DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
                    "Headless Chromium could not launch.",
                    browser_hint,
                )
        if failure is None:
            capability = DynamicBrowserCapability(
                playwright_version=version,
                browser_name="chromium",
                websocket_guard_callable=True,
                headless_launch_verified=True,
            )
    finally:
        cleanup_failed = False
        if browser is not None:
            try:
                browser.close()
            except Exception:  # noqa: BLE001 - emit only a stable safe code.
                cleanup_failed = True
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:  # noqa: BLE001 - emit only a stable safe code.
                cleanup_failed = True
        if cleanup_failed:
            if failure is None:
                failure = _error(
                    DynamicCapabilityCode.PREFLIGHT_CLEANUP_FAILED,
                    "Dynamic browser preflight cleanup did not complete.",
                    "Retry preflight in a clean local process.",
                    cleanup_failed=True,
                )
            else:
                failure = _error(
                    failure.code,
                    str(failure),
                    failure.setup_hint,
                    cleanup_failed=True,
                )

    if failure is not None:
        raise failure from None
    if capability is None:
        raise _error(
            DynamicCapabilityCode.CHROMIUM_LAUNCH_FAILED,
            "Dynamic browser preflight did not produce a result.",
            browser_hint,
        )
    return capability
