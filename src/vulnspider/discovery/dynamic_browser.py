"""Optional browser capability preflight for Native Dynamic Discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from importlib import metadata
import json
import os
from pathlib import Path
import re
from threading import Lock
from typing import Any, Callable, Generic, Protocol, TypeVar
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit


PLAYWRIGHT_REQUIREMENT = "playwright>=1.48,<2"
_PLAYWRIGHT_DISTRIBUTION = "playwright"
_SUPPORTED_MAJOR = 1
_MINIMUM_MINOR = 48
_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_HTTP_SCHEMES = frozenset({"http", "https"})
_RESOURCE_TYPES = frozenset({"script", "style", "fetch_xhr"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_DEFAULT_NAVIGATION_TIMEOUT_SECONDS = 3.0
_DEFAULT_REQUEST_DECISION_BUDGET = 50
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

T = TypeVar("T")


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


class DynamicResourceKind(StrEnum):
    """Caller-owned exact resource authority categories."""

    SCRIPT = "script"
    STYLE = "style"
    FETCH_XHR = "fetch_xhr"


class DynamicNetworkDecisionKind(StrEnum):
    """Transport decision emitted before browser network dispatch."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class DynamicNetworkReason(StrEnum):
    """Stable network-policy decision reasons."""

    AUTHORIZED_NAVIGATION = "AUTHORIZED_NAVIGATION"
    AUTHORIZED_RESOURCE = "AUTHORIZED_RESOURCE"
    REQUEST_DECISION_BUDGET_EXHAUSTED = "REQUEST_DECISION_BUDGET_EXHAUSTED"
    INVALID_URL = "INVALID_URL"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    NON_GET_METHOD = "NON_GET_METHOD"
    NON_PRIMARY_PAGE = "NON_PRIMARY_PAGE"
    CHILD_FRAME_DOCUMENT = "CHILD_FRAME_DOCUMENT"
    REQUEST_NOT_AUTHORIZED = "REQUEST_NOT_AUTHORIZED"
    RESOURCE_KIND_NOT_AUTHORIZED = "RESOURCE_KIND_NOT_AUTHORIZED"
    EVENTSOURCE_DENIED = "EVENTSOURCE_DENIED"
    WEBSOCKET_DENIED = "WEBSOCKET_DENIED"


class DynamicBrowserErrorCode(StrEnum):
    """Stable lifecycle error codes without provider diagnostics."""

    INVALID_AUTHORITY = "INVALID_AUTHORITY"
    PLAYWRIGHT_START_FAILED = "PLAYWRIGHT_START_FAILED"
    BROWSER_LAUNCH_FAILED = "BROWSER_LAUNCH_FAILED"
    CONTEXT_CREATE_FAILED = "CONTEXT_CREATE_FAILED"
    HTTP_GUARD_INSTALL_FAILED = "HTTP_GUARD_INSTALL_FAILED"
    HTTP_RESPONSE_DISPOSE_FAILED = "HTTP_RESPONSE_DISPOSE_FAILED"
    WEBSOCKET_GUARD_INSTALL_FAILED = "WEBSOCKET_GUARD_INSTALL_FAILED"
    PAGE_CREATE_FAILED = "PAGE_CREATE_FAILED"
    PAGE_OBSERVER_INSTALL_FAILED = "PAGE_OBSERVER_INSTALL_FAILED"
    POPUP_OBSERVER_INSTALL_FAILED = "POPUP_OBSERVER_INSTALL_FAILED"
    REQUEST_DECISION_BUDGET_EXHAUSTED = "REQUEST_DECISION_BUDGET_EXHAUSTED"
    NAVIGATION_NOT_AUTHORIZED = "NAVIGATION_NOT_AUTHORIZED"
    NAVIGATION_FAILED = "NAVIGATION_FAILED"
    NAVIGATION_TIMEOUT = "NAVIGATION_TIMEOUT"
    OPERATION_FAILED = "OPERATION_FAILED"
    OPERATION_TIMEOUT = "OPERATION_TIMEOUT"
    CLEANUP_FAILED = "CLEANUP_FAILED"


@dataclass(frozen=True, slots=True)
class DynamicResourceGrant:
    """One exact same-origin resource grant."""

    kind: DynamicResourceKind
    url: str

    def __post_init__(self) -> None:
        try:
            kind = DynamicResourceKind(self.kind)
        except (TypeError, ValueError):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Dynamic resource grant uses an unsupported category.",
            ) from None
        object.__setattr__(self, "kind", kind)


@dataclass(frozen=True, slots=True)
class DynamicNetworkDecision:
    """One deterministic pre-transport authority decision."""

    decision: DynamicNetworkDecisionKind
    reason: DynamicNetworkReason
    canonical_url: str | None
    resource_kind: str


@dataclass(frozen=True, slots=True)
class BrowserAuditEvent:
    """Bounded, query-value-free browser transport evidence."""

    resource_kind: str
    decision: DynamicNetworkDecisionKind
    reason: DynamicNetworkReason
    scheme: str
    host: str
    port: int | None
    path: str
    query_name_count: int


@dataclass(frozen=True, slots=True)
class BrowserAuditSummary:
    """Immutable minimal lifecycle and transport audit."""

    playwright_started: int
    playwright_stopped: int
    browsers_launched: int
    browsers_closed: int
    contexts_created: int
    contexts_closed: int
    pages_created: int
    pages_closed: int
    popup_attempt_count: int
    http_allowed_count: int
    http_blocked_count: int
    eventsource_attempt_count: int
    eventsource_blocked_count: int
    eventsource_allowed_count: int
    websocket_attempt_count: int
    websocket_blocked_count: int
    websocket_connected_count: int
    child_frame_attach_attempt_count: int
    child_frame_document_request_count: int
    child_frame_document_blocked_count: int
    child_frame_commit_count: int
    child_frame_authorized_commit_count: int
    child_frame_unauthorized_commit_count: int
    child_frame_internal_commit_count: int
    child_frame_completion_count: int
    child_frame_detach_count: int
    redirect_attempt_count: int
    redirect_allowed_count: int
    redirect_block_count: int
    request_decision_overflow_count: int
    cleanup_error_codes: tuple[str, ...]
    cleanup_complete: bool
    events: tuple[BrowserAuditEvent, ...]


class DynamicBrowserError(RuntimeError):
    """Typed lifecycle failure with retained secret-free cleanup evidence."""

    def __init__(
        self,
        code: DynamicBrowserErrorCode,
        message: str,
        *,
        cleanup_error_codes: tuple[str, ...] = (),
        audit: BrowserAuditSummary | None = None,
    ) -> None:
        super().__init__(message)
        self.code = DynamicBrowserErrorCode(code)
        self.cleanup_error_codes = tuple(cleanup_error_codes)
        self.audit = audit


@dataclass(frozen=True, slots=True)
class DynamicBrowserPolicy:
    """Bounds owned by this lifecycle seam."""

    navigation_timeout_seconds: float = _DEFAULT_NAVIGATION_TIMEOUT_SECONDS
    request_decision_budget: int = _DEFAULT_REQUEST_DECISION_BUDGET

    def __post_init__(self) -> None:
        if (
            type(self.navigation_timeout_seconds) not in {int, float}
            or isinstance(self.navigation_timeout_seconds, bool)
            or self.navigation_timeout_seconds <= 0
        ):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Navigation timeout must be a positive number.",
            )
        if (
            type(self.request_decision_budget) is not int
            or self.request_decision_budget <= 0
        ):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Request decision budget must be a positive integer.",
            )
        object.__setattr__(
            self,
            "navigation_timeout_seconds",
            float(self.navigation_timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class DynamicRequestAuthority:
    """Immutable exact caller authority for one loopback browser session."""

    root_url: str
    navigation_urls: tuple[str, ...] = ()
    resource_grants: tuple[DynamicResourceGrant, ...] = ()

    def __post_init__(self) -> None:
        root_url = _canonical_authority_url(self.root_url)
        if not _is_loopback_url(root_url):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Dynamic browser root must use an explicit loopback authority.",
            )
        try:
            navigation_inputs = tuple(self.navigation_urls)
            grant_inputs = tuple(self.resource_grants)
        except TypeError:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Dynamic request authority collections must be iterable.",
            ) from None

        navigation_urls = {root_url}
        for url in navigation_inputs:
            canonical = _canonical_authority_url(url)
            _require_same_origin(root_url, canonical)
            navigation_urls.add(canonical)

        resource_grants: set[tuple[DynamicResourceKind, str]] = set()
        for grant in grant_inputs:
            if type(grant) is not DynamicResourceGrant:
                raise DynamicBrowserError(
                    DynamicBrowserErrorCode.INVALID_AUTHORITY,
                    "Resource authority requires canonical DynamicResourceGrant.",
                )
            canonical = _canonical_authority_url(grant.url)
            _require_same_origin(root_url, canonical)
            resource_grants.add((grant.kind, canonical))

        object.__setattr__(self, "root_url", root_url)
        object.__setattr__(self, "navigation_urls", tuple(sorted(navigation_urls)))
        object.__setattr__(
            self,
            "resource_grants",
            tuple(
                DynamicResourceGrant(kind=kind, url=url)
                for kind, url in sorted(
                    resource_grants,
                    key=lambda item: (item[0].value, item[1]),
                )
            ),
        )

    def allows_navigation(self, url: str) -> bool:
        try:
            canonical = _canonical_request_url(url)
        except DynamicBrowserError:
            return False
        return canonical in self.navigation_urls

    def decide_http(
        self,
        *,
        method: str,
        url: str,
        resource_type: str,
        is_primary_page: bool,
        is_main_frame: bool,
    ) -> DynamicNetworkDecision:
        normalized_kind = resource_type.strip().lower()
        try:
            canonical = _canonical_request_url(url)
        except DynamicBrowserError:
            reason = (
                DynamicNetworkReason.UNSUPPORTED_SCHEME
                if _safe_scheme(url) not in _HTTP_SCHEMES
                else DynamicNetworkReason.INVALID_URL
            )
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                reason,
                None,
                normalized_kind,
            )
        if method.upper() != "GET":
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.NON_GET_METHOD,
                canonical,
                normalized_kind,
            )
        if not is_primary_page:
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.NON_PRIMARY_PAGE,
                canonical,
                normalized_kind,
            )
        if normalized_kind == "document":
            if not is_main_frame:
                return DynamicNetworkDecision(
                    DynamicNetworkDecisionKind.BLOCK,
                    DynamicNetworkReason.CHILD_FRAME_DOCUMENT,
                    canonical,
                    normalized_kind,
                )
            if canonical in self.navigation_urls:
                return DynamicNetworkDecision(
                    DynamicNetworkDecisionKind.ALLOW,
                    DynamicNetworkReason.AUTHORIZED_NAVIGATION,
                    canonical,
                    normalized_kind,
                )
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
                canonical,
                normalized_kind,
            )
        if normalized_kind == "eventsource":
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.EVENTSOURCE_DENIED,
                canonical,
                normalized_kind,
            )
        grant_kind = _grant_kind_for_resource_type(normalized_kind)
        if grant_kind is None:
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.RESOURCE_KIND_NOT_AUTHORIZED,
                canonical,
                normalized_kind,
            )
        if any(
            grant.kind == grant_kind and grant.url == canonical
            for grant in self.resource_grants
        ):
            return DynamicNetworkDecision(
                DynamicNetworkDecisionKind.ALLOW,
                DynamicNetworkReason.AUTHORIZED_RESOURCE,
                canonical,
                normalized_kind,
            )
        return DynamicNetworkDecision(
            DynamicNetworkDecisionKind.BLOCK,
            DynamicNetworkReason.REQUEST_NOT_AUTHORIZED,
            canonical,
            normalized_kind,
        )


class DynamicBrowserSession(Protocol):
    """Limited caller seam over one guarded primary page."""

    def navigate(self, url: str | None = None) -> str:
        """Navigate only to an exact caller-authorized URL."""

    def wait_for_selector(self, selector: str) -> None:
        """Wait within the configured operation timeout."""

    def text_content(self, selector: str) -> str | None:
        """Read one selected DOM text value."""


class DynamicBrowser(Protocol):
    """Synchronous managed browser boundary."""

    def run(
        self,
        authority: DynamicRequestAuthority,
        operation: Callable[[DynamicBrowserSession], T],
        *,
        policy: DynamicBrowserPolicy | None = None,
    ) -> "DynamicBrowserRunResult[T]":
        """Run one guarded operation and close all owned resources."""


@dataclass(frozen=True, slots=True)
class DynamicBrowserRunResult(Generic[T]):
    """Caller result plus final immutable cleanup/network audit."""

    value: T
    audit: BrowserAuditSummary


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
                browser = chromium.launch(**_browser_launch_options())
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


def _load_managed_playwright_sync_api() -> tuple[Callable[[], Any], type[Exception]]:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    return sync_playwright, PlaywrightTimeoutError


def _browser_launch_options() -> dict[str, Any]:
    browser_environment = dict(os.environ)
    browser_environment["CHROME_LOG_FILE"] = os.devnull
    return {"headless": True, "env": browser_environment}


def _canonical_authority_url(url: str) -> str:
    if type(url) is not str or not url or url != url.strip():
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority requires an absolute HTTP(S) URL.",
        )
    if any(character in url for character in "\r\n\t"):
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority contains invalid URL characters.",
        )
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority contains a malformed URL.",
        ) from None
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower() if parts.hostname else ""
    if (
        scheme not in _HTTP_SCHEMES
        or not hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority requires a credential-free HTTP(S) URL.",
        )
    effective_port = port or _DEFAULT_PORTS[scheme]
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    netloc = (
        host_text
        if effective_port == _DEFAULT_PORTS[scheme]
        else f"{host_text}:{effective_port}"
    )
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _canonical_request_url(url: str) -> str:
    try:
        return _canonical_authority_url(url)
    except DynamicBrowserError as exc:
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Browser request URL is invalid or unsupported.",
        ) from None


def _require_same_origin(root_url: str, candidate_url: str) -> None:
    if _origin(root_url) != _origin(candidate_url):
        raise DynamicBrowserError(
            DynamicBrowserErrorCode.INVALID_AUTHORITY,
            "Dynamic request authority cannot cross the root origin.",
        )


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower() if parts.hostname else ""
    return scheme, hostname, parts.port or _DEFAULT_PORTS[scheme]


def _is_loopback_url(url: str) -> bool:
    hostname = urlsplit(url).hostname
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _safe_scheme(url: str) -> str:
    if type(url) is not str:
        return ""
    try:
        return urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def _grant_kind_for_resource_type(
    resource_type: str,
) -> DynamicResourceKind | None:
    if resource_type == "script":
        return DynamicResourceKind.SCRIPT
    if resource_type == "stylesheet":
        return DynamicResourceKind.STYLE
    if resource_type in {"fetch", "xhr"}:
        return DynamicResourceKind.FETCH_XHR
    return None


def _safe_audit_event(
    *,
    url: str,
    resource_kind: str,
    decision: DynamicNetworkDecisionKind,
    reason: DynamicNetworkReason,
) -> BrowserAuditEvent:
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname.lower() if parts.hostname else ""
        port = parts.port or _DEFAULT_PORTS.get(scheme)
        path = parts.path or "/"
        query_name_count = len(parse_qsl(parts.query, keep_blank_values=True))
    except (TypeError, ValueError):
        scheme = ""
        host = ""
        port = None
        path = ""
        query_name_count = 0
    return BrowserAuditEvent(
        resource_kind=resource_kind,
        decision=decision,
        reason=reason,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query_name_count=query_name_count,
    )


class _AuditRecorder:
    def __init__(self, *, event_limit: int) -> None:
        self._event_limit = event_limit
        self._lock = Lock()
        self.playwright_started = 0
        self.playwright_stopped = 0
        self.browsers_launched = 0
        self.browsers_closed = 0
        self.contexts_created = 0
        self.contexts_closed = 0
        self.pages_created = 0
        self.pages_closed = 0
        self.popup_attempt_count = 0
        self.http_allowed_count = 0
        self.http_blocked_count = 0
        self.eventsource_attempt_count = 0
        self.eventsource_blocked_count = 0
        self.eventsource_allowed_count = 0
        self.websocket_attempt_count = 0
        self.websocket_blocked_count = 0
        self.websocket_connected_count = 0
        self.child_frame_attach_attempt_count = 0
        self.child_frame_document_request_count = 0
        self.child_frame_document_blocked_count = 0
        self.child_frame_commit_count = 0
        self.child_frame_authorized_commit_count = 0
        self.child_frame_unauthorized_commit_count = 0
        self.child_frame_internal_commit_count = 0
        self.child_frame_completion_count = 0
        self.child_frame_detach_count = 0
        self.redirect_attempt_count = 0
        self.redirect_allowed_count = 0
        self.redirect_block_count = 0
        self.request_decision_overflow_count = 0
        self._events: list[BrowserAuditEvent] = []

    def record_http(
        self,
        decision: DynamicNetworkDecision,
        *,
        url: str,
        is_child_frame_document: bool,
        is_redirect: bool,
    ) -> None:
        with self._lock:
            if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                self.http_allowed_count += 1
            else:
                self.http_blocked_count += 1
            if decision.resource_kind == "eventsource":
                self.eventsource_attempt_count += 1
                if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                    self.eventsource_allowed_count += 1
                else:
                    self.eventsource_blocked_count += 1
            if is_child_frame_document:
                self.child_frame_document_request_count += 1
                if decision.decision == DynamicNetworkDecisionKind.BLOCK:
                    self.child_frame_document_blocked_count += 1
            if is_redirect:
                self.redirect_attempt_count += 1
                if decision.decision == DynamicNetworkDecisionKind.ALLOW:
                    self.redirect_allowed_count += 1
                else:
                    self.redirect_block_count += 1
            self._append_event(
                _safe_audit_event(
                    url=url,
                    resource_kind=decision.resource_kind,
                    decision=decision.decision,
                    reason=decision.reason,
                )
            )

    def record_popup(self) -> None:
        with self._lock:
            self.popup_attempt_count += 1

    def record_child_frame_attach(self) -> None:
        with self._lock:
            self.child_frame_attach_attempt_count += 1

    def record_child_frame_commit(self, classification: str) -> None:
        with self._lock:
            self.child_frame_commit_count += 1
            if classification == "authorized":
                self.child_frame_authorized_commit_count += 1
            elif classification == "unauthorized":
                self.child_frame_unauthorized_commit_count += 1
            else:
                self.child_frame_internal_commit_count += 1

    def record_child_frame_detach(self) -> None:
        with self._lock:
            self.child_frame_detach_count += 1

    def record_child_frame_completion(self) -> None:
        with self._lock:
            self.child_frame_completion_count += 1

    def record_websocket(
        self,
        *,
        url: str,
        reason: DynamicNetworkReason,
    ) -> None:
        with self._lock:
            self.websocket_attempt_count += 1
            self.websocket_blocked_count += 1
            self._append_event(
                _safe_audit_event(
                    url=url,
                    resource_kind="websocket",
                    decision=DynamicNetworkDecisionKind.BLOCK,
                    reason=reason,
                )
            )

    def _append_event(self, event: BrowserAuditEvent) -> None:
        if len(self._events) < self._event_limit:
            self._events.append(event)
        else:
            self.request_decision_overflow_count += 1

    def snapshot(self, cleanup_error_codes: tuple[str, ...]) -> BrowserAuditSummary:
        with self._lock:
            cleanup_complete = (
                not cleanup_error_codes
                and self.playwright_started == self.playwright_stopped
                and self.browsers_launched == self.browsers_closed
                and self.contexts_created == self.contexts_closed
                and self.pages_created == self.pages_closed
            )
            return BrowserAuditSummary(
                playwright_started=self.playwright_started,
                playwright_stopped=self.playwright_stopped,
                browsers_launched=self.browsers_launched,
                browsers_closed=self.browsers_closed,
                contexts_created=self.contexts_created,
                contexts_closed=self.contexts_closed,
                pages_created=self.pages_created,
                pages_closed=self.pages_closed,
                popup_attempt_count=self.popup_attempt_count,
                http_allowed_count=self.http_allowed_count,
                http_blocked_count=self.http_blocked_count,
                eventsource_attempt_count=self.eventsource_attempt_count,
                eventsource_blocked_count=self.eventsource_blocked_count,
                eventsource_allowed_count=self.eventsource_allowed_count,
                websocket_attempt_count=self.websocket_attempt_count,
                websocket_blocked_count=self.websocket_blocked_count,
                websocket_connected_count=self.websocket_connected_count,
                child_frame_attach_attempt_count=(
                    self.child_frame_attach_attempt_count
                ),
                child_frame_document_request_count=(
                    self.child_frame_document_request_count
                ),
                child_frame_document_blocked_count=(
                    self.child_frame_document_blocked_count
                ),
                child_frame_commit_count=self.child_frame_commit_count,
                child_frame_authorized_commit_count=(
                    self.child_frame_authorized_commit_count
                ),
                child_frame_unauthorized_commit_count=(
                    self.child_frame_unauthorized_commit_count
                ),
                child_frame_internal_commit_count=(
                    self.child_frame_internal_commit_count
                ),
                child_frame_completion_count=self.child_frame_completion_count,
                child_frame_detach_count=self.child_frame_detach_count,
                redirect_attempt_count=self.redirect_attempt_count,
                redirect_allowed_count=self.redirect_allowed_count,
                redirect_block_count=self.redirect_block_count,
                request_decision_overflow_count=(
                    self.request_decision_overflow_count
                ),
                cleanup_error_codes=cleanup_error_codes,
                cleanup_complete=cleanup_complete,
                events=tuple(self._events),
            )


class _RouteGuard:
    def __init__(
        self,
        authority: DynamicRequestAuthority,
        policy: DynamicBrowserPolicy,
        audit: _AuditRecorder,
        stop_active_page: Callable[[], None],
        provider_timeout_error: type[Exception] = TimeoutError,
    ) -> None:
        self.authority = authority
        self.policy = policy
        self.audit = audit
        self.stop_active_page = stop_active_page
        self.provider_timeout_error = provider_timeout_error
        self.primary_page: Any | None = None
        self.decision_count = 0
        self._decision_lock = Lock()
        self._budget_exhausted = False
        self._request_failure: DynamicBrowserError | None = None

    def set_primary_page(self, page: Any) -> None:
        self.primary_page = page

    def handle_http(self, route: Any, request: Any) -> None:
        url = _safe_provider_text(request, "url")
        resource_type = _safe_provider_text(request, "resource_type")
        method = _safe_provider_text(request, "method")
        is_primary_page, is_main_frame = self._frame_state(request)
        is_child_frame_document = (
            resource_type.strip().lower() == "document" and not is_main_frame
        )
        within_budget, first_exhaustion, should_record = (
            self._reserve_transport_decision()
        )
        if not within_budget:
            decision = DynamicNetworkDecision(
                DynamicNetworkDecisionKind.BLOCK,
                DynamicNetworkReason.REQUEST_DECISION_BUDGET_EXHAUSTED,
                None,
                resource_type,
            )
        else:
            decision = self.authority.decide_http(
                method=method,
                url=url,
                resource_type=resource_type,
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
            )
        if should_record:
            self.audit.record_http(
                decision,
                url=url,
                is_child_frame_document=is_child_frame_document,
                is_redirect=False,
            )
        if decision.decision == DynamicNetworkDecisionKind.ALLOW:
            self._fulfill_allowed_http(
                route,
                decision,
                resource_type=resource_type,
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
            )
        else:
            if within_budget:
                self._set_navigation_failure(
                    is_primary_page=is_primary_page,
                    is_main_frame=is_main_frame,
                    is_document=resource_type.strip().lower() == "document",
                )
            self._abort_route(route)
        if first_exhaustion:
            self.stop_active_page()

    def _fulfill_allowed_http(
        self,
        route: Any,
        decision: DynamicNetworkDecision,
        *,
        resource_type: str,
        is_primary_page: bool,
        is_main_frame: bool,
    ) -> None:
        current_url = decision.canonical_url
        response: Any | None = None
        is_document_navigation = (
            is_primary_page
            and is_main_frame
            and resource_type.strip().lower() == "document"
        )
        try:
            while current_url is not None:
                response = route.fetch(
                    url=current_url,
                    max_redirects=0,
                    timeout=self.policy.navigation_timeout_seconds * 1000,
                )
                redirect_url = _response_redirect_target(
                    response,
                    current_url=current_url,
                )
                if redirect_url is None:
                    route.fulfill(response=response)
                    return
                response_disposed = _dispose_api_response(response)
                response = None
                if not response_disposed:
                    self._set_response_dispose_failure()
                    self._abort_route(route)
                    return

                within_budget, first_exhaustion, should_record = (
                    self._reserve_transport_decision()
                )
                if within_budget:
                    redirect_decision = self.authority.decide_http(
                        method="GET",
                        url=redirect_url,
                        resource_type=resource_type,
                        is_primary_page=is_primary_page,
                        is_main_frame=is_main_frame,
                    )
                else:
                    redirect_decision = DynamicNetworkDecision(
                        DynamicNetworkDecisionKind.BLOCK,
                        DynamicNetworkReason.REQUEST_DECISION_BUDGET_EXHAUSTED,
                        None,
                        resource_type,
                    )
                if should_record:
                    self.audit.record_http(
                        redirect_decision,
                        url=redirect_url,
                        is_child_frame_document=False,
                        is_redirect=True,
                    )
                if (
                    redirect_decision.decision
                    == DynamicNetworkDecisionKind.BLOCK
                ):
                    if within_budget:
                        self._set_navigation_failure(
                            is_primary_page=is_primary_page,
                            is_main_frame=is_main_frame,
                            is_document=(
                                resource_type.strip().lower() == "document"
                            ),
                        )
                    self._abort_route(route)
                    if first_exhaustion:
                        self.stop_active_page()
                    return
                current_url = redirect_decision.canonical_url
                if is_document_navigation and current_url is not None:
                    route.fulfill(
                        status=200,
                        content_type="text/html; charset=utf-8",
                        body=_redirect_relocation_document(current_url),
                    )
                    return
        except self.provider_timeout_error:
            self._set_navigation_failure(
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
                is_document=resource_type.strip().lower() == "document",
                timeout=True,
            )
            self._abort_route(route)
        except Exception:  # noqa: BLE001 - provider details remain private.
            self._set_navigation_failure(
                is_primary_page=is_primary_page,
                is_main_frame=is_main_frame,
                is_document=resource_type.strip().lower() == "document",
            )
            self._abort_route(route)
        finally:
            if not _dispose_api_response(response):
                self._set_response_dispose_failure()

    def _set_navigation_failure(
        self,
        *,
        is_primary_page: bool,
        is_main_frame: bool,
        is_document: bool,
        timeout: bool = False,
    ) -> None:
        if not (is_primary_page and is_main_frame and is_document):
            return
        code = (
            DynamicBrowserErrorCode.NAVIGATION_TIMEOUT
            if timeout
            else DynamicBrowserErrorCode.NAVIGATION_FAILED
        )
        message = (
            "Authorized browser navigation timed out."
            if timeout
            else "Authorized browser navigation failed."
        )
        with self._decision_lock:
            if self._request_failure is None:
                self._request_failure = DynamicBrowserError(code, message)

    def _set_response_dispose_failure(self) -> None:
        with self._decision_lock:
            if self._request_failure is None:
                self._request_failure = DynamicBrowserError(
                    DynamicBrowserErrorCode.HTTP_RESPONSE_DISPOSE_FAILED,
                    "Intercepted browser response cleanup did not complete.",
                )

    @staticmethod
    def _abort_route(route: Any) -> None:
        try:
            route.abort(error_code="blockedbyclient")
        except Exception:  # noqa: BLE001 - the page may already be closing.
            return

    def handle_websocket(self, websocket_route: Any) -> None:
        url = _safe_provider_text(websocket_route, "url")
        within_budget, first_exhaustion, should_record = (
            self._reserve_transport_decision()
        )
        reason = (
            DynamicNetworkReason.WEBSOCKET_DENIED
            if within_budget
            else DynamicNetworkReason.REQUEST_DECISION_BUDGET_EXHAUSTED
        )
        if should_record:
            self.audit.record_websocket(url=url, reason=reason)
        # Routed WebSockets do not contact the server unless the handler calls
        # connect_to_server(). Returning here is therefore the synchronous,
        # pre-transport denial path and avoids creating any server connection.
        if first_exhaustion:
            self.stop_active_page()

    def _reserve_transport_decision(self) -> tuple[bool, bool, bool]:
        with self._decision_lock:
            if self._budget_exhausted:
                return False, False, False
            self.decision_count += 1
            within_budget = (
                self.decision_count <= self.policy.request_decision_budget
            )
            if not within_budget:
                self._budget_exhausted = True
            return within_budget, not within_budget, True

    def raise_if_budget_exhausted(self) -> None:
        with self._decision_lock:
            exhausted = self._budget_exhausted
        if exhausted:
            _raise_request_decision_budget_exhausted()

    def raise_if_failed(self) -> None:
        self.raise_if_budget_exhausted()
        with self._decision_lock:
            request_failure = self._request_failure
        if request_failure is not None:
            raise request_failure

    def _frame_state(self, request: Any) -> tuple[bool, bool]:
        try:
            frame = request.frame
            page = frame.page
            return page is self.primary_page, frame.parent_frame is None
        except Exception:  # noqa: BLE001 - fail closed on provider ambiguity.
            return False, False


def _safe_provider_text(provider: Any, attribute: str) -> str:
    try:
        value = getattr(provider, attribute)
        if callable(value):
            value = value()
    except Exception:  # noqa: BLE001 - fail closed without provider details.
        return ""
    return value if type(value) is str else ""


def _response_redirect_target(
    response: Any,
    *,
    current_url: str,
) -> str | None:
    try:
        status = response.status
        if callable(status):
            status = status()
        headers = response.headers
        if callable(headers):
            headers = headers()
    except Exception:  # noqa: BLE001 - fail closed without provider details.
        raise ValueError("redirect response metadata is unavailable") from None
    if type(status) is not int or not isinstance(headers, dict):
        raise ValueError("redirect response metadata is invalid")
    if status not in _REDIRECT_STATUS_CODES:
        return None
    location_values = tuple(
        value
        for key, value in headers.items()
        if type(key) is str and key.lower() == "location"
    )
    if not location_values:
        return None
    location = location_values[0]
    if type(location) is not str or not location:
        raise ValueError("redirect location is invalid")
    return urljoin(current_url, location)


def _redirect_relocation_document(url: str) -> str:
    encoded_url = (
        json.dumps(url, ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    return (
        "<!doctype html><meta charset=\"utf-8\">"
        f"<script>window.location.replace({encoded_url});</script>"
    )


def _dispose_api_response(response: Any | None) -> bool:
    if response is None:
        return True
    try:
        response.dispose()
    except Exception:  # noqa: BLE001 - cleanup remains best effort and local.
        return False
    return True


def _raise_request_decision_budget_exhausted() -> None:
    raise DynamicBrowserError(
        DynamicBrowserErrorCode.REQUEST_DECISION_BUDGET_EXHAUSTED,
        "Browser transport decision budget was exhausted.",
    )


class _PageLifecycleObserver:
    def __init__(
        self,
        authority: DynamicRequestAuthority,
        audit: _AuditRecorder,
    ) -> None:
        self.authority = authority
        self.audit = audit

    def install(self, page: Any) -> None:
        page.on("frameattached", self.handle_frame_attached)
        page.on("framenavigated", self.handle_frame_navigated)
        page.on("framedetached", self.handle_frame_detached)
        page.on("requestfinished", self.handle_request_finished)

    def handle_frame_attached(self, frame: Any) -> None:
        if _is_child_frame(frame):
            self.audit.record_child_frame_attach()

    def handle_frame_navigated(self, frame: Any) -> None:
        if not _is_child_frame(frame):
            return
        url = _safe_provider_text(frame, "url")
        self.audit.record_child_frame_commit(
            _classify_child_frame_commit(url, self.authority)
        )

    def handle_frame_detached(self, frame: Any) -> None:
        if _is_child_frame(frame):
            self.audit.record_child_frame_detach()

    def handle_request_finished(self, request: Any) -> None:
        if _safe_provider_text(request, "resource_type").lower() != "document":
            return
        try:
            frame = request.frame
            if callable(frame):
                frame = frame()
        except Exception:  # noqa: BLE001 - ambiguous requests are not classified.
            return
        if _is_child_frame(frame):
            self.audit.record_child_frame_completion()


def _is_child_frame(frame: Any) -> bool:
    try:
        parent = frame.parent_frame
        if callable(parent):
            parent = parent()
    except Exception:  # noqa: BLE001 - ambiguous frames are not classified.
        return False
    return parent is not None


def _classify_child_frame_commit(
    url: str,
    authority: DynamicRequestAuthority,
) -> str:
    if _safe_scheme(url) not in _HTTP_SCHEMES:
        return "internal"
    if authority.allows_navigation(url):
        return "authorized"
    return "unauthorized"


@dataclass(slots=True)
class _ManagedResources:
    audit: _AuditRecorder
    playwright: Any | None = None
    browser: Any | None = None
    context: Any | None = None
    page: Any | None = None
    popup_pages: list[Any] = field(default_factory=list)
    _closed: bool = False
    _page_close_attempted: bool = False
    _page_cleanup_errors: tuple[str, ...] = ()
    _page_stop_requested: bool = False
    _cleanup_errors: tuple[str, ...] = ()

    def request_page_stop(self) -> None:
        self._page_stop_requested = True

    def add_popup_page(self, page: Any) -> None:
        self.popup_pages.append(page)
        self.audit.pages_created += 1
        self.audit.record_popup()

    def close_requested_page(self) -> tuple[str, ...]:
        if not self._page_stop_requested:
            return ()
        return self.close_page()

    def close_page(self) -> tuple[str, ...]:
        if self.page is None or self._page_close_attempted:
            return self._page_cleanup_errors
        self._page_close_attempted = True
        errors: list[str] = []
        self._close_one(
            self.page,
            "PAGE_CLOSE_FAILED",
            lambda: setattr(
                self.audit,
                "pages_closed",
                self.audit.pages_closed + 1,
            ),
            errors,
        )
        self._page_cleanup_errors = tuple(errors)
        return self._page_cleanup_errors

    def close(self) -> tuple[str, ...]:
        if self._closed:
            return self._cleanup_errors
        self._closed = True
        errors: list[str] = []
        for popup in reversed(self.popup_pages):
            self._close_one(
                popup,
                "POPUP_PAGE_CLOSE_FAILED",
                lambda: setattr(
                    self.audit,
                    "pages_closed",
                    self.audit.pages_closed + 1,
                ),
                errors,
            )
        self.close_page()
        errors.extend(self._page_cleanup_errors)
        self._close_one(
            self.context,
            "CONTEXT_CLOSE_FAILED",
            lambda: setattr(
                self.audit,
                "contexts_closed",
                self.audit.contexts_closed + 1,
            ),
            errors,
        )
        self._close_one(
            self.browser,
            "BROWSER_CLOSE_FAILED",
            lambda: setattr(
                self.audit,
                "browsers_closed",
                self.audit.browsers_closed + 1,
            ),
            errors,
        )
        self._close_one(
            self.playwright,
            "PLAYWRIGHT_STOP_FAILED",
            lambda: setattr(
                self.audit,
                "playwright_stopped",
                self.audit.playwright_stopped + 1,
            ),
            errors,
            method_name="stop",
        )
        self._cleanup_errors = tuple(errors)
        return self._cleanup_errors

    @staticmethod
    def _close_one(
        resource: Any | None,
        error_code: str,
        on_success: Callable[[], None],
        errors: list[str],
        *,
        method_name: str = "close",
    ) -> None:
        if resource is None:
            return
        try:
            getattr(resource, method_name)()
        except Exception:  # noqa: BLE001 - retain only stable cleanup code.
            errors.append(error_code)
        else:
            on_success()


class _PlaywrightDynamicSession:
    def __init__(
        self,
        *,
        page: Any,
        authority: DynamicRequestAuthority,
        policy: DynamicBrowserPolicy,
        provider_timeout_error: type[Exception],
        guard: _RouteGuard,
    ) -> None:
        self._page = page
        self._authority = authority
        self._policy = policy
        self._provider_timeout_error = provider_timeout_error
        self._guard = guard

    def navigate(self, url: str | None = None) -> str:
        self._guard.raise_if_failed()
        target = self._authority.root_url if url is None else url
        if not self._authority.allows_navigation(target):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.NAVIGATION_NOT_AUTHORIZED,
                "Navigation URL is not present in caller-owned authority.",
            )
        canonical = _canonical_request_url(target)
        try:
            self._page.goto(
                canonical,
                wait_until="domcontentloaded",
                timeout=self._policy.navigation_timeout_seconds * 1000,
            )
            self._guard.raise_if_failed()
            return _safe_provider_text(self._page, "url")
        except self._provider_timeout_error:
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.NAVIGATION_TIMEOUT,
                "Authorized browser navigation timed out.",
            ) from None
        except DynamicBrowserError:
            raise
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.NAVIGATION_FAILED,
                "Authorized browser navigation failed.",
            ) from None

    def wait_for_selector(self, selector: str) -> None:
        self._guard.raise_if_failed()
        if type(selector) is not str or not selector:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Selector must not be empty.",
            )
        try:
            self._page.wait_for_selector(
                selector,
                timeout=self._policy.navigation_timeout_seconds * 1000,
            )
            self._guard.raise_if_failed()
        except self._provider_timeout_error:
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                "Bounded browser operation timed out.",
            ) from None
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Bounded browser operation failed.",
            ) from None

    def text_content(self, selector: str) -> str | None:
        self._guard.raise_if_failed()
        if type(selector) is not str or not selector:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Selector must not be empty.",
            )
        try:
            value = self._page.text_content(selector)
            self._guard.raise_if_failed()
        except Exception:  # noqa: BLE001 - provider diagnostics stay private.
            self._guard.raise_if_failed()
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Bounded browser operation failed.",
            ) from None
        return value if value is None or type(value) is str else str(value)


class PlaywrightDynamicBrowser:
    """Concrete synchronous adapter with strict pre-page transport guards."""

    def run(
        self,
        authority: DynamicRequestAuthority,
        operation: Callable[[DynamicBrowserSession], T],
        *,
        policy: DynamicBrowserPolicy | None = None,
    ) -> DynamicBrowserRunResult[T]:
        if type(authority) is not DynamicRequestAuthority:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Managed browser requires canonical DynamicRequestAuthority.",
            )
        if not callable(operation):
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Managed browser operation must be callable.",
            )
        active_policy = policy or DynamicBrowserPolicy()
        if type(active_policy) is not DynamicBrowserPolicy:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.INVALID_AUTHORITY,
                "Managed browser requires canonical DynamicBrowserPolicy.",
            )

        preflight_dynamic_browser()
        audit = _AuditRecorder(
            event_limit=active_policy.request_decision_budget,
        )
        resources = _ManagedResources(audit)
        primary_error: DynamicBrowserError | None = None
        value: T | None = None
        value_set = False
        try:
            try:
                sync_playwright, provider_timeout_error = (
                    _load_managed_playwright_sync_api()
                )
                resources.playwright = sync_playwright().start()
                audit.playwright_started += 1
            except Exception:  # noqa: BLE001 - provider diagnostics stay private.
                primary_error = DynamicBrowserError(
                    DynamicBrowserErrorCode.PLAYWRIGHT_START_FAILED,
                    "Managed Playwright runtime could not start.",
                )
            if primary_error is None:
                try:
                    resources.browser = resources.playwright.chromium.launch(
                        **_browser_launch_options()
                    )
                    audit.browsers_launched += 1
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.BROWSER_LAUNCH_FAILED,
                        "Managed headless Chromium could not launch.",
                    )
            if primary_error is None:
                try:
                    resources.context = resources.browser.new_context(
                        accept_downloads=False,
                        service_workers="block",
                    )
                    audit.contexts_created += 1
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.CONTEXT_CREATE_FAILED,
                        "Isolated browser context could not be created.",
                    )
            guard = _RouteGuard(
                authority,
                active_policy,
                audit,
                resources.request_page_stop,
                provider_timeout_error,
            )
            page_observer = _PageLifecycleObserver(authority, audit)
            if primary_error is None:
                try:
                    resources.context.route("**/*", guard.handle_http)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.HTTP_GUARD_INSTALL_FAILED,
                        "HTTP(S) request guard could not be installed.",
                    )
            if primary_error is None:
                try:
                    resources.context.route_web_socket(
                        "**/*",
                        guard.handle_websocket,
                    )
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.WEBSOCKET_GUARD_INSTALL_FAILED,
                        "WebSocket request guard could not be installed.",
                    )
            if primary_error is None:
                try:
                    resources.page = resources.context.new_page()
                    audit.pages_created += 1
                    guard.set_primary_page(resources.page)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.PAGE_CREATE_FAILED,
                        "Guarded primary page could not be created.",
                    )
            if primary_error is None:
                try:
                    page_observer.install(resources.page)
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.PAGE_OBSERVER_INSTALL_FAILED,
                        "Browser lifecycle observers could not be installed.",
                    )
            if primary_error is None:
                try:
                    resources.context.on(
                        "page",
                        lambda popup: resources.add_popup_page(popup),
                    )
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.POPUP_OBSERVER_INSTALL_FAILED,
                        "Popup lifecycle observer could not be installed.",
                    )
            if primary_error is None:
                session = _PlaywrightDynamicSession(
                    page=resources.page,
                    authority=authority,
                    policy=active_policy,
                    provider_timeout_error=provider_timeout_error,
                    guard=guard,
                )
                try:
                    value = operation(session)
                    guard.raise_if_failed()
                    value_set = True
                except DynamicBrowserError as exc:
                    primary_error = exc
                except (provider_timeout_error, TimeoutError):
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.OPERATION_TIMEOUT,
                        "Managed browser operation timed out.",
                    )
                except Exception:  # noqa: BLE001
                    primary_error = DynamicBrowserError(
                        DynamicBrowserErrorCode.OPERATION_FAILED,
                        "Managed browser operation failed.",
                    )
        finally:
            resources.close_requested_page()
            cleanup_error_codes = resources.close()
            if primary_error is None:
                try:
                    guard.raise_if_failed()
                except DynamicBrowserError as exc:
                    primary_error = exc

        summary = audit.snapshot(cleanup_error_codes)
        if primary_error is not None:
            raise DynamicBrowserError(
                primary_error.code,
                str(primary_error),
                cleanup_error_codes=cleanup_error_codes,
                audit=summary,
            ) from None
        if cleanup_error_codes:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.CLEANUP_FAILED,
                "Managed browser cleanup did not complete.",
                cleanup_error_codes=cleanup_error_codes,
                audit=summary,
            )
        if not value_set:
            raise DynamicBrowserError(
                DynamicBrowserErrorCode.OPERATION_FAILED,
                "Managed browser operation did not produce a result.",
                audit=summary,
            )
        return DynamicBrowserRunResult(value=value, audit=summary)
