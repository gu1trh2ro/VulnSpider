"""Request execution and response pairing for planned probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from time import monotonic
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from spiderman.domain import (
    ProbePlan,
    RequestInstance,
    ResponsePair,
    ResponseSnapshot,
)

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_BODY_BYTES = 1_000_000
EMPTY_BODY_HASH = sha256(b"").hexdigest()


class RequestExecutionError(RuntimeError):
    """Raised when planned request execution or response pairing is invalid."""


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status_code: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    encoding: str | None = None
    redirect_location: str | None = None


class RequestTransport(Protocol):
    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        """Send one planned request and return the captured response."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: object,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class UrlLibTransport:
    """Small standard-library HTTP transport with redirects disabled."""

    def __init__(self) -> None:
        self._opener = build_opener(_NoRedirectHandler)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        headers = dict(request.headers)
        if request.cookies and not _has_header(headers, "Cookie"):
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in request.cookies.items()
            )
        body = None
        if request.form:
            body = urlencode(request.form).encode("utf-8")
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        url_request = Request(
            request.url,
            data=body,
            headers=headers,
            method=request.method.value,
        )
        started = monotonic()
        try:
            with self._opener.open(url_request, timeout=timeout_seconds) as response:
                response_body = response.read()
                elapsed_ms = (monotonic() - started) * 1000.0
                response_headers = dict(response.headers.items())
                return TransportResponse(
                    status_code=response.status,
                    body=response_body,
                    headers=response_headers,
                    elapsed_ms=elapsed_ms,
                    encoding=response.headers.get_content_charset(),
                    redirect_location=response_headers.get("Location"),
                )
        except HTTPError as exc:
            response_body = exc.read()
            elapsed_ms = (monotonic() - started) * 1000.0
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            return TransportResponse(
                status_code=exc.code,
                body=response_body,
                headers=response_headers,
                elapsed_ms=elapsed_ms,
                encoding=exc.headers.get_content_charset() if exc.headers else None,
                redirect_location=response_headers.get("Location"),
            )
        except TimeoutError as exc:
            raise RequestExecutionError("timeout") from exc
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, TimeoutError):
                raise RequestExecutionError("timeout") from exc
            reason_name = type(reason).__name__ if reason is not None else type(exc).__name__
            raise RequestExecutionError(f"transport-error:{reason_name}") from exc
        except OSError as exc:
            raise RequestExecutionError(f"transport-error:{type(exc).__name__}") from exc


@dataclass(frozen=True, slots=True)
class ProbeExecutionResult:
    baseline_response: ResponseSnapshot
    probe_response: ResponseSnapshot
    response_pair: ResponsePair


@dataclass(frozen=True, slots=True)
class RequestExecutor:
    transport: RequestTransport = field(default_factory=UrlLibTransport)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES

    def execute_request(self, request: RequestInstance) -> ResponseSnapshot:
        return execute_request(
            request,
            transport=self.transport,
            timeout_seconds=self.timeout_seconds,
            max_body_bytes=self.max_body_bytes,
        )

    def execute_plan(self, probe_plan: ProbePlan) -> ProbeExecutionResult:
        return execute_probe_plan(
            probe_plan,
            transport=self.transport,
            timeout_seconds=self.timeout_seconds,
            max_body_bytes=self.max_body_bytes,
        )


def execute_probe_plan(
    probe_plan: ProbePlan,
    *,
    transport: RequestTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> ProbeExecutionResult:
    if not isinstance(probe_plan, ProbePlan):
        raise RequestExecutionError("probe_plan must be a ProbePlan")
    active_transport = transport or UrlLibTransport()
    baseline_response = execute_request(
        probe_plan.baseline_request,
        transport=active_transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    probe_response = execute_request(
        probe_plan.probe_request,
        transport=active_transport,
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
    )
    response_pair = pair_probe_responses(
        probe_plan,
        baseline_response,
        probe_response,
    )
    return ProbeExecutionResult(
        baseline_response=baseline_response,
        probe_response=probe_response,
        response_pair=response_pair,
    )


def execute_request(
    request: RequestInstance,
    *,
    transport: RequestTransport,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> ResponseSnapshot:
    if not isinstance(request, RequestInstance):
        raise RequestExecutionError("request must be a RequestInstance")
    if max_body_bytes < 0:
        raise RequestExecutionError("max_body_bytes must be non-negative")

    try:
        response = transport.send(request, timeout_seconds=timeout_seconds)
    except RequestExecutionError as exc:
        return _error_response_snapshot(request, str(exc))

    body = bytes(response.body)
    captured_body = body[:max_body_bytes]
    execution_error = None
    if len(body) > max_body_bytes:
        execution_error = "body-capture-limit-reached"
    return ResponseSnapshot(
        request_id=request.id or "",
        status_code=int(response.status_code),
        elapsed_ms=float(response.elapsed_ms),
        body_bytes_hash=sha256(captured_body).hexdigest(),
        body_length_bytes=len(body),
        headers=dict(response.headers),
        decoded_text=_decode_body(captured_body, response.encoding),
        encoding=response.encoding,
        redirect_location=response.redirect_location,
        execution_error=execution_error,
    )


def pair_probe_responses(
    probe_plan: ProbePlan,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> ResponsePair:
    if not isinstance(probe_plan, ProbePlan):
        raise RequestExecutionError("probe_plan must be a ProbePlan")
    if baseline_response.request_id != probe_plan.baseline_request.id:
        raise RequestExecutionError("baseline response does not match ProbePlan")
    if probe_response.request_id != probe_plan.probe_request.id:
        raise RequestExecutionError("probe response does not match ProbePlan")
    return ResponsePair(
        input_point_id=probe_plan.input_point_id,
        probe_plan_id=probe_plan.id or "",
        baseline_response_id=baseline_response.id or "",
        probe_response_id=probe_response.id or "",
    )


def _decode_body(body: bytes, encoding: str | None) -> str:
    preferred = encoding or "utf-8"
    try:
        return body.decode(preferred, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _error_response_snapshot(
    request: RequestInstance,
    execution_error: str,
) -> ResponseSnapshot:
    return ResponseSnapshot(
        request_id=request.id or "",
        status_code=0,
        elapsed_ms=0.0,
        body_bytes_hash=EMPTY_BODY_HASH,
        body_length_bytes=0,
        decoded_text=None,
        execution_error=execution_error,
    )


def _has_header(headers: dict[str, str], name: str) -> bool:
    normalized = name.lower()
    return any(header_name.lower() == normalized for header_name in headers)
