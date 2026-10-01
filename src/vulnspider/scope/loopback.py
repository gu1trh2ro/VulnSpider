"""Shared validation for explicit loopback HTTP request authorities."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from ipaddress import ip_address
from urllib.parse import urlsplit

_AUTHORIZED_ORIGIN: ContextVar[tuple[str, str, int] | None] = ContextVar(
    "vulnspider_authorized_origin", default=None
)


class LoopbackSafetyError(ValueError):
    """Raised when an HTTP URL is not an explicit loopback target."""


def _http_origin(url: str) -> tuple[str, str, int]:
    if type(url) is not str or not url or url != url.strip():
        raise LoopbackSafetyError(
            "request URL must be an absolute loopback HTTP(S) URL"
        )
    if any(character.isspace() or ord(character) < 32 for character in url):
        raise LoopbackSafetyError("request URL contains invalid characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise LoopbackSafetyError("request URL authority is malformed") from exc
    hostname = parts.hostname
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.netloc
        or hostname is None
        or parts.username is not None
        or parts.password is not None
        or (port is not None and port <= 0)
    ):
        raise LoopbackSafetyError(
            "request URL must use a credential-free loopback HTTP(S) authority"
        )
    return (parts.scheme.lower(), hostname.casefold(), port or (
        443 if parts.scheme.lower() == "https" else 80
    ))


@contextmanager
def authorized_http_origin(url: str | None) -> Iterator[None]:
    """Authorize exactly one explicit origin for this execution context."""

    origin = None if url is None else _http_origin(url)
    token = _AUTHORIZED_ORIGIN.set(origin)
    try:
        yield
    finally:
        _AUTHORIZED_ORIGIN.reset(token)


def current_authorized_http_origin() -> str | None:
    """Return the explicit authority for the supervised local browser worker."""

    origin = _AUTHORIZED_ORIGIN.get()
    if origin is None:
        return None
    scheme, host, port = origin
    authority = f"[{host}]" if ":" in host else host
    return f"{scheme}://{authority}:{port}/"


def require_loopback_http_url(url: str) -> None:
    """Require loopback by default, or the explicitly authorized scan origin."""

    origin = _http_origin(url)
    authorized = _AUTHORIZED_ORIGIN.get()
    if authorized is not None:
        if origin != authorized:
            raise LoopbackSafetyError("request URL escaped the authorized scan origin")
        return
    hostname = origin[1]
    if hostname == "localhost":
        return
    try:
        address = ip_address(hostname)
    except ValueError as exc:
        raise LoopbackSafetyError(
            "request URL host must be localhost or a loopback IP"
        ) from exc
    if not address.is_loopback:
        raise LoopbackSafetyError(
            "request URL host must be localhost or a loopback IP"
        )
