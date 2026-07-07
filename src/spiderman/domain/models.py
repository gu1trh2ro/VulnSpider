"""Typed domain objects for SPIDERMAN prototype v0.1."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Any, TypeAlias
from urllib.parse import urlsplit

JsonScalar: TypeAlias = float | bool | str | None


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class InputLocation(StrEnum):
    QUERY = "QUERY"
    FORM = "FORM"
    JSON = "JSON"
    PATH = "PATH"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    MULTIPART = "MULTIPART"


class ProbeFamily(StrEnum):
    REFLECTION_MARKER = "REFLECTION_MARKER"
    TYPE_PERTURBATION = "TYPE_PERTURBATION"
    GENERIC_PERTURBATION = "GENERIC_PERTURBATION"


class VulnerabilityType(StrEnum):
    SQLI = "SQLI"
    REFLECTED_XSS = "REFLECTED_XSS"


def _normalize_text(value: str | None) -> str:
    return (value or "").strip().lower()


def canonical_path(path: str) -> str:
    parsed = urlsplit(path)
    normalized = parsed.path or "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def stable_fingerprint(*parts: object) -> str:
    serialized = "\x1f".join(str(part) for part in parts)
    return sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Endpoint:
    method: HttpMethod
    scheme: str
    host: str
    path: str
    content_type: str | None = None
    discovered_by: str = "unknown"
    id: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        method = HttpMethod(self.method)
        normalized_scheme = _normalize_text(self.scheme)
        normalized_host = _normalize_text(self.host)
        normalized_path = canonical_path(self.path)
        fingerprint = endpoint_fingerprint(
            method=method,
            scheme=normalized_scheme,
            host=normalized_host,
            path=normalized_path,
        )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "scheme", normalized_scheme)
        object.__setattr__(self, "host", normalized_host)
        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "id", self.id or f"ep_{fingerprint[:16]}")


def endpoint_fingerprint(
    *,
    method: HttpMethod,
    scheme: str,
    host: str,
    path: str,
) -> str:
    return stable_fingerprint(
        "endpoint",
        HttpMethod(method).value,
        _normalize_text(scheme),
        _normalize_text(host),
        canonical_path(path),
    )


@dataclass(frozen=True, slots=True)
class InputPoint:
    endpoint_id: str
    location: InputLocation
    name: str
    baseline_value: str | None = None
    type_hint: str | None = None
    source_page: str | None = None
    auth_context_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        location = InputLocation(self.location)
        normalized_name = _normalize_text(self.name)
        if not normalized_name:
            raise ValueError("InputPoint.name must not be empty")
        fingerprint = input_point_fingerprint(
            endpoint_fingerprint=self.endpoint_id,
            location=location,
            name=normalized_name,
            auth_context_id=self.auth_context_id,
        )
        object.__setattr__(self, "location", location)
        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(self, "metadata", dict(self.metadata))
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "id", self.id or f"inp_{fingerprint[:16]}")


def input_point_fingerprint(
    *,
    endpoint_fingerprint: str,
    location: InputLocation,
    name: str,
    auth_context_id: str | None = None,
) -> str:
    return stable_fingerprint(
        "input-point",
        endpoint_fingerprint,
        InputLocation(location).value,
        _normalize_text(name),
        _normalize_text(auth_context_id),
    )


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    endpoint_id: str
    method: HttpMethod
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", HttpMethod(self.method))
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "query", dict(self.query))
        object.__setattr__(self, "form", dict(self.form))
        object.__setattr__(self, "cookies", dict(self.cookies))
        if not self.id:
            fingerprint = stable_fingerprint("request-template", self.endpoint_id, self.url)
            object.__setattr__(self, "id", f"rt_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class RequestInstance:
    method: HttpMethod
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", HttpMethod(self.method))
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "query", dict(self.query))
        object.__setattr__(self, "form", dict(self.form))
        object.__setattr__(self, "cookies", dict(self.cookies))
        if not self.id:
            fingerprint = stable_fingerprint(
                "request-instance",
                self.method.value,
                self.url,
                tuple(sorted(self.query.items())),
                tuple(sorted(self.form.items())),
            )
            object.__setattr__(self, "id", f"req_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ProbePlan:
    input_point_id: str
    probe_family: ProbeFamily
    baseline_request: RequestInstance
    probe_request: RequestInstance
    changed_fields: tuple[str, ...]
    id: str | None = None

    def __post_init__(self) -> None:
        changed_fields = tuple(self.changed_fields)
        if len(changed_fields) != 1:
            raise ValueError("ProbePlan must change exactly one InputPoint")
        object.__setattr__(self, "probe_family", ProbeFamily(self.probe_family))
        object.__setattr__(self, "changed_fields", changed_fields)
        if not self.id:
            fingerprint = stable_fingerprint(
                "probe-plan",
                self.input_point_id,
                self.probe_family.value,
                changed_fields[0],
            )
            object.__setattr__(self, "id", f"probe_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ResponseSnapshot:
    request_id: str
    status_code: int
    elapsed_ms: float
    body_bytes_hash: str
    body_length_bytes: int
    headers: dict[str, str] = field(default_factory=dict)
    decoded_text: str | None = None
    encoding: str | None = None
    redirect_location: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers))
        if not self.id:
            fingerprint = stable_fingerprint(
                "response-snapshot",
                self.request_id,
                self.status_code,
                self.body_bytes_hash,
            )
            object.__setattr__(self, "id", f"resp_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ResponsePair:
    input_point_id: str
    probe_plan_id: str
    baseline_response_id: str
    probe_response_id: str
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            fingerprint = stable_fingerprint(
                "response-pair",
                self.input_point_id,
                self.probe_plan_id,
                self.baseline_response_id,
                self.probe_response_id,
            )
            object.__setattr__(self, "id", f"pair_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class FeatureObservation:
    name: str
    value: JsonScalar
    observed: bool
    source: str
    extractor_version: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.observed and self.value is not None:
            raise ValueError("unobserved features must use value=None")
        object.__setattr__(self, "details", dict(self.details))

    @classmethod
    def missing(
        cls,
        name: str,
        *,
        source: str,
        extractor_version: str,
        details: dict[str, Any] | None = None,
    ) -> FeatureObservation:
        return cls(
            name=name,
            value=None,
            observed=False,
            source=source,
            extractor_version=extractor_version,
            details=details or {},
        )


@dataclass(frozen=True, slots=True)
class FeatureVector:
    input_point_id: str
    probe_run_ids: tuple[str, ...]
    features: dict[str, FeatureObservation]
    feature_schema_version: str = "feature-v0.1"
    id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "probe_run_ids", tuple(self.probe_run_ids))
        object.__setattr__(self, "features", dict(self.features))
        if not self.id:
            fingerprint = stable_fingerprint(
                "feature-vector",
                self.input_point_id,
                self.feature_schema_version,
                tuple(sorted(self.features)),
            )
            object.__setattr__(self, "id", f"fv_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class VulnerabilityCandidate:
    input_point_id: str
    vulnerability_type: VulnerabilityType
    rank_score: float | None = None
    scorer_version: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        vulnerability_type = VulnerabilityType(self.vulnerability_type)
        object.__setattr__(self, "vulnerability_type", vulnerability_type)
        if not self.id:
            fingerprint = stable_fingerprint(
                "candidate",
                self.input_point_id,
                vulnerability_type.value,
            )
            object.__setattr__(self, "id", f"cand_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ScoreEvidence:
    candidate_id: str
    feature_name: str
    feature_value: float
    weight: float
    contribution: float
    reason: str

