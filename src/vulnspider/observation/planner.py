"""Deterministic baseline and one-at-a-time probe request planning."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, unquote_plus, urlencode, urlsplit, urlunsplit

from vulnspider.domain import (
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ParamPairs,
    ProbeFamily,
    ProbePlan,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
    normalize_parameter_name,
    stable_fingerprint,
    validate_input_point_request_context,
)

DEFAULT_MARKER_STRATEGY = "neutral-reflection-marker-v1"
MARKER_PREFIX = "VULNSPIDER_"
MARKER_TOKEN_LENGTH = 16
RAW_QUERY_ALIGNMENT_FAILED = "raw-query-alignment-failed"


class ProbePlanningError(ValueError):
    """Raised when a request context cannot safely produce a probe plan."""


@dataclass(frozen=True, slots=True)
class ProbePlanner:
    probe_family: ProbeFamily = ProbeFamily.REFLECTION_MARKER
    marker_strategy: str = DEFAULT_MARKER_STRATEGY

    def plan(
        self,
        input_point: InputPoint,
        request_template: RequestTemplate,
        request_context: InputPointRequestContext,
    ) -> ProbePlan:
        return plan_probe_request(
            input_point=input_point,
            request_template=request_template,
            request_context=request_context,
            probe_family=self.probe_family,
            marker_strategy=self.marker_strategy,
        )


def plan_probe_request(
    *,
    input_point: InputPoint,
    request_template: RequestTemplate,
    request_context: InputPointRequestContext,
    probe_family: ProbeFamily = ProbeFamily.REFLECTION_MARKER,
    marker_strategy: str = DEFAULT_MARKER_STRATEGY,
) -> ProbePlan:
    """Create baseline and probe requests for one selected validated context."""

    _validate_planning_inputs(input_point, request_template, request_context)
    _reject_non_probe_ready(request_template)

    target_pairs = _pairs_for_location(input_point.location, request_template)
    pair_index, baseline_value = _target_pair_index(input_point, target_pairs)
    marker = deterministic_probe_marker(
        input_point=input_point,
        request_template=request_template,
        request_context=request_context,
        probe_family=probe_family,
        marker_strategy=marker_strategy,
        baseline_value=baseline_value,
    )
    probe_query = request_template.query
    probe_form = request_template.form
    if input_point.location == InputLocation.QUERY:
        probe_query = _replace_pair_value(request_template.query, pair_index, marker)
    elif input_point.location == InputLocation.FORM:
        probe_form = _replace_pair_value(request_template.form, pair_index, marker)
    else:
        raise ProbePlanningError(
            f"location {input_point.location.value} cannot be probed by v0.1 planner"
        )

    baseline_request = _request_instance_from_template(request_template)
    probe_request = RequestInstance(
        method=request_template.method,
        url=_probe_url(
            request_template,
            probe_query,
            changed_query_index=(
                pair_index if input_point.location == InputLocation.QUERY else None
            ),
            marker=marker,
        ),
        headers=request_template.headers,
        query=probe_query,
        form=probe_form,
        cookies=request_template.cookies,
    )
    return ProbePlan(
        input_point_id=input_point.id or "",
        probe_family=probe_family,
        baseline_request=baseline_request,
        probe_request=probe_request,
        changed_fields=(_changed_field(input_point),),
        request_template_id=request_template.id,
        request_context_id=request_context.id,
        probe_marker=marker,
        marker_strategy=marker_strategy,
    )


def deterministic_probe_marker(
    *,
    input_point: InputPoint,
    request_template: RequestTemplate,
    request_context: InputPointRequestContext,
    probe_family: ProbeFamily = ProbeFamily.REFLECTION_MARKER,
    marker_strategy: str = DEFAULT_MARKER_STRATEGY,
    baseline_value: str | None = None,
) -> str:
    """Return a bounded neutral marker reproducible from planning inputs."""

    family = ProbeFamily(probe_family)
    for nonce in range(10):
        fingerprint = stable_fingerprint(
            "probe-marker",
            marker_strategy,
            family.value,
            input_point.id,
            request_template.id,
            request_context.id,
            input_point.location.value,
            input_point.name,
            input_point.occurrence_index,
            nonce,
        )
        marker = f"{MARKER_PREFIX}{fingerprint[:MARKER_TOKEN_LENGTH].upper()}"
        if marker != baseline_value:
            return marker
    raise ProbePlanningError("could not generate a marker distinct from baseline")


def _validate_planning_inputs(
    input_point: InputPoint,
    request_template: RequestTemplate,
    request_context: InputPointRequestContext,
) -> None:
    if not isinstance(input_point, InputPoint):
        raise ProbePlanningError("input_point must be an InputPoint")
    if not isinstance(request_template, RequestTemplate):
        raise ProbePlanningError("request_template must be a RequestTemplate")
    if not isinstance(request_context, InputPointRequestContext):
        raise ProbePlanningError(
            "request_context must be an InputPointRequestContext"
        )
    if request_context.input_point_id != input_point.id:
        raise ProbePlanningError("request context does not target this InputPoint")
    if request_context.request_template_id != request_template.id:
        raise ProbePlanningError(
            "request context does not target this RequestTemplate"
        )
    if request_context.role != "baseline":
        raise ProbePlanningError("request context role must be baseline")
    try:
        validate_input_point_request_context(input_point, request_template)
    except ValueError as exc:
        raise ProbePlanningError(str(exc)) from exc


def _reject_non_probe_ready(request_template: RequestTemplate) -> None:
    reasons: list[str] = []
    if request_template.completeness != RequestContextCompleteness.COMPLETE:
        reasons.append(f"completeness={request_template.completeness.value}")

    metadata = request_template.metadata
    structured_reasons = metadata.get("non_probe_ready_reasons")
    if isinstance(structured_reasons, tuple | list):
        reasons.extend(str(reason) for reason in structured_reasons)
    elif structured_reasons:
        reasons.append(str(structured_reasons))

    reconstruction_status = metadata.get("reconstruction_status")
    if reconstruction_status in {"ambiguous", "partial"}:
        reasons.append(f"reconstruction_status={reconstruction_status}")

    form_boundary_status = metadata.get("form_boundary_status")
    if form_boundary_status == "unavailable":
        reasons.append("form_boundary_status=unavailable")

    for key in ("form_method_provenance", "form_action_provenance"):
        provenance = metadata.get(key)
        if isinstance(provenance, str) and provenance != "explicit":
            reasons.append(f"{key}={provenance}")

    if reasons:
        unique_reasons = tuple(dict.fromkeys(reasons))
        raise ProbePlanningError(
            "request context is not probe-ready: " + ", ".join(unique_reasons)
        )


def _pairs_for_location(
    location: InputLocation,
    request_template: RequestTemplate,
) -> ParamPairs:
    if location == InputLocation.QUERY:
        return request_template.query
    if location == InputLocation.FORM:
        return request_template.form
    raise ProbePlanningError(f"unsupported InputPoint location: {location.value}")


def _target_pair_index(
    input_point: InputPoint,
    pairs: ParamPairs,
) -> tuple[int, str]:
    matches = [
        (index, value)
        for index, (name, value) in enumerate(pairs)
        if normalize_parameter_name(name) == input_point.name
    ]
    if not matches:
        raise ProbePlanningError("InputPoint target is missing from RequestTemplate")

    if input_point.occurrence_index is None:
        if len(matches) != 1:
            raise ProbePlanningError(
                "repeated target requires an occurrence-level InputPoint"
            )
        return matches[0]

    if input_point.occurrence_index >= len(matches):
        raise ProbePlanningError("InputPoint occurrence_index is out of range")
    return matches[input_point.occurrence_index]


def _replace_pair_value(pairs: ParamPairs, pair_index: int, value: str) -> ParamPairs:
    return tuple(
        (name, value if index == pair_index else pair_value)
        for index, (name, pair_value) in enumerate(pairs)
    )


def _request_instance_from_template(request_template: RequestTemplate) -> RequestInstance:
    return RequestInstance(
        method=request_template.method,
        url=request_template.url,
        headers=request_template.headers,
        query=request_template.query,
        form=request_template.form,
        cookies=request_template.cookies,
    )


def _probe_url(
    request_template: RequestTemplate,
    probe_query: ParamPairs,
    *,
    changed_query_index: int | None = None,
    marker: str | None = None,
) -> str:
    if request_template.query == probe_query:
        return request_template.url
    parts = urlsplit(request_template.url)
    if changed_query_index is not None and marker is not None:
        raw_query = _replace_raw_query_value(
            raw_query=parts.query,
            original_query=request_template.query,
            changed_query_index=changed_query_index,
            marker=marker,
        )
        if raw_query is not None:
            return urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    raw_query,
                    parts.fragment,
                )
            )
        if _url_has_raw_query(request_template.url):
            raise ProbePlanningError(RAW_QUERY_ALIGNMENT_FAILED)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(probe_query),
            parts.fragment,
        )
    )


def _replace_raw_query_value(
    *,
    raw_query: str,
    original_query: ParamPairs,
    changed_query_index: int,
    marker: str,
) -> str | None:
    raw_tokens = raw_query.split("&") if raw_query else []
    if len(raw_tokens) != len(original_query):
        return None

    decoded_pairs: list[tuple[str, str]] = []
    for token in raw_tokens:
        raw_name, raw_value = _split_raw_query_token(token)
        decoded_pairs.append((unquote_plus(raw_name), unquote_plus(raw_value)))
    if tuple(decoded_pairs) != original_query:
        return None

    mutated_tokens = list(raw_tokens)
    raw_name, _raw_value = _split_raw_query_token(mutated_tokens[changed_query_index])
    mutated_tokens[changed_query_index] = f"{raw_name}={quote(marker, safe='')}"
    return "&".join(mutated_tokens)


def _split_raw_query_token(token: str) -> tuple[str, str]:
    if "=" not in token:
        return token, ""
    raw_name, raw_value = token.split("=", 1)
    return raw_name, raw_value


def _url_has_raw_query(url: str) -> bool:
    return "?" in url.split("#", 1)[0]


def _changed_field(input_point: InputPoint) -> str:
    location = input_point.location.value.lower()
    if input_point.occurrence_index is None:
        return f"{location}.{input_point.name}"
    return f"{location}.{input_point.name}[{input_point.occurrence_index}]"
