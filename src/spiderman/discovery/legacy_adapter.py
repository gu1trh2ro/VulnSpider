"""Adapter for legacy WHSPIDER crawl records.

The adapter is intentionally pure: it does not import or execute the legacy
crawler, perform network I/O, or depend on the old SQLite schema at runtime.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from spiderman.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    RequestTemplate,
)


@dataclass(frozen=True, slots=True)
class LegacyCrawlRecord:
    link: str
    parent: str | None = None
    depth: int | None = None
    host: str | None = None
    query_params: str | Mapping[str, Any] | None = None
    input_fields: str | Sequence[Mapping[str, Any]] | None = None
    collected_time: str | None = None
    source: str = "legacy_static"

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> LegacyCrawlRecord:
        return cls(
            link=str(raw.get("link") or raw.get("url") or ""),
            parent=_optional_str(raw.get("parent")),
            depth=_optional_int(raw.get("depth")),
            host=_optional_str(raw.get("host")),
            query_params=raw.get("query_params"),
            input_fields=raw.get("input_fields"),
            collected_time=_optional_str(raw.get("collected_time")),
            source=str(raw.get("source") or "legacy_static"),
        )


@dataclass(frozen=True, slots=True)
class LegacyAdapterResult:
    endpoints: tuple[Endpoint, ...]
    input_points: tuple[InputPoint, ...]
    request_templates: tuple[RequestTemplate, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)


class LegacyCrawlerAdapter:
    def convert(
        self,
        records: Sequence[LegacyCrawlRecord | Mapping[str, Any]],
    ) -> LegacyAdapterResult:
        endpoints: dict[str, Endpoint] = {}
        input_points: dict[str, InputPoint] = {}
        request_templates: dict[str, RequestTemplate] = {}
        warnings: list[str] = []

        normalized_records = [
            record
            if isinstance(record, LegacyCrawlRecord)
            else LegacyCrawlRecord.from_mapping(record)
            for record in records
        ]

        for record in sorted(normalized_records, key=_record_sort_key):
            if not record.link:
                warnings.append("legacy record skipped: missing link")
                continue
            page_parts = urlsplit(record.link)
            if not page_parts.scheme or not page_parts.netloc:
                warnings.append(f"legacy record skipped: invalid link: {record.link}")
                continue

            query_values = _parse_query_params(record, warnings)
            if query_values:
                endpoint = _endpoint_from_url(record.link, HttpMethod.GET)
                endpoints.setdefault(endpoint.fingerprint, endpoint)
                request_template = _query_request_template(endpoint, record.link)
                request_templates.setdefault(request_template.id or "", request_template)
                for name, value in sorted(query_values.items()):
                    input_point = InputPoint(
                        endpoint_id=endpoint.fingerprint,
                        location=InputLocation.QUERY,
                        name=name,
                        baseline_value=_baseline_value(value),
                        source_page=record.link,
                        metadata={
                            "legacy_source": record.source,
                            "legacy_parent": record.parent,
                            "legacy_depth": record.depth,
                        },
                    )
                    input_points.setdefault(input_point.fingerprint, input_point)

            fields = _parse_input_fields(record, warnings)
            for field in fields:
                name = _optional_str(field.get("name"))
                if not name:
                    warnings.append(
                        f"legacy form field skipped on {record.link}: missing name"
                    )
                    continue
                method = _form_method(field, record, warnings)
                action = _optional_str(field.get("form_action")) or record.link
                form_url = urljoin(record.link, action)
                endpoint = _endpoint_from_url(form_url, method)
                endpoints.setdefault(endpoint.fingerprint, endpoint)
                request_template = _form_request_template(
                    endpoint,
                    form_url,
                    _form_values_for_template(fields, method, action, record.link),
                )
                request_templates.setdefault(request_template.id or "", request_template)

                type_hint = _optional_str(field.get("type"))
                hidden = (type_hint or "").strip().lower() == "hidden"
                input_point = InputPoint(
                    endpoint_id=endpoint.fingerprint,
                    location=InputLocation.FORM,
                    name=name,
                    baseline_value=_optional_str(field.get("value")),
                    type_hint=type_hint,
                    source_page=record.link,
                    metadata={
                        "legacy_source": record.source,
                        "legacy_parent": record.parent,
                        "legacy_depth": record.depth,
                        "form_action": action,
                        "form_method": method.value,
                        "hidden": hidden,
                        "visibility": "hidden" if hidden else "visible",
                    },
                )
                input_points.setdefault(input_point.fingerprint, input_point)

        return LegacyAdapterResult(
            endpoints=tuple(sorted(endpoints.values(), key=lambda item: item.fingerprint)),
            input_points=tuple(
                sorted(input_points.values(), key=lambda item: item.fingerprint)
            ),
            request_templates=tuple(
                sorted(
                    request_templates.values(),
                    key=lambda item: item.id or "",
                )
            ),
            warnings=tuple(warnings),
        )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_sort_key(record: LegacyCrawlRecord) -> tuple[str, str, str]:
    return (record.link, record.collected_time or "", record.source)


def _parse_json_object(raw: Any, *, label: str, link: str, warnings: list[str]) -> Any:
    if raw is None or raw == "":
        return {} if label == "query_params" else []
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            warnings.append(f"{label} on {link} is not valid JSON")
            return {} if label == "query_params" else []
    return raw


def _parse_query_params(
    record: LegacyCrawlRecord,
    warnings: list[str],
) -> dict[str, Any]:
    parsed = _parse_json_object(
        record.query_params,
        label="query_params",
        link=record.link,
        warnings=warnings,
    )
    values: dict[str, Any] = {}
    if isinstance(parsed, Mapping):
        values.update({str(key): value for key, value in parsed.items()})
    elif parsed:
        warnings.append(f"query_params on {record.link} is not an object")

    if not values:
        url_values = parse_qsl(urlsplit(record.link).query, keep_blank_values=True)
        values.update({key: value for key, value in url_values})
    return values


def _parse_input_fields(
    record: LegacyCrawlRecord,
    warnings: list[str],
) -> tuple[Mapping[str, Any], ...]:
    parsed = _parse_json_object(
        record.input_fields,
        label="input_fields",
        link=record.link,
        warnings=warnings,
    )
    if parsed in ({}, None):
        return ()
    if not isinstance(parsed, Sequence) or isinstance(parsed, str):
        warnings.append(f"input_fields on {record.link} is not a list")
        return ()
    fields: list[Mapping[str, Any]] = []
    for item in parsed:
        if isinstance(item, Mapping):
            fields.append(item)
        else:
            warnings.append(f"input_fields on {record.link} contains non-object item")
    return tuple(fields)


def _baseline_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _form_method(
    field: Mapping[str, Any],
    record: LegacyCrawlRecord,
    warnings: list[str],
) -> HttpMethod:
    raw = (_optional_str(field.get("form_method")) or "GET").strip().upper()
    try:
        return HttpMethod(raw)
    except ValueError:
        warnings.append(
            f"form field {field.get('name')!r} on {record.link}: "
            f"unsupported method {raw!r}; defaulted to GET"
        )
        return HttpMethod.GET


def _endpoint_from_url(url: str, method: HttpMethod) -> Endpoint:
    parts = urlsplit(url)
    return Endpoint(
        method=method,
        scheme=parts.scheme,
        host=parts.netloc,
        path=parts.path or "/",
        discovered_by="legacy_whspider",
    )


def _query_request_template(endpoint: Endpoint, url: str) -> RequestTemplate:
    parts = urlsplit(url)
    return RequestTemplate(
        endpoint_id=endpoint.fingerprint,
        method=HttpMethod.GET,
        url=url,
        query=dict(parse_qsl(parts.query, keep_blank_values=True)),
    )


def _form_values_for_template(
    fields: Sequence[Mapping[str, Any]],
    target_method: HttpMethod,
    target_action: str,
    page_url: str,
) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in fields:
        raw_method = (_optional_str(field.get("form_method")) or "GET").strip().upper()
        try:
            method = HttpMethod(raw_method)
        except ValueError:
            method = HttpMethod.GET
        action = _optional_str(field.get("form_action")) or page_url
        if method != target_method or action != target_action:
            continue
        name = _optional_str(field.get("name"))
        if name:
            values[name] = _optional_str(field.get("value")) or ""
    return values


def _form_request_template(
    endpoint: Endpoint,
    form_url: str,
    form_values: Mapping[str, str],
) -> RequestTemplate:
    return RequestTemplate(
        endpoint_id=endpoint.fingerprint,
        method=endpoint.method,
        url=form_url,
        form=dict(sorted(form_values.items())),
    )
