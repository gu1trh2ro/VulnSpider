"""Minimal v0.1 feature extraction from one baseline/probe response pair."""

from __future__ import annotations

import re
from dataclasses import dataclass

from spiderman.domain import (
    FeatureObservation,
    FeatureVector,
    InputPoint,
    ProbePlan,
    ResponsePair,
    ResponseSnapshot,
)

FEATURE_SCHEMA_VERSION = "feature-v0.1"
DIFFERENTIAL_EXTRACTOR_VERSION = "differential-v1"
REFLECTION_EXTRACTOR_VERSION = "reflection-v1"
SQL_EXTRACTOR_VERSION = "sql-signal-v1"

STATUS_CODE_CHANGED = "status_code_changed"
RESPONSE_LENGTH_DIFF_RATIO = "response_length_diff_ratio"
MARKER_REFLECTED = "marker_reflected"
SQL_ERROR_PATTERN = "sql_error_pattern"
REQUEST_ROLE_BASELINE = "baseline"
REQUEST_ROLE_PROBE = "probe"

SQL_ERROR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("sql_syntax", r"\bSQL syntax\b"),
    ("sqlstate", r"\bSQLSTATE\b"),
    ("mysql", r"\bMySQL\b|\bMariaDB\b"),
    ("postgresql", r"\bPostgreSQL\b|unterminated quoted string"),
    ("sqlite", r"\bSQLite\b|near .{0,40}: syntax error"),
    ("oracle", r"\bORA-\d{5}\b"),
    ("odbc", r"\bODBC\b"),
    ("mssql", r"Unclosed quotation mark|Microsoft SQL Server"),
)


class FeatureExtractionError(ValueError):
    """Raised when one response pair cannot be attributed to one probe plan."""


@dataclass(frozen=True, slots=True)
class MinimalFeatureExtractor:
    def extract(
        self,
        input_point: InputPoint,
        probe_plan: ProbePlan,
        response_pair: ResponsePair,
        baseline_response: ResponseSnapshot,
        probe_response: ResponseSnapshot,
    ) -> FeatureVector:
        return extract_minimal_features(
            input_point,
            probe_plan,
            response_pair,
            baseline_response,
            probe_response,
        )


def extract_minimal_features(
    input_point: InputPoint,
    probe_plan: ProbePlan,
    response_pair: ResponsePair,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureVector:
    _validate_feature_inputs(
        input_point,
        probe_plan,
        response_pair,
        baseline_response,
        probe_response,
    )
    if baseline_response.execution_error or probe_response.execution_error:
        features = _missing_features_for_execution_error(
            baseline_response,
            probe_response,
        )
    else:
        features = {
            STATUS_CODE_CHANGED: _status_code_changed(
                baseline_response,
                probe_response,
            ),
            RESPONSE_LENGTH_DIFF_RATIO: _response_length_diff_ratio(
                baseline_response,
                probe_response,
            ),
            MARKER_REFLECTED: _marker_reflected(probe_plan, baseline_response, probe_response),
            SQL_ERROR_PATTERN: _sql_error_pattern(baseline_response, probe_response),
        }
    return FeatureVector(
        input_point_id=input_point.id or "",
        probe_run_ids=(response_pair.id or "",),
        features=features,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def _validate_feature_inputs(
    input_point: InputPoint,
    probe_plan: ProbePlan,
    response_pair: ResponsePair,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> None:
    if not isinstance(input_point, InputPoint):
        raise FeatureExtractionError("input_point must be an InputPoint")
    if not isinstance(probe_plan, ProbePlan):
        raise FeatureExtractionError("probe_plan must be a ProbePlan")
    if response_pair.input_point_id != input_point.id:
        raise FeatureExtractionError("ResponsePair does not target this InputPoint")
    if probe_plan.input_point_id != input_point.id:
        raise FeatureExtractionError("ProbePlan does not target this InputPoint")
    if response_pair.probe_plan_id != probe_plan.id:
        raise FeatureExtractionError("ResponsePair does not target this ProbePlan")
    if response_pair.baseline_response_id != baseline_response.id:
        raise FeatureExtractionError("baseline ResponseSnapshot mismatch")
    if response_pair.probe_response_id != probe_response.id:
        raise FeatureExtractionError("probe ResponseSnapshot mismatch")
    _validate_response_ownership(
        label=REQUEST_ROLE_BASELINE,
        response=baseline_response,
        expected_probe_plan_id=probe_plan.id or "",
        expected_request_role=REQUEST_ROLE_BASELINE,
        expected_request_id=probe_plan.baseline_request.id or "",
    )
    _validate_response_ownership(
        label=REQUEST_ROLE_PROBE,
        response=probe_response,
        expected_probe_plan_id=probe_plan.id or "",
        expected_request_role=REQUEST_ROLE_PROBE,
        expected_request_id=probe_plan.probe_request.id or "",
    )


def _validate_response_ownership(
    *,
    label: str,
    response: ResponseSnapshot,
    expected_probe_plan_id: str,
    expected_request_role: str,
    expected_request_id: str,
) -> None:
    if response.probe_plan_id != expected_probe_plan_id:
        raise FeatureExtractionError(
            f"{label} response ProbePlan provenance mismatch"
        )
    if response.request_role != expected_request_role:
        raise FeatureExtractionError(f"{label} response role mismatch")
    if response.request_id != expected_request_id:
        raise FeatureExtractionError(f"{label} response request mismatch")


def _status_code_changed(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    value = 1.0 if baseline_response.status_code != probe_response.status_code else 0.0
    return FeatureObservation(
        name=STATUS_CODE_CHANGED,
        value=value,
        observed=True,
        source="response_diff",
        extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "baseline_status_code": baseline_response.status_code,
            "probe_status_code": probe_response.status_code,
        },
    )


def _response_length_diff_ratio(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    baseline_length = baseline_response.body_length_bytes
    probe_length = probe_response.body_length_bytes
    raw_ratio = abs(probe_length - baseline_length) / max(baseline_length, 1)
    value = min(raw_ratio, 1.0)
    return FeatureObservation(
        name=RESPONSE_LENGTH_DIFF_RATIO,
        value=value,
        observed=True,
        source="response_diff",
        extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "baseline_length": baseline_length,
            "probe_length": probe_length,
            "raw_ratio": raw_ratio,
            "formula": "abs(probe-baseline)/max(baseline,1), clipped to 1.0",
        },
    )


def _marker_reflected(
    probe_plan: ProbePlan,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    marker = probe_plan.probe_marker
    if not marker:
        return FeatureObservation.missing(
            MARKER_REFLECTED,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details={"reason": "probe-marker-missing"},
        )
    baseline_text = baseline_response.decoded_text or ""
    probe_text = probe_response.decoded_text or ""
    baseline_contains = marker in baseline_text
    probe_contains = marker in probe_text
    value = 1.0 if probe_contains and not baseline_contains else 0.0
    return FeatureObservation(
        name=MARKER_REFLECTED,
        value=value,
        observed=True,
        source="reflection_marker_probe",
        extractor_version=REFLECTION_EXTRACTOR_VERSION,
        details={
            "marker": marker,
            "baseline_contains_marker": baseline_contains,
            "probe_contains_marker": probe_contains,
        },
    )


def _sql_error_pattern(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    baseline_patterns = _matched_sql_patterns(baseline_response.decoded_text or "")
    probe_patterns = _matched_sql_patterns(probe_response.decoded_text or "")
    new_patterns = tuple(
        pattern for pattern in probe_patterns if pattern not in baseline_patterns
    )
    value = 1.0 if new_patterns else 0.0
    return FeatureObservation(
        name=SQL_ERROR_PATTERN,
        value=value,
        observed=True,
        source="sql_error_probe",
        extractor_version=SQL_EXTRACTOR_VERSION,
        details={
            "baseline_patterns": baseline_patterns,
            "probe_patterns": probe_patterns,
            "new_patterns": new_patterns,
        },
    )


def _missing_features_for_execution_error(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> dict[str, FeatureObservation]:
    details = {
        "reason": "execution-error",
        "baseline_execution_error": baseline_response.execution_error,
        "probe_execution_error": probe_response.execution_error,
    }
    return {
        STATUS_CODE_CHANGED: FeatureObservation.missing(
            STATUS_CODE_CHANGED,
            source="response_diff",
            extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
        RESPONSE_LENGTH_DIFF_RATIO: FeatureObservation.missing(
            RESPONSE_LENGTH_DIFF_RATIO,
            source="response_diff",
            extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
        MARKER_REFLECTED: FeatureObservation.missing(
            MARKER_REFLECTED,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details=details,
        ),
        SQL_ERROR_PATTERN: FeatureObservation.missing(
            SQL_ERROR_PATTERN,
            source="sql_error_probe",
            extractor_version=SQL_EXTRACTOR_VERSION,
            details=details,
        ),
    }


def _matched_sql_patterns(text: str) -> tuple[str, ...]:
    matches: list[str] = []
    for name, pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(name)
    return tuple(matches)
