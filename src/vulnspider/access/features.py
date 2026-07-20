"""Feature extraction for one executed Broken Access Control (BAC) probe pair.

Same ``value``/``observed``/``source``/``extractor_version``/``details``
shape as ``vulnspider.features.extraction`` (docs/FEATURE_SCHEMA.md), but the
signal direction is inverted from the injection features: here a *high*
value means the comparison request was **not** denied something it should
have been denied, not that an injected value caused an observable change.
"""

from __future__ import annotations

from vulnspider.domain import AccessProbePlan, FeatureObservation, ResponseSnapshot

ACCESS_FEATURE_SCHEMA_VERSION = "access-feature-v0.1"
ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION = "access-differential-v1"

ACCESS_UNAUTHORIZED_SUCCESS = "access_unauthorized_success"
ACCESS_BODY_SIZE_SIMILARITY_RATIO = "access_body_size_similarity_ratio"

_REFERENCE_NOT_ELIGIBLE_REASON = "reference-request-did-not-succeed"
_EXECUTION_ERROR_REASON = "execution-error"


def _is_success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def extract_access_features(
    access_probe_plan: AccessProbePlan,
    reference_response: ResponseSnapshot,
    comparison_response: ResponseSnapshot,
) -> dict[str, FeatureObservation]:
    """Extract the two BAC features for one reference/comparison response pair.

    Both features require the reference request to have actually succeeded
    (2xx, no transport error): if the reference itself was not served, there
    is nothing to check the comparison request against, and both features are
    reported ``observed=False`` rather than guessed (AGENTS.md rule 9).
    """

    if reference_response.execution_error is not None:
        return _missing_features(
            details={
                "reason": _EXECUTION_ERROR_REASON,
                "reference_execution_error": reference_response.execution_error,
            }
        )
    if not _is_success_status(reference_response.status_code):
        return _missing_features(
            details={
                "reason": _REFERENCE_NOT_ELIGIBLE_REASON,
                "reference_status_code": reference_response.status_code,
            }
        )

    features = {
        ACCESS_UNAUTHORIZED_SUCCESS: _unauthorized_success(
            reference_response, comparison_response
        ),
    }
    if comparison_response.execution_error is not None:
        features[ACCESS_BODY_SIZE_SIMILARITY_RATIO] = FeatureObservation.missing(
            ACCESS_BODY_SIZE_SIMILARITY_RATIO,
            source="access_response_diff",
            extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
            details={
                "reason": _EXECUTION_ERROR_REASON,
                "comparison_execution_error": comparison_response.execution_error,
            },
        )
    else:
        features[ACCESS_BODY_SIZE_SIMILARITY_RATIO] = _body_size_similarity_ratio(
            reference_response, comparison_response
        )
    return features


def _unauthorized_success(
    reference_response: ResponseSnapshot,
    comparison_response: ResponseSnapshot,
) -> FeatureObservation:
    comparison_succeeded = (
        comparison_response.execution_error is None
        and _is_success_status(comparison_response.status_code)
    )
    value = 1.0 if comparison_succeeded else 0.0
    return FeatureObservation(
        name=ACCESS_UNAUTHORIZED_SUCCESS,
        value=value,
        observed=True,
        source="access_response_diff",
        extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "reference_status_code": reference_response.status_code,
            "comparison_status_code": comparison_response.status_code,
            "comparison_execution_error": comparison_response.execution_error,
        },
    )


def _body_size_similarity_ratio(
    reference_response: ResponseSnapshot,
    comparison_response: ResponseSnapshot,
) -> FeatureObservation:
    reference_length = reference_response.body_length_bytes
    comparison_length = comparison_response.body_length_bytes
    raw_diff_ratio = abs(comparison_length - reference_length) / max(reference_length, 1)
    value = 1.0 - min(raw_diff_ratio, 1.0)
    return FeatureObservation(
        name=ACCESS_BODY_SIZE_SIMILARITY_RATIO,
        value=value,
        observed=True,
        source="access_response_diff",
        extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "reference_length": reference_length,
            "comparison_length": comparison_length,
            "raw_diff_ratio": raw_diff_ratio,
            "formula": "1 - min(abs(comparison-reference)/max(reference,1), 1.0)",
        },
    )


def _missing_features(*, details: dict[str, object]) -> dict[str, FeatureObservation]:
    return {
        ACCESS_UNAUTHORIZED_SUCCESS: FeatureObservation.missing(
            ACCESS_UNAUTHORIZED_SUCCESS,
            source="access_response_diff",
            extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
        ACCESS_BODY_SIZE_SIMILARITY_RATIO: FeatureObservation.missing(
            ACCESS_BODY_SIZE_SIMILARITY_RATIO,
            source="access_response_diff",
            extractor_version=ACCESS_DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
    }
