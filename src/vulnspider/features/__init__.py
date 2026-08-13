"""Feature extraction package."""

from vulnspider.features.extraction import (
    FEATURE_AGGREGATION_VERSION,
    FEATURE_SCHEMA_VERSION,
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
    FeatureExtractionError,
    MinimalFeatureExtractor,
    combine_input_point_features,
    extract_minimal_features,
)

__all__ = [
    "FEATURE_AGGREGATION_VERSION",
    "FEATURE_SCHEMA_VERSION",
    "MARKER_REFLECTED",
    "RESPONSE_LENGTH_DIFF_RATIO",
    "SQL_ERROR_PATTERN",
    "STATUS_CODE_CHANGED",
    "FeatureExtractionError",
    "MinimalFeatureExtractor",
    "combine_input_point_features",
    "extract_minimal_features",
]
