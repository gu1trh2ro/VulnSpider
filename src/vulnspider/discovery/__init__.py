"""Discovery package."""

from vulnspider.discovery.contracts import (
    BACStaticHint,
    CONTRACT_VERSION,
    CanonicalDiscoveryResult,
    CollectorKind,
    CrawlStatistics,
    DiscoveryContractError,
    DiscoveryMetadata,
    DiscoveryProvenance,
    DiscoverySubjectKind,
    DiscoveryWarning,
    NonProbeReadyReason,
    ProbeReadiness,
    ProbeReadyStatus,
    ScopeMetadata,
    discovery_run_id_for,
    scope_id_for_root,
)
from vulnspider.discovery.html_extractor import (
    NavigableLink,
    StaticExtractionResult,
    extract_static_html,
)
from vulnspider.discovery.legacy_adapter import (
    LegacyAdapterResult,
    LegacyCrawlerAdapter,
    LegacyCrawlRecord,
)

__all__ = [
    "BACStaticHint",
    "CONTRACT_VERSION",
    "CanonicalDiscoveryResult",
    "CollectorKind",
    "CrawlStatistics",
    "DiscoveryContractError",
    "DiscoveryMetadata",
    "DiscoveryProvenance",
    "DiscoverySubjectKind",
    "DiscoveryWarning",
    "LegacyAdapterResult",
    "LegacyCrawlerAdapter",
    "LegacyCrawlRecord",
    "NavigableLink",
    "NonProbeReadyReason",
    "ProbeReadiness",
    "ProbeReadyStatus",
    "ScopeMetadata",
    "StaticExtractionResult",
    "discovery_run_id_for",
    "extract_static_html",
    "scope_id_for_root",
]
