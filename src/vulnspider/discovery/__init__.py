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
    "NonProbeReadyReason",
    "ProbeReadiness",
    "ProbeReadyStatus",
    "ScopeMetadata",
    "discovery_run_id_for",
    "scope_id_for_root",
]
