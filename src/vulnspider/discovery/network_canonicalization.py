"""Transport-free canonicalization of already-authorized browser GET candidates."""

from __future__ import annotations

from collections import Counter

from vulnspider.discovery.contracts import (
    CanonicalDiscoveryResult,
    DiscoveryMetadata,
    DiscoverySafetyInvariant,
    NonProbeReadyReason,
    ScopeMetadata,
)
from vulnspider.discovery.dynamic_browser import (
    NetworkDiscoveryCandidate,
    NetworkDiscoveryCollection,
    NetworkDiscoveryDisposition,
)
from vulnspider.discovery.html_extractor import CanonicalDiscoveryBuilder
from vulnspider.discovery.static_crawler import same_origin_crawl_url


def canonicalize_network_discovery(
    collection: NetworkDiscoveryCollection,
    *,
    discovery_metadata: DiscoveryMetadata,
    scope_metadata: ScopeMetadata,
) -> tuple[CanonicalDiscoveryResult, ...]:
    """Build deterministic Dynamic components without issuing any request."""

    if type(collection) is not NetworkDiscoveryCollection:
        raise TypeError("collection must be NetworkDiscoveryCollection")
    by_source: dict[str, list[NetworkDiscoveryCandidate]] = {}
    for candidate in collection.candidates:
        if not same_origin_crawl_url(scope_metadata.root_url, candidate.source_url):
            raise ValueError("network discovery source escaped canonical scope")
        if not same_origin_crawl_url(scope_metadata.root_url, candidate.base_url):
            raise ValueError("network discovery endpoint escaped canonical scope")
        by_source.setdefault(candidate.source_url, []).append(candidate)

    components: list[CanonicalDiscoveryResult] = []
    for source_url in sorted(by_source):
        builder = CanonicalDiscoveryBuilder(
            source_url=source_url,
            metadata=discovery_metadata,
            scope=scope_metadata,
            parent_url=None,
            depth=0,
            request_authorizer=None,
            discovered_by="native_dynamic_network",
        )
        elision_counts: Counter[str] = Counter()
        elided_candidate_count = 0
        audit_only_candidate_count = 0
        for candidate in sorted(by_source[source_url], key=lambda item: item.id):
            observation_key = (
                f"network:{candidate.resource_type}:{candidate.id}"
            )
            origin_kind = f"network_{candidate.resource_type}"
            if candidate.disposition == NetworkDiscoveryDisposition.SAFE:
                canonical_url = candidate.canonical_url
                if canonical_url is None:
                    raise ValueError("safe network candidate has no canonical URL")
                builder.add_url_surface(
                    canonical_url,
                    observation_key=observation_key,
                    query_origin_kind=origin_kind,
                )
                continue
            elided_candidate_count += 1
            for reason in candidate.elision_reasons:
                elision_counts[reason.value] += 1
            if not candidate.query_parameter_names:
                audit_only_candidate_count += 1
                continue
            builder.add_structural_query_surface(
                candidate.base_url,
                query_parameter_names=candidate.query_parameter_names,
                observation_key=observation_key,
                not_ready_reasons=(NonProbeReadyReason.REQUEST_CONTEXT_MISSING,),
                query_origin_kind=origin_kind,
            )
        if elision_counts:
            builder.add_warning(
                "NETWORK_GET_VALUES_ELIDED",
                "Allowed browser GET values were elided before canonical construction.",
                {
                    "elided_candidate_count": elided_candidate_count,
                    "structural_candidate_count": (
                        elided_candidate_count - audit_only_candidate_count
                    ),
                    "audit_only_candidate_count": audit_only_candidate_count,
                    "elision_reason_counts": tuple(sorted(elision_counts.items())),
                    "producer_kind": discovery_metadata.collector_kind.value,
                },
                skipped=False,
            )
        components.append(
            builder.build(
                link_count=0,
                form_count=0,
                safety_invariants=(
                    DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
                ),
                pages_processed=0,
                html_pages=0,
            )
        )
    return tuple(components)
