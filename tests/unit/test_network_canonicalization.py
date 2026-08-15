from __future__ import annotations

import pickle
import unittest

from vulnspider.discovery import (
    CollectorKind,
    DiscoveryMergePolicy,
    DiscoveryMetadata,
    NetworkDiscoveryCandidate,
    NetworkDiscoveryCollection,
    NetworkDiscoveryDisposition,
    NetworkDiscoveryElisionReason,
    ProbeReadyStatus,
    ScopeMetadata,
    canonicalize_network_discovery,
    discovery_snapshot_id_for,
    extract_static_html_with_sensitive_form_elision,
    merge_discovery_results,
    scope_id_for_root,
)
from vulnspider.discovery import dynamic_browser as browser_module
from vulnspider.domain import validate_input_point_request_context


ROOT = "http://127.0.0.1:8080/"
ORIGIN = ("http", "127.0.0.1", 8080)


def _metadata(kind: CollectorKind) -> DiscoveryMetadata:
    return DiscoveryMetadata(
        collector_kind=kind,
        collector_version=f"test-{kind.value.lower()}/1",
        configuration_fingerprint=f"config-{kind.value.lower()}",
    )


def _scope() -> ScopeMetadata:
    return ScopeMetadata(
        target_scope_id=scope_id_for_root(
            ROOT,
            policy_version="same-origin-v1",
        ),
        root_url=ROOT,
        scope_policy_version="same-origin-v1",
    )


def _candidate(
    url: str,
    *,
    resource_type: str = "fetch",
    credential_header_present: bool = False,
):
    candidate, reason = browser_module._safe_network_discovery_candidate(
        method="GET",
        url=url,
        resource_type=resource_type,
        source_url=ROOT,
        root_origin=ORIGIN,
        credential_header_present=credential_header_present,
    )
    if reason is not None:
        raise AssertionError(reason)
    if candidate is None:
        raise AssertionError("expected a network discovery candidate")
    return candidate


def _canonical(*candidates):
    components = canonicalize_network_discovery(
        NetworkDiscoveryCollection(candidates=tuple(candidates)),
        discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
        scope_metadata=_scope(),
    )
    if len(components) != 1:
        raise AssertionError("expected one source-page component")
    return components[0]


class NetworkCanonicalizationTests(unittest.TestCase):
    def test_route_guard_collects_only_authority_allowed_primary_get(self) -> None:
        class Page:
            url = ROOT

        class Frame:
            page = Page()
            parent_frame = None

        class Request:
            frame = Frame()

            def __init__(self, method, url, resource_type, headers=None):
                self.method = method
                self.url = url
                self.resource_type = resource_type
                self._headers = headers or {}

            def all_headers(self):
                return dict(self._headers)

        class Response:
            status = 200
            headers = {}

            def dispose(self):
                return None

        class Route:
            def __init__(self):
                self.fetch_count = 0
                self.fulfill_count = 0
                self.abort_count = 0

            def fetch(self, **_kwargs):
                self.fetch_count += 1
                return Response()

            def fulfill(self, **_kwargs):
                self.fulfill_count += 1

            def abort(self, **_kwargs):
                self.abort_count += 1

        authority = browser_module.DynamicRequestAuthority(
            ROOT,
            allow_passive_same_origin_fetch_xhr=True,
        )
        audit = browser_module._AuditRecorder(event_limit=16)
        network = browser_module._NetworkDiscoveryRecorder(candidate_limit=16)
        guard = browser_module._RouteGuard(
            authority,
            browser_module.DynamicBrowserPolicy(request_decision_budget=16),
            audit,
            lambda: None,
            network_discovery=network,
        )
        guard.set_primary_page(Frame.page)

        allowed = Route()
        guard.handle_http(
            allowed,
            Request(
                "GET",
                "http://127.0.0.1:8080/api/search?q=phone",
                "fetch",
            ),
        )
        guard.handle_http(
            Route(),
            Request("HEAD", "http://127.0.0.1:8080/api/head?q=1", "fetch"),
        )
        guard.handle_http(
            Route(),
            Request("POST", "http://127.0.0.1:8080/api/post?q=1", "fetch"),
        )
        guard.handle_http(
            Route(),
            Request("GET", "http://127.0.0.1:8081/api/off?q=1", "xhr"),
        )
        header_secret = "ROUTE_HEADER_SECRET_SENTINEL"
        guard.handle_http(
            Route(),
            Request(
                "GET",
                "http://127.0.0.1:8080/api/private?page=1",
                "xhr",
                {"Authorization": f"Bearer {header_secret}"},
            ),
        )

        collection = network.snapshot()
        self.assertEqual(allowed.fetch_count, 1)
        self.assertEqual(len(collection.candidates), 2)
        self.assertEqual(
            {item.base_url for item in collection.candidates},
            {
                "http://127.0.0.1:8080/api/search",
                "http://127.0.0.1:8080/api/private",
            },
        )
        private = next(
            item for item in collection.candidates if item.base_url.endswith("/private")
        )
        self.assertEqual(
            private.disposition,
            NetworkDiscoveryDisposition.STRUCTURAL_ELIDED,
        )
        self.assertNotIn(header_secret, repr(collection))
        self.assertNotIn(header_secret.encode(), pickle.dumps(collection, protocol=5))

        blocked_network = browser_module._NetworkDiscoveryRecorder(candidate_limit=4)
        blocked_guard = browser_module._RouteGuard(
            browser_module.DynamicRequestAuthority(ROOT),
            browser_module.DynamicBrowserPolicy(request_decision_budget=4),
            browser_module._AuditRecorder(event_limit=4),
            lambda: None,
            network_discovery=blocked_network,
        )
        blocked_guard.set_primary_page(Frame.page)
        blocked_route = Route()
        blocked_guard.handle_http(
            blocked_route,
            Request(
                "GET",
                "http://127.0.0.1:8080/api/blocked?q=1",
                "fetch",
            ),
        )
        self.assertEqual(blocked_route.abort_count, 1)
        self.assertEqual(blocked_network.snapshot().candidates, ())

    def test_safe_fetch_builds_endpoint_points_template_and_contexts(self) -> None:
        result = _canonical(
            _candidate(
                "http://127.0.0.1:8080/api/search"
                "?keyword=phone&page=1&tag=a&tag=b"
            )
        )

        endpoint = next(item for item in result.endpoints if item.path == "/api/search")
        self.assertEqual(endpoint.discovered_by, "native_dynamic_network")
        points = sorted(
            (item for item in result.input_points if item.endpoint_id == endpoint.id),
            key=lambda item: (
                item.name,
                -1 if item.occurrence_index is None else item.occurrence_index,
            ),
        )
        self.assertEqual(
            [(item.name, item.occurrence_index) for item in points],
            [("keyword", None), ("page", None), ("tag", 0), ("tag", 1)],
        )
        self.assertTrue(
            all("network_fetch" in item.metadata["origin_kinds"] for item in points)
        )
        template = result.request_templates[0]
        self.assertEqual(
            template.query,
            (("keyword", "phone"), ("page", "1"), ("tag", "a"), ("tag", "b")),
        )
        self.assertEqual(template.headers, {})
        self.assertEqual(template.cookies, {})
        contexts = {item.input_point_id: item for item in result.input_point_request_contexts}
        for point in points:
            context = contexts[point.id or ""]
            self.assertEqual(context.request_template_id, template.id)
            validate_input_point_request_context(point, template)
        self.assertTrue(
            all(item.status == ProbeReadyStatus.READY for item in result.probe_readiness)
        )

    def test_safe_xhr_uses_the_same_canonical_contract(self) -> None:
        result = _canonical(
            _candidate(
                "http://127.0.0.1:8080/api/filter?category=book&tag=a&tag=b",
                resource_type="xhr",
            )
        )
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(len(result.input_points), 3)
        self.assertTrue(
            all(
                "network_xhr" in item.metadata["origin_kinds"]
                for item in result.input_points
            )
        )
        self.assertEqual(len(result.ready_contexts()), 3)

    def test_candidate_event_order_and_duplicates_are_deterministic(self) -> None:
        first = _candidate("http://127.0.0.1:8080/api/a?x=1")
        second = _candidate(
            "http://127.0.0.1:8080/api/b?y=2",
            resource_type="xhr",
        )
        forward = canonicalize_network_discovery(
            NetworkDiscoveryCollection(candidates=(first, second)),
            discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
            scope_metadata=_scope(),
        )
        reverse = canonicalize_network_discovery(
            NetworkDiscoveryCollection(candidates=(second, first)),
            discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
            scope_metadata=_scope(),
        )
        self.assertEqual(forward, reverse)
        self.assertEqual(
            discovery_snapshot_id_for(forward[0].to_dict()),
            discovery_snapshot_id_for(reverse[0].to_dict()),
        )
        recorder = browser_module._NetworkDiscoveryRecorder(candidate_limit=4)
        for _ in range(2):
            recorder.record_allowed_get(
                method="GET",
                url="http://127.0.0.1:8080/api/a?x=1",
                resource_type="fetch",
                source_url=ROOT,
                root_origin=ORIGIN,
                credential_header_present=False,
            )
        self.assertEqual(len(recorder.snapshot().candidates), 1)

    def test_query_order_preserves_pairs_but_not_endpoint_or_input_identity(self) -> None:
        first = _canonical(
            _candidate("http://127.0.0.1:8080/api/search?keyword=phone&page=1")
        )
        second = _canonical(
            _candidate("http://127.0.0.1:8080/api/search?page=1&keyword=phone")
        )
        self.assertEqual(first.endpoints[0].id, second.endpoints[0].id)
        self.assertEqual(
            {item.id for item in first.input_points},
            {item.id for item in second.input_points},
        )
        self.assertNotEqual(first.request_templates[0].id, second.request_templates[0].id)
        self.assertEqual(
            second.request_templates[0].query,
            (("page", "1"), ("keyword", "phone")),
        )

    def test_sensitive_query_and_credential_header_are_structural_only(self) -> None:
        query_secret = "QUERY_SECRET_SENTINEL"
        header_secret = "HEADER_SECRET_SENTINEL"
        sensitive = _candidate(
            f"http://127.0.0.1:8080/api/private?token={query_secret}&page=1",
            credential_header_present=True,
        )
        self.assertEqual(
            sensitive.disposition,
            NetworkDiscoveryDisposition.STRUCTURAL_ELIDED,
        )
        self.assertNotIn(query_secret, repr(sensitive))
        self.assertNotIn(header_secret, repr(sensitive))
        self.assertNotIn(query_secret.encode(), pickle.dumps(sensitive, protocol=5))
        self.assertNotIn(header_secret.encode(), pickle.dumps(sensitive, protocol=5))

        result = _canonical(sensitive)
        payload = repr(result.to_dict())
        self.assertNotIn(query_secret, payload)
        self.assertNotIn(header_secret, payload)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(
            [(item.name, item.baseline_value) for item in result.input_points],
            [("page", None), ("token", None)],
        )
        self.assertEqual(result.request_templates, ())
        self.assertEqual(result.input_point_request_contexts, ())
        self.assertTrue(
            all(item.status == ProbeReadyStatus.NOT_READY for item in result.probe_readiness)
        )
        warning = next(
            item for item in result.warnings if item.code == "NETWORK_GET_VALUES_ELIDED"
        )
        self.assertEqual(warning.details["elided_candidate_count"], 1)
        self.assertEqual(warning.details["structural_candidate_count"], 1)
        self.assertEqual(warning.details["audit_only_candidate_count"], 0)

    def test_credential_request_without_query_is_audit_only_with_count(self) -> None:
        result = _canonical(
            _candidate(
                "http://127.0.0.1:8080/api/private",
                credential_header_present=True,
            )
        )
        self.assertEqual(result.endpoints, ())
        self.assertEqual(result.input_points, ())
        self.assertEqual(result.request_templates, ())
        self.assertEqual(result.input_point_request_contexts, ())
        warning = next(
            item for item in result.warnings if item.code == "NETWORK_GET_VALUES_ELIDED"
        )
        self.assertEqual(warning.details["elided_candidate_count"], 1)
        self.assertEqual(warning.details["structural_candidate_count"], 0)
        self.assertEqual(warning.details["audit_only_candidate_count"], 1)

    def test_ineligible_and_invalid_requests_fail_closed(self) -> None:
        cases = (
            {
                "method": "HEAD",
                "url": "http://127.0.0.1:8080/api?q=1",
                "resource_type": "fetch",
            },
            {
                "method": "POST",
                "url": "http://127.0.0.1:8080/api?q=1",
                "resource_type": "xhr",
            },
            {
                "method": "GET",
                "url": "http://127.0.0.1:8081/api?q=1",
                "resource_type": "fetch",
            },
            {
                "method": "GET",
                "url": "http://user:pass@127.0.0.1:8080/api?q=1",
                "resource_type": "fetch",
            },
            {
                "method": "GET",
                "url": "http://127.0.0.1:8080/api?q=%ZZ",
                "resource_type": "fetch",
            },
            {
                "method": "GET",
                "url": "http://127.0.0.1:8080/" + "a" * 8200,
                "resource_type": "fetch",
            },
        )
        for case in cases:
            with self.subTest(case=case):
                candidate, _ = browser_module._safe_network_discovery_candidate(
                    source_url=ROOT,
                    root_origin=ORIGIN,
                    credential_header_present=False,
                    **case,
                )
                self.assertIsNone(candidate)

    def test_dom_and_network_share_identity_and_preserve_both_provenances(self) -> None:
        static = extract_static_html_with_sensitive_form_elision(
            '<a href="/api/search?keyword=phone">search</a>',
            ROOT,
            discovery_metadata=_metadata(CollectorKind.NATIVE_STATIC),
            scope_metadata=_scope(),
            parent_url=None,
            depth=0,
        ).discovery
        dynamic = _canonical(
            _candidate("http://127.0.0.1:8080/api/search?keyword=phone")
        )
        merged = merge_discovery_results(static, dynamic, DiscoveryMergePolicy())
        endpoint = next(item for item in merged.endpoints if item.path == "/api/search")
        points = [item for item in merged.input_points if item.endpoint_id == endpoint.id]
        self.assertEqual(len(points), 1)
        self.assertEqual(len(merged.request_templates), 1)
        self.assertEqual(len(merged.input_point_request_contexts), 1)
        subjects = {
            endpoint.id,
            points[0].id,
            merged.request_templates[0].id,
            merged.input_point_request_contexts[0].id,
        }
        for subject_id in subjects:
            evidence = {
                item.collector_kind
                for item in merged.crawl_provenance
                if item.subject_id == subject_id
            }
            self.assertEqual(
                evidence,
                {CollectorKind.NATIVE_STATIC, CollectorKind.NATIVE_DYNAMIC},
            )
        self.assertEqual(
            set(points[0].metadata["origin_kinds"]),
            {"query", "network_fetch"},
        )

    def test_collection_pickle_round_trip_preserves_canonical_content(self) -> None:
        collection = NetworkDiscoveryCollection(
            candidates=(
                _candidate("http://127.0.0.1:8080/api/search?q=phone"),
            )
        )
        self.assertEqual(pickle.loads(pickle.dumps(collection, protocol=5)), collection)

    def test_candidate_constructor_rejects_forged_unsafe_executable_state(self) -> None:
        common = {
            "resource_type": "fetch",
            "source_url": ROOT,
            "base_url": "http://127.0.0.1:8080/api/search",
            "disposition": NetworkDiscoveryDisposition.SAFE,
        }
        with self.assertRaises(ValueError):
            NetworkDiscoveryCandidate(
                **common,
                query_parameter_names=("token",),
                query_pairs=(("token", "FORGED_QUERY_SECRET"),),
            )
        with self.assertRaises(ValueError):
            NetworkDiscoveryCandidate(
                **common,
                query_parameter_names=("q",),
                query_pairs=(("q", "x" * 2049),),
            )
        with self.assertRaises(ValueError):
            NetworkDiscoveryCandidate(
                **{
                    **common,
                    "base_url": "http://127.0.0.1:8081/api/search",
                },
                query_parameter_names=("q",),
                query_pairs=(("q", "safe"),),
            )
        structural = NetworkDiscoveryCandidate(
            **{
                **common,
                "disposition": NetworkDiscoveryDisposition.STRUCTURAL_ELIDED,
            },
            query_parameter_names=("token",),
            query_pairs=(),
            elision_reasons=(NetworkDiscoveryElisionReason.SENSITIVE_QUERY,),
        )
        self.assertIsNone(structural.canonical_url)

        escaped = NetworkDiscoveryCandidate(
            resource_type="fetch",
            source_url="http://127.0.0.1:8081/",
            base_url="http://127.0.0.1:8081/api/search",
            query_parameter_names=("q",),
            query_pairs=(("q", "safe"),),
            disposition=NetworkDiscoveryDisposition.SAFE,
        )
        with self.assertRaises(ValueError):
            canonicalize_network_discovery(
                NetworkDiscoveryCollection(candidates=(escaped,)),
                discovery_metadata=_metadata(CollectorKind.NATIVE_DYNAMIC),
                scope_metadata=_scope(),
            )


if __name__ == "__main__":
    unittest.main()
