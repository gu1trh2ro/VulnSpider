from __future__ import annotations

from dataclasses import dataclass, field
import unittest

import vulnspider.discovery.dynamic_browser as browser_module
from vulnspider.discovery import (
    CollectorKind,
    DynamicBrowserError,
    DynamicBrowserErrorCode,
    DynamicBrowserPolicy,
    DynamicBrowserRunResult,
    DynamicCrawlCompletion,
    DynamicCrawler,
    DynamicCrawlPolicy,
    DynamicCrawlTerminationReason,
    DynamicNetworkDecision,
    DynamicNetworkDecisionKind,
    DynamicNetworkReason,
    DynamicRequestAuthority,
    RenderedDomPolicy,
    RenderedDomSnapshot,
)


def rendered_snapshot(
    url: str,
    body: str = "",
    *,
    sensitive_occurrences: tuple[int, ...] = (),
) -> RenderedDomSnapshot:
    html = f"<html><body>{body}</body></html>"
    return RenderedDomSnapshot(
        page_url=url,
        sanitized_html=html,
        sensitive_form_occurrences=sensitive_occurrences,
        node_count=max(1, body.count("<")),
        anchor_count=body.count("<a "),
        form_count=body.count("<form"),
        control_count=(
            body.count("<input")
            + body.count("<select")
            + body.count("<textarea")
        ),
        serialized_bytes=len(html.encode("utf-8")),
        capture_policy_fingerprint=RenderedDomPolicy().fingerprint,
    )


def _allow(url: str) -> DynamicNetworkDecision:
    return DynamicNetworkDecision(
        DynamicNetworkDecisionKind.ALLOW,
        DynamicNetworkReason.AUTHORIZED_NAVIGATION,
        url,
        "document",
    )


@dataclass
class FakeDynamicSession:
    snapshots: dict[str, RenderedDomSnapshot]
    recorder: browser_module._AuditRecorder
    statuses: dict[str, int] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    errors: dict[str, DynamicBrowserErrorCode] = field(default_factory=dict)
    current_url: str | None = None
    current_status: int | None = None
    navigation_calls: list[str] = field(default_factory=list)
    rendered_navigation_calls: list[str] = field(default_factory=list)

    def navigate(
        self,
        url: str | None = None,
        *,
        timeout_seconds: float | None = None,
        rendered_navigation: bool = False,
    ) -> str:
        if url is None:
            raise AssertionError("crawler must pass an explicit URL")
        if timeout_seconds is None or timeout_seconds <= 0:
            raise AssertionError("crawler must pass a bounded timeout")
        self.navigation_calls.append(url)
        if rendered_navigation:
            self.rendered_navigation_calls.append(url)
        self.recorder.record_http(
            _allow(url),
            url=url,
            is_child_frame_document=False,
            is_redirect=False,
        )
        self.recorder.record_main_frame_navigation(_allow(url))
        code = self.errors.get(url)
        if code is not None:
            raise DynamicBrowserError(code, "fake bounded failure")
        final_url = self.redirects.get(url, url)
        if final_url != url:
            self.recorder.record_http(
                _allow(final_url),
                url=final_url,
                is_child_frame_document=False,
                is_redirect=True,
            )
            self.recorder.record_http(
                _allow(final_url),
                url=final_url,
                is_child_frame_document=False,
                is_redirect=False,
            )
            self.recorder.record_main_frame_navigation(_allow(final_url))
            self.recorder.record_redirect_followed()
        self.current_url = final_url
        self.current_status = self.statuses.get(final_url, 200)
        return final_url

    def navigation_status_code(self) -> int | None:
        return self.current_status

    def capture_rendered_dom(
        self,
        policy: RenderedDomPolicy | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> RenderedDomSnapshot:
        if type(policy) is not RenderedDomPolicy:
            raise AssertionError("crawler must pass its rendered DOM policy")
        if self.current_url is None:
            raise AssertionError("navigation must precede capture")
        if timeout_seconds is None or timeout_seconds <= 0:
            raise AssertionError("crawler must bound rendered DOM capture")
        return self.snapshots[self.current_url]


@dataclass
class FakeDynamicBrowser:
    snapshots: dict[str, RenderedDomSnapshot]
    statuses: dict[str, int] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    errors: dict[str, DynamicBrowserErrorCode] = field(default_factory=dict)
    session: FakeDynamicSession | None = None

    def run(self, authority, operation, *, policy=None):
        if type(policy) is not DynamicBrowserPolicy:
            raise AssertionError("crawler must pass a browser policy")
        recorder = browser_module._AuditRecorder(
            event_limit=policy.request_decision_budget
        )
        session = FakeDynamicSession(
            snapshots=self.snapshots,
            recorder=recorder,
            statuses=self.statuses,
            redirects=self.redirects,
            errors=self.errors,
        )
        self.session = session
        try:
            value = operation(session)
        except DynamicBrowserError as exc:
            audit = recorder.snapshot(())
            raise DynamicBrowserError(exc.code, str(exc), audit=audit) from None
        return DynamicBrowserRunResult(value=value, audit=recorder.snapshot(()))


class DynamicCrawlerTests(unittest.TestCase):
    def test_simple_authority_navigates_only_rendered_same_origin_anchors(
        self,
    ) -> None:
        root = "http://127.0.0.1:8080/start"
        rendered = "http://127.0.0.1:8080/rendered?q=1"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    (
                        '<a href="/rendered?q=1"></a>'
                        '<a href="http://127.0.0.1:8081/out"></a>'
                    ),
                ),
                rendered: rendered_snapshot(rendered),
            }
        )
        authority = DynamicRequestAuthority(
            root,
            allow_rendered_navigation=True,
            allow_passive_same_origin_resources=True,
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        self.assertEqual(result.visited_urls, (root, rendered))
        self.assertEqual(browser.session.navigation_calls, [root, rendered])
        self.assertEqual(browser.session.rendered_navigation_calls, [rendered])
        self.assertIn(
            "DYNAMIC_OFF_AUTHORITY_LINK",
            {warning.code for warning in result.discovery.warnings},
        )

    def test_deterministic_bfs_uses_exact_authority_and_page_provenance(self) -> None:
        root = "http://127.0.0.1/start"
        page_a = "http://127.0.0.1/page-a"
        page_b = "http://127.0.0.1/page-b"
        page_c = "http://127.0.0.1/page-c?x=1"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    (
                        '<a href="/page-b"></a>'
                        '<a href="/page-a#one"></a>'
                        '<a href="/page-a#two"></a>'
                        '<a href="http://127.0.0.1:9/out"></a>'
                        '<a href="/not-authorized"></a>'
                    ),
                ),
                page_a: rendered_snapshot(
                    page_a,
                    '<a href="/page-c?x=1"></a><a href="/start"></a>',
                ),
                page_b: rendered_snapshot(page_b),
                page_c: rendered_snapshot(
                    page_c,
                    '<form action="/safe" method="get"><input name="q" value="1"></form>',
                ),
            }
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(page_b, page_a, page_c),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(max_depth=2),
            authority,
        )

        self.assertEqual(result.visited_urls, (root, page_a, page_b, page_c))
        self.assertEqual([item.depth for item in result.pages], [0, 1, 1, 2])
        self.assertEqual(
            [item.parent_url for item in result.pages],
            [None, root, root, page_a],
        )
        self.assertEqual(result.completion, DynamicCrawlCompletion.COMPLETE)
        self.assertEqual(
            result.termination_reason,
            DynamicCrawlTerminationReason.FRONTIER_EXHAUSTED,
        )
        self.assertEqual(
            result.discovery.discovery_metadata.collector_kind,
            CollectorKind.NATIVE_DYNAMIC,
        )
        self.assertEqual(result.navigation_attempts, 4)
        self.assertEqual(result.route_actions_attempted, 0)
        self.assertTrue(result.browser_audit.cleanup_complete)
        self.assertTrue(
            all(
                provenance.depth
                == next(
                    page.depth
                    for page in result.pages
                    if page.page_url == provenance.source_url
                )
                for provenance in result.discovery.crawl_provenance
            )
        )
        self.assertEqual(browser.session.navigation_calls, list(result.visited_urls))

    def test_same_authority_redirect_uses_final_page_once(self) -> None:
        root = "http://127.0.0.1/start"
        redirect = "http://127.0.0.1/a-redirect"
        final = "http://127.0.0.1/z-final"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/a-redirect"></a><a href="/z-final"></a>',
                ),
                final: rendered_snapshot(final),
            },
            redirects={redirect: final},
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(redirect, final),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        self.assertEqual([item.page_url for item in result.pages], [root, final])
        self.assertEqual(len({item.page_url for item in result.pages}), 2)
        self.assertEqual(result.discovery.crawl_statistics.redirects_followed, 1)
        self.assertEqual(result.navigation_attempts, 3)
        result.discovery.validate()

    def test_http_error_isolated_while_later_page_is_retained(self) -> None:
        root = "http://127.0.0.1/start"
        error = "http://127.0.0.1/a-error"
        good = "http://127.0.0.1/b-good"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(
                    root,
                    '<a href="/a-error"></a><a href="/b-good"></a>',
                ),
                error: rendered_snapshot(error),
                good: rendered_snapshot(
                    good,
                    '<form action="/safe" method="get"><input name="live" value="yes"></form>',
                ),
            },
            statuses={error: 500},
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(error, good),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        self.assertEqual([item.page_url for item in result.pages], [root, good])
        self.assertEqual(result.completion, DynamicCrawlCompletion.DEGRADED)
        self.assertEqual(
            result.termination_reason,
            DynamicCrawlTerminationReason.COMPLETED_WITH_FAILURES,
        )
        self.assertIn("DYNAMIC_HTTP_ERROR", {item.code for item in result.warnings})
        self.assertTrue(any(point.name == "live" for point in result.discovery.input_points))

    def test_sensitive_occurrence_stays_page_local_and_secret_free(self) -> None:
        root = "http://127.0.0.1/start"
        sensitive = "http://127.0.0.1/sensitive"
        browser = FakeDynamicBrowser(
            {
                root: rendered_snapshot(root, '<a href="/sensitive"></a>'),
                sensitive: rendered_snapshot(
                    sensitive,
                    '<form action="/safe" method="get"><input name="safe" value="1"></form>',
                    sensitive_occurrences=(1,),
                ),
            }
        )
        authority = DynamicRequestAuthority(
            root_url=root,
            navigation_urls=(sensitive,),
        )

        result = DynamicCrawler(browser=browser, clock=lambda: 0.0).crawl(
            root,
            DynamicCrawlPolicy(),
            authority,
        )

        warnings = [
            item for item in result.warnings if item.code == "SENSITIVE_FORM_ELIDED"
        ]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].details["form_occurrence_index"], 1)
        self.assertNotIn("password", repr(result.to_dict()).lower())
        self.assertTrue(any(point.name == "safe" for point in result.discovery.input_points))


if __name__ == "__main__":
    unittest.main()
