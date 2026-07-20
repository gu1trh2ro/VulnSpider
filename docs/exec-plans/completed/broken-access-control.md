# Broken Access Control (BAC) Detection Modules

## Goal

Add a working BAC candidate-ranking path (subject_context x resource_reference,
per `docs/DOMAIN_MODEL.md` #12 `AccessCandidate`) alongside the existing
SQLi/Reflected XSS injection-candidate path, so `vulnspider analyze` can select
a Top-N across all three categories: SQL Injection, Reflected XSS, and Broken
Access Control.

This is an explicit, user-requested scope expansion of ADR-007 (`BAC deferred
and separately modeled`), following the same procedure ADR-011 (HTML
dashboard) used: implement + update `docs/DECISION_LOG.md` with a new ADR +
update the out-of-scope lists in `AGENTS.md`, `docs/ARCHITECTURE.md`,
`docs/PROTOTYPE_V0_1.md`, `docs/DOMAIN_MODEL.md`, `docs/FEATURE_SCHEMA.md`.

## Non-Goals

- No login/session orchestration, credential store, or multi-account
  management. There is no auth infrastructure in this repo today and building
  one is out of scope for this change.
- No role-based (vertical) privilege matrix testing across arbitrary roles.
- No mutation of state: only `GET` requests are eligible for access probing.
- No changes to the existing SQLi/XSS domain types, scorer weights, or
  `selection/top_k.py` behavior — this is additive only. Existing tests must
  keep passing unmodified.
- No fabricated "safe" verdicts: absence of a BAC signal is reported as
  unrankable/not-observed, never as a confirmation that access control is
  correct (mirrors AGENTS.md rule 9).

## Context Read

- `AGENTS.md` rules 1-10, especially rule 8.
- `docs/ARCHITECTURE.md` §2.2, §7.
- `docs/PROTOTYPE_V0_1.md` §3 (Out of Scope), §9-13.
- `docs/DOMAIN_MODEL.md` §12 (`AccessCandidate` reserved shape).
- `docs/FEATURE_SCHEMA.md` (feature conventions: observed/missing, versions).
- `docs/DECISION_LOG.md` ADR-007, ADR-010, ADR-011.
- Code: `src/vulnspider/domain/models.py`, `observation/{planner,executor}.py`,
  `features/extraction.py`, `scoring/engine.py`, `selection/top_k.py`,
  `reporting/{json_report,html_report}.py`, `pipeline.py`, `cli.py`.

## Current State

`analyze_legacy_records()` runs one pipeline: adapter -> one-InputPoint-at-a-time
probe planning -> execution -> feature extraction -> `SQLiScorer`/`XSSScorer`
-> `select_top_k()` -> JSON/HTML report. There is no concept of an auth
context, a session, or a "same resource, different subject" comparison
anywhere in the code. `InputPoint.auth_context_id` and
`InputPointRequestContext.role` exist but are always unset/`"baseline"`.

## Proposed Changes

1. `domain/access.py` (new): `AccessSubjectContext` (`ORIGINAL`, `ANONYMOUS`),
   `AccessCheckKind` (`CREDENTIAL_STRIP`, `IDENTIFIER_SUBSTITUTION`),
   `AccessProbePlan`, `AccessCandidate`, `AccessScoreEvidence`,
   `AccessScoringResult` (validated factory, mirrors `ScoringResult`). Reuses
   `RequestInstance`/`ResponseSnapshot`/`stable_fingerprint` from
   `domain.models` — does not touch `VulnerabilityType`/`VulnerabilityCandidate`
   (rule 8: BAC is not forced into the injection-candidate model).
2. `observation/executor.py`: add optional `probe_plan_id`/`request_role`
   passthrough kwargs to the existing public `execute_request()` (default
   `None`, so every existing call site is unaffected) so the access executor
   can reuse the same tested snapshot-construction logic instead of
   duplicating it.
3. `access/` (new package): `planner.py`, `executor.py`, `features.py`,
   `scoring.py`, `selection.py` — a small parallel pipeline mirroring the
   shape of `observation/`, `features/`, `scoring/`, `selection/` but for the
   two BAC check kinds:
   - `CREDENTIAL_STRIP`: for a `COMPLETE` `GET` `RequestTemplate` that carries
     cookies or an `Authorization` header, re-send the exact same request with
     those credentials removed. Signal: does the anonymous copy still succeed
     (2xx) with a similarly-sized body?
   - `IDENTIFIER_SUBSTITUTION`: for a `GET` `InputPoint` in `QUERY`/`FORM`
     whose baseline value is purely numeric, re-send the same request with the
     value incremented by one. Signal: does the substituted-id request still
     succeed (2xx) with a similarly-sized (i.e. real, not a 404 stub) body,
     instead of being rejected?
   Both are light, non-destructive, GET-only, deterministic, and explainable
   (same `observed`/`value`/`source`/`extractor_version` feature shape as
   05B).
4. `selection/combined.py` (new): merge `select_top_k()` (existing, untouched)
   and the new `select_top_k_access()` into one true cross-category Top-K.
   Correctness argument: requesting each category's own top-K and merging by
   `selection_priority` before trimming to K is exact, because any item in the
   global top-K must already rank inside its own category's top-K (removing
   items from other categories cannot lower an item's rank within its
   category).
5. `pipeline.py`: `analyze_legacy_records()` additively grows
   `AnalysisResult` with `access_scoring_results`, `access_probe_observations`,
   and `combined_selection`; existing fields (`selection`, `scoring_results`,
   `probe_observations`) are unchanged.
6. `reporting/combined_report.py` (new): JSON + HTML rendering for the merged
   Top-N. `cli.py --output` switches to this combined report (existing
   `build_json_report`/`render_html_report` stay as-is and keep their own
   tests green — nothing about their public behavior changes). The combined
   report is additive at the CLI boundary: same summary/candidate keys tests
   already assert on, plus new `category`/`check_kind` fields.
7. `demo_target_server.py`: add `/account` (cookie-gated, leaks to anonymous
   GET => CREDENTIAL_STRIP demo) and extend `/product?id=` semantics so a
   numeric id one higher than baseline returns a *different* product body
   with 200 instead of 404 (=> IDENTIFIER_SUBSTITUTION demo). Not part of the
   test suite — manual end-to-end fixture only, matching the existing
   `demo_target_server.py` docstring.

## Interfaces / Data Changes

New public API surface: `vulnspider.domain.access.*`, `vulnspider.access.*`,
`vulnspider.selection.combined.*`, `vulnspider.reporting.combined_report.*`.
`AnalysisResult` gains three new fields (additive dataclass fields with
defaults are not possible on a frozen slots dataclass without defaults for
all-or-none — will add them as required fields produced by
`analyze_legacy_records()`, so any other direct constructor call site needs
updating; grep for other constructors before landing). `execute_request()`
gains two new optional keyword arguments.

## Safety / Scope Impact

- Access probes are GET-only and non-destructive (read-only re-requests of
  already-discovered URLs; the identifier substitution only increments a
  numeric value by one, never writes).
- Still bound by the existing `_require_loopback_request` scope guard in
  `pipeline.py` — no new host reach.
- No new destructive, state-changing, or authentication-bypassing *exploit*
  behavior is added — this only sends a normal HTTP GET and observes the
  response, exactly like the existing Light Probes.

## Test Plan

- unit: `domain/access.py` identity/validation; `access/planner.py`
  eligibility rules (GET-only, COMPLETE-only, numeric-only, cookie/auth-header
  presence); `access/executor.py` with a fake transport; `access/features.py`
  observed-vs-missing and value-formula cases; `access/scoring.py` evidence
  arithmetic and missing-term handling; `access/selection.py` cross-run
  dedup/ordering; `selection/combined.py` merge correctness (including the
  "global top-K subset of per-category top-K" property) and empty-access-set
  backward compatibility.
- integration: extend the CLI smoke pattern
  (`tests/integration/test_v01_smoke.py` style) with a fake transport serving
  both a credential-leak and an IDOR-like fixture, asserting a BAC candidate
  appears in the combined JSON report.
- negative: reference request not 2xx -> unrankable, not "safe"; POST
  endpoints never probed; non-numeric identifiers never substituted; existing
  SQLi/XSS-only fixture (no cookies, no numeric id) produces zero access
  candidates and an unchanged injection-only result set.

## Acceptance Criteria

- [x] `python -m unittest discover -s tests` passes, including new tests
      (243 tests, up from 192).
- [x] `tools/check_format.py`, `tools/check_lint.py`, `tools/check_types.py`
      pass.
- [x] A combined-report integration test shows a `BROKEN_ACCESS_CONTROL`
      (or equivalent) candidate ranked in the same Top-N list as SQLi/XSS
      candidates (`tests/integration/test_bac_smoke.py`).
- [x] Existing SQLi/XSS unit + integration tests pass unmodified.
- [x] `docs/DECISION_LOG.md` has a new ADR (ADR-012) superseding ADR-007;
      `AGENTS.md`/`ARCHITECTURE.md`/`PROTOTYPE_V0_1.md`/`DOMAIN_MODEL.md`/
      `FEATURE_SCHEMA.md` no longer list BAC as out-of-scope and instead
      describe what was actually implemented.
- [x] This file is moved to `docs/exec-plans/completed/`.

## Progress Log

- 2026-07-20: Plan created; scope confirmed with user (implement both
  CREDENTIAL_STRIP and IDENTIFIER_SUBSTITUTION; update docs/ADR).
- 2026-07-20: Implemented `domain/access.py`, `vulnspider.access` package
  (planner/executor/features/scoring/selection), `selection/combined.py`,
  `reporting/combined_report.py`; wired into `pipeline.py` and `cli.py`.
  Added an optional `cookies` field to `LegacyCrawlRecord` so
  `CREDENTIAL_STRIP` is reachable via the real CLI `--input` JSON path (it
  previously had no way to carry session cookies at all). Verified live
  end-to-end against `demo_target_server.py` (extended with `/account`) via
  a real socket, not just fake-transport tests. Added unit tests for every
  new module plus an integration smoke test, and updated
  `AGENTS.md`/`ARCHITECTURE.md`/`PROTOTYPE_V0_1.md`/`DOMAIN_MODEL.md`/
  `FEATURE_SCHEMA.md`/`DECISION_LOG.md` (ADR-012). All acceptance criteria
  met; moving to `completed/`.

## Decision Log

- Decision: BAC is modeled as a new, separate `AccessCandidate` relational
  type (subject_context x resource_reference), not as a new
  `VulnerabilityType` value on the existing injection `VulnerabilityCandidate`.
  Reason: ADR-007's structural argument still holds — access-control
  correctness is a relationship between a subject and a resource, not a
  property of one InputPoint's injection response. Keeping the models
  separate also protects the well-tested SQLi/XSS scorer semantics ("higher
  observed value = more suspicious") from BAC's inverted semantics ("request
  was NOT rejected = more suspicious").
- Decision: only two check kinds are implemented (`CREDENTIAL_STRIP`,
  `IDENTIFIER_SUBSTITUTION`), both GET-only and both derivable from data the
  crawler/adapter already produces. Reason: there is no auth/session
  infrastructure in this repo; anything requiring real multi-account login is
  out of scope for this change and would need its own exec-plan.
- Decision: combine Top-K by running each category's own `select_top_k`-style
  selector at `k` and merging, instead of rewriting `selection/top_k.py` to be
  polymorphic. Reason: zero risk to the existing, heavily-tested
  `SelectionOutcome`/`select_top_k` invariants; the merge is provably exact
  (see Proposed Changes #4).

## Open Questions

- None blocking; UUID/opaque-token identifier substitution and vertical
  (role-based) BAC checks are explicitly deferred to a future exec-plan.
