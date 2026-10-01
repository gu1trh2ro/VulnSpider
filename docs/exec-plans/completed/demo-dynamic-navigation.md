# Authorized demo targets and bounded dynamic navigation

## Goal
Run DemoShop, Juice Shop, DVWA and explicitly authorized external origins through
the same short CLI, including browser search navigation.

## Non-Goals
No model execution, external live scan, authentication automation, destructive
payloads or changes to ranking and verdict rules.

## Context Read
- AGENTS.md, PLANS.md, CODE_REVIEW.md and docs/ARCHITECTURE.md
- CLI, loopback validation, dynamic browser/crawler and navigation safety
- Existing dynamic and simple CLI tests

## Current State
Search Enter causes an ungranted main-frame navigation. Fifty intercepted
requests are insufficient for the current DemoShop. Loopback validation also
rejects explicit remote lab origins.

## Proposed Changes
1. Add --allow-external for the exact origin of --url, scoped to one scan.
2. Transfer explicit authority into the supervised browser worker.
3. Permit bounded same-origin search navigation during safe actions, retaining
   path, method, authentication and redirect checks.
4. Add simple CLI request-budget control and retain partial marked reports on
   expected page/depth limits without treating transport failures as success.
5. Document commands, add regression tests and obtain two Gate reviews.

## Interfaces / Data Changes
Additive CLI flag and scoped HTTP authority; default legacy loopback behavior
stays unchanged. Worker payload adds the explicitly authorized origin.

## Safety / Scope Impact
The user explicitly authorized Juice Shop, DVWA and permitted external sites.
External scope uses exact scheme/host/effective port, never discovered hosts.
GET navigation remains bounded; no new POST permission or model verdict powers.

## Test Plan
- Scope rejection, exact-origin opt-in and scope reset tests
- Dynamic action navigation and negative route-guard cases
- CLI adapter and bounded partial report regressions
- Real Chromium on local DemoShop, no LLM
- Full unit/integration suite, format/lint/types and diff checks

## Acceptance Criteria
- [x] Explicit remote origin passes controlled transports without opening other origins.
- [x] Local search action no longer fails with NAVIGATION_FAILED.
- [x] Bounded demo scan produces marked analysis/dashboard output.
- [x] Required checks and two independent Gate reviews pass.

## Progress Log
- 2026-10-01: Confirmed both failures with controlled local traces; created
  fix/demo-dynamic-navigation in the prepared demo checkout.
- 2026-10-01: Implemented explicit origin scope, worker transfer, temporary
  search navigation and simple request-budget control. Chromium DemoShop run
  produced analysis/dashboard: 8 main-frame navigations, 3 actions, complete
  cleanup, PAGE_BUDGET_EXHAUSTED partial status.
- 2026-10-01: Legacy targeted 66 tests passed; full suite 1,070 tests passed
  in 293.481 seconds. Final affected tests: 20 passed, including depth 0/2
  Chromium subcases and partial report opening. Format, lint, type-hint and
  diff checks passed. No LLM or external live scan was run.
- 2026-10-01: Two independent Gate reviews returned PASS WITH MINOR/APPROVE.
  Updated architecture/default-scope documentation, documented hash-route DOM
  limitations and action-vs-DOM depth semantics, added depth-boundary regression.

## Decision Log
- Use explicit per-scan opt-in instead of disabling URL validation globally.
- Keep degraded discovery visible and retain exit code 4 for bounded partial
  runs, while allowing safe page/depth truncation to proceed to analysis.
- Route-action navigation is governed by separate action/request/navigation
  limits; max_depth bounds queued DOM collection. Hash-only SPA transitions do
  not guarantee a second DOM snapshot, while passive GET API capture continues.

## Open Questions
- Authenticated DVWA requires a user-supplied session cookie; exact target
  addresses and sessions have not been supplied. No external target is run.
