# Prototype v0.1 Specification

## 1. 목표

첫 번째 프로토타입은 다음 연구 가설을 빠르게 검증한다.

> 기존 WHSPIDER의 수집 결과를 InputPoint 단위로 정규화하고, 저위험 Light Probe에서 추출한 feature를 이용해 SQLi와 Reflected XSS 후보를 순위화할 수 있는가?

v0.1은 완성형 취약점 스캐너가 아니다.

---

## 2. In Scope

### 취약점 유형

- SQL Injection candidate ranking
- Reflected XSS candidate ranking
- Broken Access Control candidate ranking (ADR-012; §14 참고) — 두 가지
  점검으로 한정: 자격 증명 제거(`CREDENTIAL_STRIP`)와 숫자 식별자 치환
  (`IDENTIFIER_SUBSTITUTION`)

### 수집

- 기존 WHSPIDER static crawler 재사용 가능
- query parameter
- HTML form input
- form action/method

### 관찰

- Baseline request
- Reflection marker probe
- Non-destructive type perturbation probe
- 한 번에 하나의 InputPoint만 변경

### Feature

- `numeric_value`
- `status_code_changed`
- `response_length_diff_ratio`
- `response_time_diff_ratio`
- `redirect_changed`
- `marker_reflected`
- `reflection_count_norm`
- `safe_html_encoding_detected` (가능 범위)
- `sql_error_pattern`

### Scoring

- SQLiScorer
- XSSScorer
- ScoreEvidence

### Selection

- deterministic global Top-K using cross-type `selection_priority`

### Output

- CLI summary
- JSON report
- HTML dashboard report (optional `--html-output`; renders the same
  validated `SelectionOutcome` and the actually-executed baseline/probe
  pair as the JSON report — see §13 and ADR-011)

---

## 3. Out of Scope

- real multi-account authentication/session orchestration (login flows,
  credential storage, role management)
- role-based vertical BAC matrices beyond the two ADR-012 checks
- focused exploit verification
- LLM payload generation
- payload mutation
- Playwright dynamic crawler
- browser network interception
- ML ranker
- grid search
- ZAP replacement
- scanning arbitrary Internet hosts

---

## 4. Required User Flow

```text
vulnspider scan \
  --target http://127.0.0.1:PORT \
  --max-depth 2 \
  --max-requests 100 \
  --delay-ms 100 \
  --top-k 10 \
  --output result.json
```

정확한 CLI 문법은 구현 중 조정 가능하지만 의미는 유지한다.

---

## 5. Required Functional Flow

1. target URL validation
2. scope allowlist validation
3. crawl or load legacy crawl records
4. normalize Endpoint
5. split each parameter/form field into separate InputPoint
6. deduplicate InputPoints
7. create Baseline request
8. create one-at-a-time Probe request
9. collect ResponsePair
10. extract FeatureVector
11. generate SQLi/XSS Candidates
12. compute RankScore
13. store ScoreEvidence
14. sort global Top-K by deterministic cross-type selection priority
15. emit JSON

---

## 6. Acceptance Criteria

### AC-01 InputPoint 분해

입력:

```text
/search?q=book&page=1
```

출력 최소:

```text
GET /search :: query.q
GET /search :: query.page
```

---

### AC-02 Form 분해

입력:

```html
<form method="post" action="/login">
  <input name="username">
  <input name="password" type="password">
</form>
```

출력 최소:

```text
POST /login :: form.username
POST /login :: form.password
```

---

### AC-03 One-at-a-time Probe

두 개 이상의 parameter가 있는 request에서 Probe가 target 하나만 변경해야 한다.

테스트가 이를 기계적으로 검증해야 한다.

---

### AC-04 4xx/5xx 보존

Probe 응답 4xx/5xx를 예외로 폐기하지 않고 ResponseSnapshot으로 저장한다.

---

### AC-05 Missing vs Zero

미실행 feature는:

```text
observed=false
value=null
```

검사 결과 없음은:

```text
observed=true
value=0
```

이어야 한다.

---

### AC-06 Explainable Score

각 Candidate는 최소 다음을 출력한다.

```text
rank_score
feature value
weight
contribution
reason
```

---

### AC-07 Type-specific Ranking

동일 InputPoint에 대해 SQLi와 XSS Candidate가 독립적으로 존재할 수 있어야 한다.

---

### AC-08 Scope Safety

허용되지 않은 host로 redirect되거나 외부 link가 발견되어도 요청하지 않는다.

---

### AC-09 Deterministic Unit Tests

네트워크 없이 다음 핵심 로직을 검증한다.

- canonicalization
- InputPoint extraction
- deduplication
- probe mutation
- feature calculation
- score contribution
- Top-K

---

### AC-10 End-to-end Local Smoke Test

허가된 로컬 fixture/test app 하나에서:

```text
Target -> InputPoints -> Features -> Candidates -> Top-K JSON
```

전체 흐름이 완료되어야 한다.

---

### AC-11 Broken Access Control Cross-category Top-K (ADR-012)

쿠키/`Authorization` 헤더가 있는 GET `RequestTemplate`과 숫자 식별자를 가진
GET `InputPoint`가 모두 존재하는 fixture에서, `vulnspider analyze`의 최종
Top-K JSON에 `category: "BROKEN_ACCESS_CONTROL"` 후보가 `category:
"INJECTION"` 후보와 함께 `selection_priority` 기준으로 정렬되어 나타나야
한다. 쿠키도 숫자 식별자도 없는 기존 fixture는 BAC 후보 없이 이전과 동일한
injection 결과를 내야 한다(`tests/integration/test_bac_smoke.py`).

---

## 7. v0.1 성공 기준

프로토타입 성공은 "취약점 100% 탐지"가 아니다.

다음이 성공이다.

1. 입력점 단위 attribution이 깨지지 않는다.
2. 동일한 fixture에서 동일 score가 재현된다.
3. 후보마다 점수 근거를 설명할 수 있다.
4. Top-K가 생성된다.
5. 안전한 로컬 범위 밖으로 요청하지 않는다.
6. 후속 실험을 위한 feature cache가 가능하다.

---

## 8. 권장 구현 순서

```text
P0 Repository scaffold
P1 Legacy audit
P2 Domain model
P3 Legacy adapter + normalizer
P4 Probe planner + executor
P5 Feature extraction
P6 Scorers + evidence
P7 Top-K + JSON
P8 Integration smoke test
P9 Review + docs sync
```

---

## 9. 05A Baseline / Probe Planning Semantics

05A implements deterministic request planning only. It does not perform HTTP
execution, collect responses, extract features, generate candidates, score,
select Top-K, call an LLM, invoke browser/dynamic crawling, or use the legacy
SQLite schema.

Planning consumes an explicit, validated relationship between an `InputPoint`
and one selected `RequestTemplate` through `InputPointRequestContext`. The
planner never chooses a baseline from an `InputPoint` alone and never selects a
canonical baseline when multiple request contexts exist. Callers that want
multiple baseline variants must plan once per selected valid context.

The baseline request preserves the selected request context: method, URL,
headers, cookies, ordered query pairs, ordered form pairs, repeated
occurrences, empty values, and all non-target values. The probe request is a
new request instance built from the same context.

For query probes, when the selected `RequestTemplate.url` contains a raw query
string, executable URL mutation is allowed only if the raw query tokens align
exactly with the stored ordered `RequestTemplate.query` pairs. In the aligned
case, the planner replaces only the selected target occurrence value and
preserves every non-target raw token unchanged, including order, repeated names,
bare tokens, empty values, `%20` versus `+`, and percent-escape spelling. If a
raw query exists but cannot be aligned exactly with `RequestTemplate.query`, the
planner rejects planning with `raw-query-alignment-failed` rather than
reconstructing a potentially different executable query. If no raw query exists
in the URL, the planner may reconstruct the executable query from the structured
ordered pairs; that path is structured reconstruction, not raw-token
preservation.

The probe mutates exactly one intended `InputPoint` occurrence:

- non-repeated targets use `query.name` or `form.name`;
- repeated targets require an occurrence-level `InputPoint`;
- occurrence indexes are counted among same-name pairs while preserving the
  original cross-name pair order;
- equal repeated values, such as `tag=a&tag=a`, remain distinct when their
  occurrence indexes differ.

The v0.1 marker strategy is `neutral-reflection-marker-v1`. It produces a
bounded, deterministic, non-destructive marker in this form:

```text
VULNSPIDER_<16 uppercase hex characters>
```

The marker is derived from the marker strategy, probe family, selected
`InputPoint`, selected `RequestTemplate`, selected `InputPointRequestContext`,
location, name, and occurrence index. If the first marker would equal the
baseline value, a deterministic alternate nonce is used.

Non-probe-ready contexts are rejected before request construction. A context is
not probe-ready when its `RequestTemplate.completeness` is not `COMPLETE`, when
structured `non_probe_ready_reasons` are present, when reconstruction status is
`partial` or `ambiguous`, when form boundary status is `unavailable`, or when
form method/action provenance records an assumed or invalid value. The planner
does not parse warning strings, fabricate hidden inputs, or upgrade `PARTIAL`
to `COMPLETE`.

Plan identity is deterministic and persistent. `RequestInstance.id` includes
method, URL, headers, ordered query pairs, ordered form pairs, and cookies.
`ProbePlan.id` includes the input point, probe family, selected request
template, selected request context, marker, marker strategy, baseline request,
probe request, and the changed field. Built-in Python `hash()` is not used.

## 10. 05B Request Execution and Minimal Observation Semantics

05B consumes an existing valid `ProbePlan`; it does not choose an InputPoint,
rebuild a request from a template, collect new discovery evidence, generate
candidates, score, select Top-K, invoke an LLM, or use browser/dynamic crawling.

The request executor sends exactly the plan's `baseline_request` and
`probe_request` through a narrow transport boundary. Unit tests use fake
transports. The standard-library transport disables automatic redirects, keeps
the planned method and executable URL, passes planned headers and cookies, and
uses ordered form pairs as the form body when present. Query execution uses the
planned executable URL from 05A.

`ResponseSnapshot` captures status code, elapsed time, response headers,
bounded decoded body text, body length, body hash, encoding, redirect location,
`execution_error`, and optional ProbePlan provenance. Snapshots produced by
`execute_probe_plan()` carry the exact `probe_plan_id`, `request_role`
(`baseline` or `probe`), and `request_id` for the request they observed. Direct
`execute_request()` snapshots are unowned observations and are not accepted as
ProbePlan-owned pair members. HTTP 4xx/5xx responses are normal observations.
Transport failures, timeouts, and body capture limit failures use
`execution_error`; feature extraction treats those observations as missing, not
as positive vulnerability evidence.

`ResponsePair` attribution is validated before feature extraction: the baseline
snapshot must match `ProbePlan.id`, role `baseline`, and
`ProbePlan.baseline_request.id`; the probe snapshot must match `ProbePlan.id`,
role `probe`, and `ProbePlan.probe_request.id`; and the pair must target the
same `InputPoint` and `ProbePlan`. Equal concrete request bytes or equal
`RequestInstance.id` values across distinct plans do not imply shared
observation ownership.

The minimal 05B extractor emits `FeatureVector` for exactly one InputPoint and
one validated response pair. It currently extracts:

- `status_code_changed`: `1.0` when baseline and probe status codes differ,
  otherwise `0.0`.
- `response_length_diff_ratio`: `abs(probe_length - baseline_length) /
  max(baseline_length, 1)`, clipped to `1.0`; raw ratio and lengths are kept in
  details.
- `marker_reflected`: `1.0` only when the exact 05A probe marker appears in the
  probe body and not in the baseline body; pre-existing marker text is recorded
  but not treated as new reflection.
- `sql_error_pattern`: `1.0` only when a small auditable SQL/DB error pattern
  appears newly in the probe body; generic HTTP 500 alone is not SQL evidence.

Deferred to later stages: candidate generation, SQLi/XSS scoring, Top-K,
advanced timing analysis, DOM/browser analysis, BAC, LLM/RAG, and focused
verification.

## 11. 05C Candidate Generation and Scoring Semantics

05C consumes one existing `FeatureVector`; it does not read response bodies,
rerun extraction, send requests, select Top-K, or create findings/confidence.
It generates the two independent ranking interpretations defined by the exact
unit `InputPoint x VulnerabilityType`: `SQLI` and `REFLECTED_XSS`.

Candidate ownership comes only from `FeatureVector.input_point_id`; the API has
no separate caller-supplied InputPoint id. Candidate identity is the stable
fingerprint of that exact InputPoint id and vulnerability type, so the two types
cannot collide and occurrence-level InputPoint ids remain distinct even when
their values are equal. Score evidence also records the exact source
`FeatureVector.id` so observations from separate request contexts are not mixed.
`ScoringResult` construction requires the actual `FeatureVector` through a
validated factory; direct construction from an opaque vector id is unsupported.
The factory rejects candidate owner mismatches and evidence whose candidate,
vector, or vulnerability type does not match the result.

The deterministic 05C policies use only features currently emitted by 05B:

```text
SQLi raw RankScore (0..75):
+ 20 * status_code_changed
+ 20 * response_length_diff_ratio
+ 35 * sql_error_pattern

Reflected XSS raw RankScore (0..45):
+ 35 * marker_reflected
+ 10 * response_length_diff_ratio
```

These are unnormalized verification-priority signals, not vulnerability
probabilities or final confidence. A missing term is recorded with
`observed=false`, `feature_value=null`, and `contribution=null`; it supplies no
numeric contribution and does not renormalize remaining weights. An observed
zero remains `observed=true`, `feature_value=0.0`, and `contribution=0.0`.

Deferred to 05D and later stages: Top-K, CLI/JSON orchestration, focused
verification, confidence updates, findings, BAC, LLM/RAG, and weight tuning.

## 12. 05D Top-K, JSON, and CLI Semantics

05D preserves each candidate's raw RankScore and derives a separate global
selection key:

```text
selection_priority = raw_rank_score / exact_scorer_maximum

SQLi maximum:          75
Reflected XSS maximum: 45
```

Selection sorts by `selection_priority` descending and `candidate.id`
ascending. Multiple request contexts for one exact candidate identity resolve to
the best priority, then `FeatureVector.id`; distinct vulnerability types and
occurrence-level InputPoints are never merged. Results with no observed scoring
term are counted as unrankable and excluded. An observed zero remains rankable.

`RankedScoringResult` is created only from an authoritative `ScoringResult` and
the exact scorer policy; callers do not supply raw score, maximum, or selection
priority independently. Selection summaries validate non-negative accounting,
`total = rankable + unrankable`, and selected-count bounds. A
`SelectionOutcome` validates that summary counts match its selected and
unrankable contents, that selected identities are unique and ordered, and that
every ranked entry still matches its underlying `ScoringResult`. JSON reporting
revalidates the complete outcome before serialization. Summaries and outcomes
are produced only by `select_top_k()` from its actual input set; direct public
construction with caller-supplied accounting is unsupported.

Neither RankScore nor `selection_priority` is a vulnerability probability,
final Confidence, or confirmation state.

The deterministic JSON report contains summary counts and selected candidates:

```json
{
  "schema_version": "0.1",
  "summary": {
    "total_scoring_results": 2,
    "rankable_results": 2,
    "unrankable_results": 0,
    "selected_results": 1,
    "top_k_requested": 1
  },
  "candidates": [
    {
      "rank": 1,
      "candidate_id": "cand_...",
      "input_point_id": "inp_...",
      "feature_vector_id": "fv_...",
      "vulnerability_type": "REFLECTED_XSS",
      "raw_rank_score": 45.0,
      "raw_rank_score_max": 45.0,
      "selection_priority": 1.0,
      "evidence": []
    }
  ]
}
```

The CLI boundary is an array of existing `LegacyCrawlerAdapter`-compatible JSON
records, not a live crawler. The audited legacy runtime is not present as a
safe callable dependency in this checkout. The command performs only authorized
localhost/loopback Light Probes:

```text
vulnspider analyze \
  --input legacy-records.json \
  --top-k 10 \
  --output result.json
```

It reuses the existing planner, `execute_probe_plan()` path, extractor, and
ownership-validated scorers. Focused verification, findings, confidence, LLM,
BAC, dynamic crawling, and database persistence remain out of scope.

## 13. HTML Dashboard Report Semantics (ADR-011)

13 adds a second, optional report renderer; it does not add a new pipeline
stage, new scoring, new vulnerability types, or focused/multi-payload
verification. It consumes the same `SelectionOutcome` the JSON reporter
consumes, plus the `InputPoint`/`Endpoint` objects already produced by the
adapter and the `ProbePlan`/`ResponseSnapshot` pair already produced by
`execute_probe_plan()` for each `FeatureVector`. It does not recompute a
score, invent evidence, or call the network.

```text
vulnspider analyze \
  --input legacy-records.json \
  --top-k 10 \
  --output result.json \
  --html-output result.html
```

`--html-output` is optional; omitting it leaves CLI behavior identical to
05D (JSON report only).

Terminology: the dashboard labels `selection_priority` as "priority" /
"RankScore" (우선순위) with its exact scorer maximum shown alongside it. It
never uses "confidence", "probability", or "confirmed" — the same constraint
the JSON report's evidence text already follows (AGENTS.md rules 5-6,
ADR-010). Body copy is Korean, and the constraint is about the claim rather
than the language, so the Korean equivalents (확률, 신뢰도, 확정) are banned
too; both bans are asserted by the reporting tests. Vulnerability/check
names (SQL Injection, Reflected XSS, Broken Access Control), identifiers,
URLs, and feature names stay verbatim so the dashboard, the JSON report, and
these docs keep naming the same things the same way.

Charts: `reporting/charts.py` renders inline SVG/CSS only — a priority-band
donut, a per-type bar chart, a pipeline funnel, a Top-K priority comparison,
one bar per evidence term (sized by its share of the scorer maximum), and a
baseline/probe response comparison. Every chart is a second reading of
numbers already in the report context; none of them derives a new signal,
and none loads an external script, stylesheet, font, or image, so the report
stays a single static file that renders offline and makes no outbound
request when opened. Chart colours come from a fixed tone whitelist, never
from interpolated observed data.

Verification content: v0.1's Light Probe sends exactly one baseline request
and one probe request per `InputPoint` (§2.3). The dashboard's "Executed
requests" section shows exactly those two real requests/responses (role,
URL or changed field + injected value, status code, body length, elapsed
ms) for the `FeatureVector` backing each selected candidate. It does not
show a multi-row "verification payload" table implying several distinct
confirmation payloads were sent, because v0.1 does not send them; that
remains Focused Verification, a later-version concept (§2.2, §3).

Every other figure shown (endpoint, parameter, "why it ranks" evidence
list, summary counts, warnings, unrankable results) is the same data the
JSON report already exposes, joined for display only — no new derived
signal is introduced. All text interpolated from crawled/observed data
(endpoint path, parameter name, evidence reason strings, warnings) is HTML
escaped — including chart labels and captions — since that data can come
from an untrusted target response.

## 14. Broken Access Control (BAC) Semantics (ADR-012)

14 adds a second, structurally separate candidate pipeline
(`vulnspider.access`); it does not add a `VulnerabilityType` value, does not
reuse `VulnerabilityCandidate`/`ScoringResult`/`SQLiScorer`/`XSSScorer`, and
does not perform real multi-account login. It is only reachable for `GET`
requests, and only for the two comparisons a normal crawl already gives
enough information to plan.

### AccessCandidate identity

`docs/DOMAIN_MODEL.md` #12 reserves this shape; `domain.access` implements
it: `AccessCandidate` = `endpoint_id x check_kind x subject_context x
resource_reference x input_point_id`. `input_point_id` is `None` for
`CREDENTIAL_STRIP` (it is not about one InputPoint's value) and set for
`IDENTIFIER_SUBSTITUTION`.

### CREDENTIAL_STRIP

Eligible only for a probe-ready `GET` `RequestTemplate` that carries cookies
or an `Authorization` header — i.e. the crawl actually used some credential
to reach this resource. The comparison request is the exact same request
with `Cookie`/`Authorization` removed. `subject_context` on the resulting
candidate is `ANONYMOUS`.

### IDENTIFIER_SUBSTITUTION

Eligible only for a probe-ready `GET` `RequestTemplate` and a `QUERY`/`FORM`
`InputPoint` whose baseline value is purely numeric digits. The comparison
request substitutes `baseline + 1` for that one occurrence, exactly as
05A's one-at-a-time discipline requires for InputPoint mutation (AGENTS.md
rule 4), except the marker is a plausible alternate identifier instead of an
injection marker. Non-numeric identifiers (UUIDs, opaque tokens) are never
substituted — v0.1 does not fabricate a "plausible" alternate value for
those.

### Features and scoring

Two features, both `access_response_diff`-sourced and both requiring the
reference request to have actually returned 2xx (otherwise both are
`observed=False`, never a fabricated zero):

```text
access_unauthorized_success: 1.0 if the comparison request ALSO returns 2xx
  (not denied), else 0.0.
access_body_size_similarity_ratio: 1 - min(abs(comparison_len - reference_len)
  / max(reference_len, 1), 1.0) — how substantial/similarly-sized the
  comparison body is to the reference body.

AccessScorer raw rank_score (0..75):
+ 55 * access_unauthorized_success
+ 20 * access_body_size_similarity_ratio
```

This is the same unnormalized verification-priority signal discipline as
05C's SQLi/XSS weights (§11) — not a probability, not confidence, not a
finding.

### Cross-category Top-K

`selection.combined.select_combined_top_k()` merges the existing injection
`SelectionOutcome` (unmodified `select_top_k()`) and a new
`AccessSelectionOutcome` (`access.selection.select_top_k_access()`, same
`RankedScoringResult`-style invariants as 05D §12) into one ranked list, both
compared through the same `selection_priority = raw_rank_score /
exact_scorer_maximum` principle ADR-010 established for SQLi vs XSS. Both
sub-selections must be computed with the same `k`; the merge takes each
category's own top-`k` and re-sorts, which is exact because any item inside
the true global top-`k` must already be inside its own category's top-`k`.

### CLI/report output

```text
vulnspider analyze \
  --input legacy-records.json \
  --top-k 10 \
  --output result.json \
  --html-output result.html
```

The CLI flags are unchanged. `--output`/`--html-output` now render the
combined Top-N (`reporting.combined_report`) instead of the SQLi/XSS-only
report; the existing `reporting.json_report`/`reporting.html_report` public
functions and their SQLi/XSS-only behavior are untouched and still directly
callable. A fixture with no cookies/`Authorization` header and no numeric
InputPoint produces zero access candidates and an unchanged injection-only
result (see AC-11).

`discovery.legacy_adapter.LegacyCrawlRecord` gained an optional `cookies`
field (JSON object or JSON-encoded string) so a crawl record can carry the
session used to reach it; omitting it is identical to before this field
existed.

Deferred: real login/session orchestration, role-based vertical BAC checks,
non-numeric identifier substitution, and any BAC verification beyond the two
Light Probes above.
