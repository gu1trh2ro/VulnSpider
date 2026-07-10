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

- Top-K per vulnerability type

### Output

- CLI summary
- JSON report

---

## 3. Out of Scope

- BAC / IDOR automation
- authentication role orchestration
- focused exploit verification
- LLM payload generation
- payload mutation
- dashboard
- Playwright dynamic crawler
- browser network interception
- ML ranker
- grid search
- ZAP replacement
- scanning arbitrary Internet hosts

---

## 4. Required User Flow

```text
spiderman scan \
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
14. sort Top-K per type
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
SPIDERMAN_<16 uppercase hex characters>
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
