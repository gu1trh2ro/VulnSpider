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
