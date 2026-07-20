# VulnSpider Architecture — Prototype v0.1

## 1. 목적

VulnSpider은 웹 애플리케이션에서 수집된 다수의 입력점 중 **어떤 입력점을 먼저 검증할 가치가 있는지** 자동으로 순위화하는 시스템이다.

v0.1의 연구 질문은 다음과 같다.

> 모든 입력점에 동일한 수준의 심층 검증을 수행하지 않고도, 가벼운 관찰 결과로 실제 취약 가능성이 높은 후보를 상위에 배치할 수 있는가?

따라서 v0.1의 핵심 산출물은 "취약점 확정"이 아니라 다음이다.

1. 공격 표면 수집
2. 입력점 정규화
3. 입력점별 저위험 Light Probe
4. Feature Vector 생성
5. 취약점 유형별 RankScore 계산
6. Top-K 후보와 근거 출력

---

## 2. 핵심 설계 원칙

### 2.1 분석 단위 분리

```text
Page
  -> Endpoint
      -> InputPoint
          -> VulnerabilityCandidate
```

예시:

```text
Page:      /search?q=book&page=1
Endpoint:  GET /search
InputPoint A: query.q
InputPoint B: query.page
Candidate A1: query.q x REFLECTED_XSS
Candidate A2: query.q x SQLI
Candidate B1: query.page x REFLECTED_XSS
Candidate B2: query.page x SQLI
```

### 2.2 Discovery, Observation, Verification 분리

- **Discovery**: 무엇이 존재하는가?
- **Observation**: 입력 하나를 약하게 변화시켰을 때 응답이 어떻게 달라지는가?
- **Verification**: 실제 취약점 근거가 반복 가능하게 확인되는가?

v0.1은 Observation과 Ranking까지 구현한다. Focused Verification은 후속 버전이다.

BAC는 ADR-012로 §4.9의 별도 `vulnspider.access` 파이프라인으로 in-scope에
추가됐다. Discovery/Observation/Verification 구분은 BAC에도 동일하게 적용된다 —
다만 BAC의 "Observation"은 InputPoint 하나를 변화시키는 대신 subject_context
(자격 증명 유무) 또는 resource_reference(식별자)를 하나만 변화시켜 같은 요청을
재전송한다(§2.3 참고).

### 2.3 한 번에 하나의 입력점만 변경

동일한 RequestTemplate을 유지하고 target InputPoint 하나만 변화시킨다.

```text
Baseline: /search?q=book&page=1
Probe(q): /search?q=ZXCV_7F21_MARKER&page=1
```

이 원칙을 지켜야 응답 변화의 원인을 특정 입력점에 귀속할 수 있다.

### 2.4 점수와 확신도 분리

- `RankScore`: 먼저 검증할 가치
- `VerificationConfidence`: 후속 검증 뒤 실제 취약이라고 판단할 근거 강도

v0.1에는 RankScore만 존재한다.

---

## 3. v0.1 전체 파이프라인

```text
[0] ScopeGuard
      |
[1] DiscoveryCollector
      |
[2] LegacyCrawlerAdapter
      |
[3] AttackSurfaceNormalizer
      |
      +--> Endpoint[]
      +--> InputPoint[]
      |
[4] ProbePlanner
      |
[5] RequestExecutor
      |
      +--> Baseline ResponseSnapshot
      +--> Probe ResponseSnapshot
      |
[6] ResponseNormalizer
      |
[7] FeatureExtractor Pipeline
      |
      +--> StaticFeatureSet
      +--> DifferentialFeatureSet
      +--> ReflectionFeatureSet
      +--> SQLSignalFeatureSet
      |
[8] FeatureVector
      |
[9] CandidateGenerator
      |
      +--> SQLI Candidate
      +--> REFLECTED_XSS Candidate
      |
[10] Type-specific Scorers
      |
      +--> SQLiScorer
      +--> XSSScorer
      |
[4b] AccessProbePlanner (vulnspider.access, ADR-012)
      |
      +--> CREDENTIAL_STRIP plan (RequestTemplate has cookies/Authorization)
      +--> IDENTIFIER_SUBSTITUTION plan (numeric InputPoint baseline)
      |
[5b] AccessProbe RequestExecutor (same RequestTransport boundary)
      |
      +--> reference ResponseSnapshot
      +--> comparison ResponseSnapshot
      |
[7b] Access FeatureExtractor
      |
[9b] AccessCandidate generation + AccessScorer
      |
[11] Cross-category TopKSelector (select_combined_top_k, ADR-012)
      |
[12] Reporting
      |
      +--> JsonReporter / HtmlDashboardReporter (SQLi/XSS-only, unchanged)
      +--> Combined JsonReporter / HtmlDashboardReporter (ADR-012, all 3 types)
```

---

## 4. 모듈 경계

### 4.1 `scope/`

책임:

- 허용 host 검사
- redirect 후 scope 재검사
- request budget 검사
- crawl depth 검사

금지:

- suffix 문자열만으로 내부 도메인 판단
- 새 host 자동 허용

---

### 4.2 `discovery/`

책임:

- URL, link, form, input, query parameter 수집
- 기존 WHSPIDER의 proven crawling logic을 adapter 뒤에서 재사용 가능

v0.1:

- static discovery 우선
- dynamic/browser discovery 제외

출력:

```text
RawDiscoveredSurface[]
```

---

### 4.3 `surface/`

책임:

- URL canonicalization
- Endpoint 추출
- InputPoint 분해
- form action/method 해석
- deduplication
- deterministic fingerprint 생성

출력:

```text
Endpoint[]
InputPoint[]
RequestTemplate[]
```

---

### 4.4 `observation/`

책임:

- Baseline 계획
- Probe family 선택
- target InputPoint 하나만 변화
- 요청 전송
- raw response snapshot 저장

중요:

Crawler HTTP client와 Probe Executor는 분리한다. 4xx/5xx는 Probe에서 중요한 관찰값이다.

---

### 4.5 `features/`

책임:

응답과 입력 특성을 deterministic feature로 변환한다.

Feature 그룹:

1. Static
2. Differential
3. Reflection / Encoding
4. SQL signal

각 feature는 최소 다음 메타데이터를 가진다.

```text
value
observed
source
extractor_version
```

---

### 4.6 `scoring/`

책임:

- 취약점 유형별 독립 점수 계산
- feature contribution 기록
- explainable evidence 출력

구조:

```text
BaseScorer
  |- SQLiScorer
  `- XSSScorer
```

점수는 확률이 아니다.

---

### 4.7 `selection/`

v0.1:

- raw RankScore는 취약점 유형 내부의 원래 우선순위 신호로 보존
- global Top-K는 각 exact scorer maximum으로 나눈 `selection_priority` 사용
- 동률은 deterministic candidate id 순서로 결정
- 모든 scoring term이 미관찰인 결과는 unrankable로 집계하고 제외

이유:

SQLi와 XSS raw RankScore는 서로 다른 범위이므로 raw 값을 직접 비교하지
않는다. `selection_priority`도 확률이나 Confidence가 아니다.

---

### 4.8 `access/` (ADR-012)

책임:

- BAC(Broken Access Control) 후보 관찰과 채점
- `CREDENTIAL_STRIP`: 크롤 시 사용된 cookies/`Authorization` 헤더를 제거한
  동일 GET 요청 재전송
- `IDENTIFIER_SUBSTITUTION`: 숫자 InputPoint 값을 `baseline + 1`로 치환한
  동일 GET 요청 재전송
- `AccessCandidate`(subject_context x resource_reference) 생성과 `AccessScorer`
  채점

금지:

- `domain.models`의 `VulnerabilityType`/`VulnerabilityCandidate`를 재사용하지
  않는다(`docs/DOMAIN_MODEL.md` #12, ADR-007/ADR-012) — 별도의 `domain.access`
  타입만 사용한다.
- POST 등 상태 변경 가능성이 있는 method는 probe하지 않는다(GET 전용).
- 실제 로그인/다중 계정 세션을 오케스트레이션하지 않는다 — 크롤러가 이미
  관찰한 자격 증명/식별자만 사용한다.

출력:

```text
AccessProbePlan[]
AccessCandidate[] (with AccessScoreEvidence)
```

`selection.combined.select_combined_top_k()`가 이 출력과 §4.7의 injection
`SelectionOutcome`을 병합해 하나의 cross-category Top-K를 만든다. 이 함수는
`selection.top_k.select_top_k()`를 수정하지 않고, 두 카테고리를 동일한 k로
각자 선택한 뒤 병합한다 — 전역 top-k의 모든 항목은 이미 자기 카테고리의
top-k 안에 있어야 하므로 이 방식은 정확하다.

---

### 4.9 `reporting/`

네 개의 렌더러가 있다: SQLi/XSS 전용 `json_report`(필수)와
`html_report`(선택, ADR-011), 그리고 SQLi/XSS/BAC 통합
`combined_report`(ADR-012)의 JSON/HTML 렌더러. 어느 쪽도 점수를 재계산하지
않는다. `combined_report`는 `json_report`/`html_report`의 기존 공개 함수를
바꾸지 않고 그 위에 추가된 렌더러다 — `cli.py`의 `analyze` 명령은
`combined_report`를 사용해 `--output`/`--html-output`에 통합 Top-N을 쓴다.

`html_report`/`combined_report`는 표시용으로 `InputPoint`/`Endpoint`(adapter
출력)와 `ProbePlan`/`AccessProbePlan`/`ResponseSnapshot`(observation/access
출력, 모두 `domain` 타입) 조인을 추가로 받지만, `reporting`은 `observation`,
`access`의 실행/계획 로직, `pipeline`을 직접 import하지 않는다 — 이 값들은
호출자(`pipeline`이 만들고 `cli`가 전달)가 조립해서 넘긴다. `combined_report`가
같은 패키지 내 `html_report`의 렌더링 헬퍼를 재사용하는 것은 예외로 허용한다
(§4.8/§4.9 사이의 재사용이며, `pipeline`으로의 역방향 의존은 아니다). 의존성
방향은 §6과 동일하게 유지된다.

최종 JSON은 raw score와 cross-type selection key를 구분하고 최소 다음을
포함한다.

```json
{
  "candidate_id": "cand_...",
  "input_point_id": "inp_...",
  "feature_vector_id": "fv_...",
  "vulnerability_type": "REFLECTED_XSS",
  "raw_rank_score": 45.0,
  "raw_rank_score_max": 45.0,
  "selection_priority": 1.0,
  "evidence": [
    {
      "feature_name": "marker_reflected",
      "feature_value": 1.0,
      "weight": 35.0,
      "contribution": 35.0
    }
  ]
}
```

---

## 5. 권장 디렉터리 구조

```text
src/vulnspider/
├─ domain/
│   └─ access.py      (AccessCandidate 관계형 모델, ADR-012)
├─ scope/
├─ discovery/
├─ surface/
├─ observation/
├─ access/            (BAC probe planning/execution/features/scoring, ADR-012)
├─ features/
├─ scoring/
├─ selection/
│   └─ combined.py    (cross-category Top-K merge, ADR-012)
├─ reporting/
│   └─ combined_report.py  (SQLi/XSS/BAC 통합 JSON/HTML, ADR-012)
└─ cli.py
```

후속 버전에서만 추가:

```text
verification/
llm/
auth/       (실제 다중 계정 로그인/세션 오케스트레이션 — access/의 두 점검과는
             다르게, 자격 증명을 직접 발급/관리하는 인프라)
```

---

## 6. 의존성 방향

```text
cli -> pipeline + reporting
pipeline -> discovery + observation + features + scoring + selection + access
reporting -> selection -> scoring -> features -> domain
reporting.combined_report -> selection.combined -> access.selection -> access -> domain
selection -> scoring -> features -> domain
selection.combined -> selection.top_k + access.selection
observation -> domain
access -> observation.executor (request execution reuse only) + domain
surface -> domain
discovery -> domain adapters
scope -> shared boundary checks
```

원칙:

- `domain`은 네트워크/DB/LLM에 의존하지 않는다.
- `features`는 HTTP 전송을 직접 하지 않는다.
- `scoring`은 HTTP 응답 원문을 직접 해석하지 않는다.
- `reporting`은 점수를 재계산하지 않는다.
- `access`는 `domain.models`의 `VulnerabilityType`/`VulnerabilityCandidate`를
  재사용하지 않는다(§4.8, ADR-012) — `domain.access`의 별도 타입만 사용한다.

---

## 7. v0.1에서 하지 않는 것

- LLM payload mutation
- exploit-style focused/multi-payload verification (HTML 대시보드의
  "Executed requests"는 실제로 전송된 요청 쌍만 보여주며 이 항목에 해당하지
  않는다 — §4.9, ADR-011/ADR-012)
- Playwright browser collector
- ML ranking model
- grid search weight tuning
- ZAP 대체 구현
- 실제 다중 계정 로그인/세션 오케스트레이션, role 기반 vertical BAC 매트릭스
  (BAC 자체는 ADR-012로 §4.8의 두 점검에 한해 in-scope다 — 그 이상은 여전히
  범위 밖이다)

이 항목을 의도적으로 제외해야 첫 프로토타입이 연구 핵심을 빠르게 검증할 수 있다.

dashboard는 ADR-011로, BAC의 두 점검(§4.8)은 ADR-012로 in-scope로
전환됐다. 위 목록의 다른 항목, 특히 focused verification과 실제
다중 계정 세션 오케스트레이션은 여전히 제외된다.
