# Domain Model

## 1. 목표

코드 전체에서 동일한 용어를 사용하기 위한 v0.1 도메인 명세다.

가장 중요한 규칙:

```text
Page != Endpoint != InputPoint != VulnerabilityCandidate
```

---

## 2. `Endpoint`

서버 기능의 정규화된 요청 대상.

권장 필드:

```text
id: str
method: HttpMethod
scheme: str
host: str
path: str
content_type: str | None
discovered_by: str
```

예:

```text
GET /search
POST /login
```

### Endpoint identity

v0.1 fingerprint 권장 입력:

```text
method + normalized_scheme + normalized_host + canonical_path
```

Query value는 Endpoint identity에 포함하지 않는다.

---

## 3. `InputPoint`

외부 입력을 독립적으로 변화시킬 수 있는 원자 단위.

권장 필드:

```text
id: str
endpoint_id: str
location: InputLocation
name: str
baseline_value: str | None
type_hint: str | None
source_page: str | None
auth_context_id: str | None
metadata: dict
fingerprint: str
```

### InputLocation

v0.1 필수:

```text
QUERY
FORM
```

미래 확장:

```text
JSON
PATH
HEADER
COOKIE
MULTIPART
```

### InputPoint identity

권장:

```text
endpoint_fingerprint
+ location
+ normalized_parameter_name
+ auth_context_id(optional)
```

예:

```text
GET /search :: query.q
GET /search :: query.page
POST /login :: form.username
```

---

## 4. `RequestTemplate`

특정 Endpoint 요청을 재구성하기 위한 원본 구조.

권장 필드:

```text
id: str
endpoint_id: str
method: HttpMethod
url: str
headers: dict[str, str]
query: dict[str, str]
form: dict[str, str]
cookies: dict[str, str]
```

원칙:

- Probe는 template을 복제한다.
- target InputPoint 하나만 변경한다.
- 나머지 입력은 동일하게 유지한다.

---

## 5. `ProbePlan`

관찰 요청 계획.

권장 필드:

```text
id: str
input_point_id: str
probe_family: ProbeFamily
baseline_request: RequestInstance
probe_request: RequestInstance
changed_fields: list[str]
```

검증 규칙:

```text
len(changed_fields) == 1
```

v0.1 ProbeFamily:

```text
REFLECTION_MARKER
TYPE_PERTURBATION
GENERIC_PERTURBATION
```

---

## 6. `ResponseSnapshot`

HTTP 응답 관찰값.

권장 필드:

```text
id: str
request_id: str
status_code: int
elapsed_ms: float
body_bytes_hash: str
body_length_bytes: int
headers: dict[str, str]
decoded_text: str | None
encoding: str | None
redirect_location: str | None
```

주의:

- 4xx/5xx도 정상적인 관찰 데이터다.
- Probe Executor에서 `raise_for_status()` 방식으로 버리지 않는다.

---

## 7. `ResponsePair`

동일 InputPoint에 대한 Baseline/Probe 응답 쌍.

```text
input_point_id
probe_plan_id
baseline_response_id
probe_response_id
```

---

## 8. `FeatureObservation`

단일 feature의 값과 관찰 상태.

권장 필드:

```text
name: str
value: float | bool | str | None
observed: bool
source: str
extractor_version: str
details: dict
```

핵심:

```text
observed=false, value=null
```

은

```text
observed=true, value=0
```

과 다르다.

---

## 9. `FeatureVector`

InputPoint 하나에 귀속되는 정량 feature 집합.

권장 필드:

```text
id: str
input_point_id: str
probe_run_ids: list[str]
feature_schema_version: str
features: dict[str, FeatureObservation]
```

---

## 10. `VulnerabilityCandidate`

랭킹의 원자 단위.

```text
InputPoint x VulnerabilityType
```

권장 필드:

```text
id: str
input_point_id: str
vulnerability_type: VulnerabilityType
rank_score: float | None
scorer_version: str | None
```

v0.1 VulnerabilityType:

```text
SQLI
REFLECTED_XSS
```

---

## 11. `ScoreEvidence`

RankScore 설명용 기여도.

권장 필드:

```text
candidate_id: str
feature_name: str
feature_value: float
weight: float
contribution: float
reason: str
```

합계 규칙:

```text
raw_score = sum(contribution)
```

정규화가 있다면 raw score와 normalized score를 둘 다 보존한다.

---

## 12. 후속 버전 객체

v0.1에는 구현하지 않지만 이름은 예약한다.

### `VerificationEvidence`

Focused Verification 결과 근거.

### `Finding`

최종 상태:

```text
CONFIRMED
LIKELY
UNVERIFIED
REJECTED
```

### `AccessCandidate`

BAC용 관계형 후보. InjectionCandidate와 분리한다.

예:

```text
subject_context
endpoint
resource_reference
resource_owner_context
```

---

## 13. 예시

URL:

```text
/search?q=book&page=1
```

정규화 결과:

```text
Endpoint
  GET /search

InputPoint
  GET /search :: query.q
  GET /search :: query.page

Candidates
  query.q x REFLECTED_XSS
  query.q x SQLI
  query.page x REFLECTED_XSS
  query.page x SQLI
```

---

## 14. Probe-readiness clarifications

These rules refine the v0.1 model for the Probe Planning stage without adding
Probe execution.

### Endpoint ID and fingerprint

`Endpoint.id` is the relationship identifier used by other domain objects. The
raw deterministic endpoint fingerprint remains available as
`Endpoint.fingerprint`.

Fields named `endpoint_id` contain `Endpoint.id`. Fields named
`endpoint_fingerprint` contain the raw fingerprint used for deterministic
InputPoint identity.

### RequestTemplate identity

`RequestTemplate.id` identifies a preserved request context, not only an
endpoint. Its deterministic fingerprint includes:

- endpoint id and endpoint fingerprint
- method and URL
- canonical headers and cookies
- ordered query pairs
- ordered form pairs
- request context completeness
- context key

Two forms that share the same action and method but preserve different request
context must produce different `RequestTemplate` IDs. When a mapping is used for
query or form values, it is canonicalized by sorted key/value pairs. When ordered
pairs are used, their order and duplicate names are preserved.

### InputPoint to request context association

An `InputPoint` can be associated with one or more request contexts through
`InputPointRequestContext`. No future Probe Planner should infer the baseline
request solely from endpoint identity.

If one logical `InputPoint` has multiple baseline request variants, all variants
must be preserved and explicitly associated. v0.1 does not select a canonical
baseline silently.

### Repeated parameter policy

Repeated query parameters are supported by preserving ordered parameter pairs in
`RequestTemplate.query`.

For an `InputPoint`, a single baseline value is stored in `baseline_value`.
Repeated values are stored losslessly in `baseline_values`; in that case
`baseline_value` is `null`.

The same ordered-pair representation is available for form controls so duplicate
same-name controls are not collapsed by `dict` semantics.

### Legacy form completeness

Legacy-derived form request templates are `PARTIAL` by default because the
legacy static parser may omit hidden inputs. The adapter must not interpret the
absence of hidden fields as proof that no hidden fields existed.

The hidden-input limitation must be visible in request template metadata and/or
adapter warnings so future Probe Planning can distinguish complete context from
lossy legacy context.

### Missing method/action provenance

The adapter may keep convenience defaults, such as `GET` for an unknown form
method or the current page URL for an unknown form action, but those defaults are
assumptions. They must be recorded with provenance metadata and warnings.

Explicit legacy metadata, unknown legacy metadata, invalid metadata, and adapter
assumptions must remain distinguishable.

### FeatureVector identity

`FeatureVector.id` identifies a concrete observation set for one InputPoint and
the probe runs that produced it. Its deterministic fingerprint includes:

- `input_point_id`
- `feature_schema_version`
- canonical `probe_run_ids`
- feature names
- observed state
- feature values
- source and extractor version
- feature details

Equivalent vectors produce the same ID. Distinct observed values, observed
states, details, schema versions, or probe-run sets must not silently collide.
