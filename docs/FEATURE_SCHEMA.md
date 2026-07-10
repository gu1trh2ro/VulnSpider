# Feature Schema — v0.1

## 1. 목적

Feature는 후보 우선순위화의 근거다. 따라서 모든 feature는:

1. 정의가 deterministic 해야 하고
2. 어느 InputPoint에서 생성됐는지 명확해야 하며
3. 미관찰과 0을 구분해야 하고
4. 버전이 있어야 한다.

v0.1 schema version:

```text
feature-v0.1
```

---

## 2. 공통 표현

```json
{
  "value": 1.0,
  "observed": true,
  "source": "reflection_marker_probe",
  "extractor_version": "reflection-v1",
  "details": {}
}
```

미관찰:

```json
{
  "value": null,
  "observed": false,
  "source": "not_run",
  "extractor_version": "reflection-v1",
  "details": {}
}
```

---

## 3. Static Features

### `numeric_value`

목적: baseline 값이 숫자형으로 해석 가능한지 표시.

정의:

```text
1.0: 전체 문자열이 정수 또는 실수 형태
0.0: 그 외
```

주의: 숫자형이라는 사실은 취약 증거가 아니라 약한 prior다.

---

### `id_like_name`

v0.1에서는 수집 가능하나 SQLi/XSS 기본 scorer에 높은 가중치를 주지 않는다.

예시 이름 패턴:

```text
id
user_id
product_id
itemId
```

---

### `input_location_query`

```text
1.0 if location == QUERY else 0.0
```

---

### `input_location_form`

```text
1.0 if location == FORM else 0.0
```

---

## 4. Differential Features

Baseline 응답 B와 Probe 응답 P를 비교한다.

### `status_code_changed`

```text
1.0 if B.status_code != P.status_code else 0.0
```

세부 정보에 before/after status 저장.

---

### `response_length_diff_ratio`

권장 정의:

```text
abs(len(P) - len(B)) / max(len(B), 1)
```

초기에는 clipping 가능:

```text
min(value, 1.0)
```

raw 값도 details에 보존.

---

### `response_time_diff_ratio`

v0.1 보조 feature.

단일 요청 timing은 노이즈가 크므로 높은 가중치 금지.

권장:

```text
abs(P_ms - B_ms) / max(B_ms, 1)
```

후속 버전에서는 반복 요청 median 사용.

---

### `redirect_changed`

```text
1.0 if redirect behavior or Location differs else 0.0
```

---

## 5. Reflection / XSS Features

### `marker_reflected`

Probe marker가 decoded response text에 존재하는지.

```text
1.0: exact marker found
0.0: not found
```

source:

```text
reflection_marker_probe
```

---

### `reflection_count_norm`

marker 등장 횟수의 정규화 값.

v0.1 권장:

```text
min(count / 3, 1.0)
```

---

### `safe_html_encoding_detected`

marker 주변의 특수 문자가 안전한 HTML entity로 변환되었는지.

v0.1에서는 구현 가능 범위를 좁힌다.

```text
1.0: configured probe sentinel의 위험 문자가 일관되게 entity encoding
0.0: 그렇지 않음
```

이 feature는 XSS score의 penalty 후보다.

주의:

- 단순 marker reflection만으로 XSS 확정 금지
- context parser가 불충분하면 `observed=false` 사용

---

### `dangerous_reflection_context`

v0.1 optional feature.

문맥 분류가 안정적으로 구현되기 전에는 scorer에서 제외해도 된다.

가능한 값의 수치화 예:

```text
0.0 text-safe/unknown
0.5 attribute-like
1.0 script-like dangerous context
```

불확실하면 추측하지 말고 미관찰 처리.

---

## 6. SQL Signal Features

### `sql_error_pattern`

Probe 응답에서 DB/SQL 관련 오류 패턴이 새롭게 나타나는지.

정의 원칙:

- baseline에도 동일 패턴이 있으면 강한 신호로 보지 않음
- probe에서 새롭게 등장해야 함
- pattern source/version 저장

값:

```text
1.0: new SQL-related error pattern
0.0: checked, not found
```

주의:

일반 500 오류만으로 1.0 금지.

---

### `type_perturbation_behavior_diff`

숫자형 baseline에 비파괴적인 type perturbation을 적용했을 때 유의미한 응답 차이가 있는지.

v0.1 권장 계산:

다음 신호의 weighted local combination으로 만들 수 있으나, 개별 feature와 중복 기여하지 않도록 scorer 설계 시 주의한다.

```text
status change
length diff
new SQL error pattern
redirect change
```

초기에는 별도 composite feature를 만들지 않고 개별 feature만 사용하는 것도 권장된다.

---

## 7. v0.1 기본 Scoring 초안

초기 가중치는 연구 결과가 아니라 **작동하는 baseline**이다. 이후 ground truth 실험으로 조정한다.

### XSS

```text
+ 35 * marker_reflected
+ 10 * reflection_count_norm
- 30 * safe_html_encoding_detected
+ 15 * dangerous_reflection_context   # observed일 때만
+ 10 * response_length_diff_ratio
```

### SQLi

```text
+ 15 * numeric_value
+ 20 * status_code_changed
+ 20 * response_length_diff_ratio
+ 35 * sql_error_pattern
+  5 * redirect_changed
```

### 05C implemented subset

현재 05B가 실제로 추출하는 feature만 사용한다. 아직 추출되지 않는
`numeric_value`, `reflection_count_norm`, `safe_html_encoding_detected`,
`dangerous_reflection_context`, `redirect_changed`는 05C에서 값을 만들거나
0으로 가장하지 않는다.

```text
SQLi raw RankScore:
+ 20 * status_code_changed
+ 20 * response_length_diff_ratio
+ 35 * sql_error_pattern
available range: 0..75

Reflected XSS raw RankScore:
+ 35 * marker_reflected
+ 10 * response_length_diff_ratio
available range: 0..45
```

두 score는 정규화하지 않으며 vulnerability probability나 최종 Confidence가
아니다. 서로 다른 scale의 verification-priority 신호다.

### Missing feature 처리

미관찰 feature는 numeric score 합계에 0의 효과만 주지만, evidence의
`contribution`은 관찰된 숫자 `0.0`으로 만들지 않고 `null`로 기록한다.

단:

- "관찰하지 않았음"을 "안전함"으로 해석하지 않는다.
- score evidence에 `observed=false`, `feature_value=null`,
  `contribution=null` 상태를 기록한다.

---

## 8. Feature 추가 규칙

새 feature를 추가하기 전에 문서에 다음을 기록한다.

1. 이름
2. 목적
3. 정확한 계산식
4. 입력 데이터
5. 출력 범위
6. missing 조건
7. 오탐 가능성
8. 사용 scorer
9. extractor version
10. 테스트 fixture
