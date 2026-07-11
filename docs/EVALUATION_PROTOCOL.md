# Evaluation Protocol

## 1. 목적

VulnSpider의 핵심 주장은 "모든 입력점을 깊게 검사하지 않고도 검증 가치가 높은 후보를 상위에 배치한다"는 것이다.

따라서 평가도 단순 탐지 개수보다 ranking과 request budget 효율을 중심으로 설계한다.

---

## 2. v0.1 평가 단계

v0.1에서는 본격적인 최종 논문 평가보다 **평가 가능성 확보**가 목표다.

필수:

- feature cache 가능
- candidate-level ground truth key 정의
- deterministic scorer version 기록
- request count 기록
- timing 기록

---

## 3. Ground Truth Key

권장 최소 단위:

```text
(application_id,
 method,
 canonical_path,
 parameter_location,
 parameter_name,
 vulnerability_type)
```

예:

```text
(dvwa, GET, /vulnerabilities/sqli/, query, id, SQLI)
```

정상 입력점도 포함해야 false positive를 평가할 수 있다.

---

## 4. 데이터 누수 방지

금지:

- 같은 route family의 거의 동일한 InputPoint를 무작위 row split로 train/validation에 분산
- test app을 보면서 weight 조정
- ground truth에 맞춰 feature definition을 사후 수정하고 같은 test 결과를 최종 성능으로 재사용

권장:

### 데이터 충분

- GroupKFold
- group = application 또는 challenge/route family

### 데이터 적음

- Development apps: weight 설계/튜닝
- Completely unseen app: final holdout

자체 제작 앱을 test-only로 유지하는 방식을 우선 고려한다.

---

## 5. 비교군

### Baseline A — All-input verification

모든 후보를 동일하게 검증한다고 가정.

### Baseline B — Random Top-K

무작위 후보 선택.

목적:

"그냥 적게 뽑아도 되는가?"에 답한다.

### Baseline C — Static heuristic only

예:

- numeric parameter 우선
- reflection 유무만 사용

### Proposed — Differential Feature Scoring

정적 + baseline/probe 응답 차이 기반.

### Secondary External Reference

ZAP 등은 보조 참고 비교로 두고, 주된 인과 비교는 내부 baseline과 수행한다.

---

## 6. 핵심 지표

### `Recall@K` / Top-N Hit Rate

실제 positive 후보 중 상위 K에 포함된 비율.

### `Precision@K`

상위 K 중 실제 positive 비율.

### `MAP@K`

여러 query/group에서 positive가 상위에 배치되는 정도.

### `NDCG@K`

순위 품질 보조 지표.

### `Request Reduction`

```text
1 - selected_verification_requests / all_verification_requests
```

### `Candidate Reduction`

```text
1 - TopK / all_candidates
```

### `Vulnerabilities Found vs Request Budget`

강력 추천 그래프:

```text
x = verification request budget
y = cumulative true vulnerabilities found
```

---

## 7. Ablation

후속 실험:

- XSS에서 encoding feature 제거
- SQLi에서 SQL error pattern 제거
- differential features 전체 제거
- static features 전체 제거

질문:

> 어떤 feature family가 실제 ranking 향상에 기여하는가?

---

## 8. Reproducibility

모든 실험 결과에 기록:

```text
commit hash
feature_schema_version
scorer_version
target app version
seed
request limits
probe policy
weight config
```

---

## 9. v0.1에서 하지 않는 평가

- LLM 모델 간 비교
- BAC 완전 자동화 성능
- 인터넷 실서비스 일반화 주장
- "상용 스캐너보다 우수"라는 광범위 주장

v0.1은 ranking pipeline이 평가 가능한 구조인지 확인하는 단계다.
