# Decision Layer — 개요와 재현 가이드

`feat/scoring` 브랜치가 만든 것을 한 문서로 정리한다. 세부 근거는
ADR-021~026(`docs/DECISION_LOG.md`)과 `docs/EVALUATION_PROTOCOL.md`에 있고,
이 문서는 그 위를 걷는 지도다.

**한 줄 요약:** 손으로 정한 가중합을 **보정된 확률**로 바꾸고, 고정 Top-K를
**근사 보장이 있는 예산 제약 선택**과 **conformal recall 보장**으로 바꿨다.
그리고 그것이 실제로 나아졌음을 프로토콜이 정한 지표로 측정했다.

---

## 1. 기존 휴리스틱과 무엇이 다른가

### 1.1 기존 방식

`scoring/engine.py`는 feature에 손으로 정한 가중치를 곱해 더한다.

```text
SQLi  RankScore = 20*status_code_changed + 20*response_length_diff_ratio
                + 35*sql_error_pattern                    범위 0..75
XSS   RankScore = 35*marker_reflected + 10*response_length_diff_ratio
                                                          범위 0..45
```

그리고 서로 다른 family를 비교하려고 각자의 최댓값으로 나눴다(ADR-010).

```text
selection_priority = raw RankScore / 그 scorer의 최댓값
```

**세 가지 문제가 있었다.**

| 문제 | 구체적으로 |
|---|---|
| 가중치의 근거가 없음 | 왜 20이고 35인가에 답할 수 없다 |
| family 비교가 정당화되지 않음 | `45/75`와 `27/45`가 왜 비교 가능한가에 답할 수 없다. ADR-010 본문도 "확률이 아니라 selection 전용 key"라고만 적었다 |
| 확률이 아님 | 기대 효용을 더할 수 없다. 예산 배분이 원리적으로 불가능하다 |

### 1.2 측정된 증거

가장 중요한 발견 두 가지.

**(가) 현행 점수는 상수 예측기보다 나쁘다.**

```text
휴리스틱 Brier          0.2150
항상 base rate 예측     0.1858   <- 휴리스틱이 이보다 나쁨
보정 모델(out-of-fold)  0.1134
```

순위로는 쓸 수 있지만 **확률로는 쓸 수 없다**는 뜻이다.

**(나) 손으로 정한 가중치의 부호가 틀렸다.**

코퍼스에서 학습한 SQLi 가중치:

```text
status_code_changed        = -0.451   (휴리스틱: +20)
response_length_diff_ratio = +4.428   (휴리스틱: +20)
sql_error_pattern          = +3.770   (휴리스틱: +35)
```

`status_code_changed`가 **음수**다. 입력 검증이 정상 동작해서 400을 반환하는
것도 상태 코드를 바꾸기 때문이다. 즉 이 신호는 취약점 신호이면서 동시에
**방어가 동작한다는 신호**이기도 하다. 손으로는 알아낼 수 없는 사실이다.

### 1.3 바꾸지 않은 것

기존 휴리스틱을 **버리지 않고 prior로 흡수했다.**

```text
prior 평균 = 휴리스틱 가중치 / prior_scale     (기본 10.0)
logit_mean = logit(base_rate) + RankScore / prior_scale
```

학습 데이터가 0개면 `logit_mean` 순서가 기존 RankScore 순서와 **정확히**
같다. 그래서 코퍼스 없이도 안전하게 채택할 수 있고, 논문에서는 **"rule-based는
데이터가 0일 때의 특수해"**라고 서술할 수 있다.

`analyze`, `-u`, `RankScore`, `selection_priority`, `select_top_k()`의 동작은
그대로다. 결정 계층은 그 검증된 출력을 소비하는 별도 경로다(ADR-022).

---

## 2. Scoring 알고리즘 상세

### 2.1 베이지안 로지스틱 회귀 (`scoring/calibration.py`)

```text
P(취약 | 증거) = sigmoid(w0 + Σ wi·fi)
prior:  w ~ N(휴리스틱가중치 / prior_scale,  τ²I)
```

- **MAP 추정**: damped Newton + backtracking line search
- **사후 분산**: Laplace 근사 (`H = XᵀWX + Λ`의 역행렬 대각)
- **의존성 0개**: 표준 라이브러리만. Cholesky 분해를 직접 구현

### 2.2 line search가 필요한 이유 (실제 발생한 버그)

처음 구현은 undamped Newton이었고 **실제 코퍼스에서 발산했다.**

원인은 **quasi-complete separation**이다. 취약한 XSS candidate 중
`marker_reflected = 0`인 것이 하나도 없어서, 그 가중치가 무한대로 밀려나고,
작업 분산 `μ(1-μ)`가 붕괴하고, 정보 행렬이 prior precision만 남아 매 반복이
직전보다 더 크게 overshoot했다.

```text
수정 전:  intercept +29.8,  Brier 0.4598   (상수 예측기보다 나쁨)
수정 후:  intercept  -4.2,  Brier 0.1134
```

**모든 스텝이 로그 사후확률을 증가시킬 것을 요구**하면 이 실패가 사라진다.
회귀 테스트가 붙어 있다.

> 이 버그는 합성 fixture로는 재현되지 않았다. **실제 코퍼스를 수집했기 때문에**
> 드러났다.

### 2.3 결측 feature 처리

미관측 feature는 logit 합에서 제외된다. 기존 `engine.py`가 이미 하던 것과 같은
규율이고, log-odds 공간에서는 **"증거 없음 → posterior가 prior에 머무름"**으로
정확히 읽힌다.

**알려진 한계(문서화됨):** 선형 모델에서 관측된 `0.0`과 미관측은 logit 기여가
모두 0이라 점수상 구분되지 않는다. 상태는 `CalibrationEvidence.observed`와
`observed_feature_count`에 보존된다.

### 2.4 확률은 logit의 단조 함수가 아니다

가중치 사후분포를 적분하므로(MacKay probit 근사), 점수는 **의존하는 가중치가
얼마나 불확실한지에 비례해 base rate 쪽으로 당겨진다.**

```text
Var(logit) = Var(intercept) + Σ fi²·Var(wi)
```

학습 후에는 코퍼스가 정밀하게 고정한 가중치에 기댄 점수가 damping을 덜 받는다.
**확신 있는 0.9와 어림짐작 0.9를 구분**하는 것이 결정 계층에 필요하다.
휴리스틱 순서가 필요한 소비자는 `logit_mean`을 읽는다.

---

## 3. Selection Top-K 알고리즘 상세

### 3.1 예산 제약 submodular 최대화 (`decision/greedy.py`)

고정 K 대신 **요청 예산 B**를 입력받는다.

```text
U(S) = Σ_그룹 Σ_j  discount^(j-1) · P(취약) · severity
subject to  Σ cost ≤ B
```

**중복성 할인이 핵심이다.** 같은 서버 코드 경로(`redundancy_key` =
endpoint fingerprint)의 candidate는 함께 취약하거나 함께 안전하므로, 두 번째
확인의 가치가 낮다. 감소하는 가중치의 순서 집계는 **단조 submodular**이므로
수확 체감이 탐색에 붙인 휴리스틱이 아니라 **목적함수의 성질**이다.

**알고리즘:** density greedy와 "예산 내 최선의 단일 후보" 중 나은 쪽.

```text
discount < 1 (submodular):  ½(1 − 1/e) ≈ 0.316 보장
discount = 1 (modular):     ½ 보장
```

단일 후보 arm은 장식이 아니다. density greedy만 쓰면 **싼 부스러기로 예산을
채우고 정작 값비싼 대어를 못 사는** 무한히 나쁜 경우가 생긴다.

> 심사에서 **"왜 이 순서인가"에 정리로 답할 수 있다.** rule-based 순위가 줄 수
> 없는 것이다.

### 3.2 Conformal risk control (`decision/conformal.py`)

K를 사람이 정하는 대신 **목표 recall에서 유도한다.**

```text
E[1 − Recall(S_λ̂)] ≤ α
λ̂ = R̂n(λ) ≤ α − (1−α)/n 을 만족하는 가장 큰 임계값
```

분포 무관, 유한 표본 보장이다.

**정직하게 밝힌 두 제약:**

- `α ≥ 1/(n+1)`일 때만 인증 가능하다. **recall 0.90 보장에는 보정
  application이 최소 9개** 필요하다. 미달이면
  `guarantee_attainable = False`가 되고 임계값 0.0으로 전부 선택한다.
  보장되지 않은 수치를 보장된 것처럼 반환하지 않는다.
- exchangeability 가정은 웹 애플리케이션 간에 약하다. leave-one-app-out으로
  보정하고 실측 위반율을 함께 보고한다.

보정은 **out-of-fold 확률**로 한다. 모델이 이미 라벨을 본 확률로 보정하면
보장이 낙관적으로 부풀려진다.

### 3.3 Value of Information — 구현했으나 휴면 (ADR-026)

`decision/voi.py`는 정확하고 테스트도 돼 있지만 **CLI에 배선하지 않았다.**
현재 파이프라인에는 결정할 것이 없기 때문이다. 각각 독립적으로 충분한 이유
네 가지:

1. probe 한 쌍이 이미 feature를 전부 준다 — "다음에 뭘 측정할까"가 없다
2. 미관측 feature가 0/146 — 재probe로 밝힐 것이 없다
3. 결정 계층 실행 시점엔 `analyze_url()`이 이미 전부 probe했다 — 배분할
   probe 예산이 없다
4. 모델에서 candidate가 독립 — A를 probe해도 B가 안 변하므로 적응적 순서가
   임의 순서보다 나을 **수학적 근거가 없다**

살리려면 배선이 아니라 모델링이 필요하다: 같은 코드 경로 candidate 간 상관
모델링(경로 A) 또는 probe family 복수화(경로 B). 둘 다 별도 ADR 대상이고,
**scoring도 selection도 아닌 관측 계층** 작업이다.

---

## 4. Evaluation Metrics 도입과 검증

### 4.1 왜 필요했나

`EVALUATION_PROTOCOL.md` §6이 Recall@K / Precision@K / MAP@K / NDCG@K를 핵심
지표로 지정하고 §5가 Baseline A/B/C를 정의했지만, **그것을 계산하는 코드가
없었다.** 알고리즘은 좋아졌는데 프로토콜이 정한 언어로 말할 수단이 없었다.

### 4.2 코드보다 먼저 판정 규칙을 고정했다 (§6-A)

숫자를 뽑은 뒤 정의를 바꾸면 결과를 유리하게 조작할 수 있다. 그래서 다섯 가지를
먼저 문서에 못박았다.

| 항목 | 결정 |
|---|---|
| 세는 단위 | candidate-level 주 지표, bug-level 병기 |
| 미라벨 | 비관련으로 간주(IR 표준), 개수 함께 보고 |
| query 단위 | application 1개 = query 1개, 그 후 평균 |
| 동점 | 그룹 내 균등 무작위 순서 가정한 **기대값** |
| K vs 예산 | 별도 표로 분리 |

**세는 단위에 대한 정정:** 처음에 `/product?id=1..100`이 candidate를
부풀린다고 했는데 **틀렸다.** 그것들은 `canonical_path`와 `InputPoint`가 같아
도메인 모델이 이미 합친다. 실제 위험은 **경로 세그먼트 템플릿**
(`/product/1`, `/product/2`)이고, `normalize_route()`가 그것만 처리한다.

**동점은 실재한다.** `app01`은 candidate 10개에 서로 다른 확률이 8개뿐이다.
`selection`의 tie-break은 `candidate_id` 해시 — 재현 가능하지만 임의다. 평가가
그 임의성에 의존하면 안 되므로 기대값으로 계산한다. `AP`는 McSherry-Najork
(2008)의 expected average precision을 쓴다.

### 4.3 지표 구현을 두 겹으로 검증했다

의존성이 없어 sklearn 대조가 불가능하므로:

**(가) Baseline B 항등식.** 무작위 랭킹 = 전체가 하나의 동점 그룹이다. 따라서
기대값 계산이 정확하면 **Precision@K가 모든 K에서 유병률과 같아야 한다.**

```text
실측 Precision@K = 0.247  (모든 K)
유병률           = 36/146 = 0.2466   ✓
```

동점 처리와 Baseline B를 **동시에** 검증하는 항등식이다.

**(나) 전수 열거 대조.** 폐쇄형 동점 처리가 **모든 순열의 기대값**과 소수점
9자리까지 일치한다(Recall, NDCG, expected AP 각각). 처음엔 몬테카를로였는데
(34초, 소수점 2자리) 테스트 쿼리가 ≤4개라 전수 열거로 바꿨다 — 0.04초, 정확값.

---

## 5. 측정 결과 전체

전부 합성 loopback 애플리케이션에서 나온 수치다. 실제 웹 애플리케이션 성능이
아니다(§7 참조).

### 5.1 코퍼스

```text
14 applications, 146 candidates (취약 36 / 안전 110), 유병률 0.2466
SQLI          73 (취약 22)
REFLECTED_XSS 73 (취약 14)
```

feature 값은 전부 실제 HTTP 응답에서 추출됐고 합성하지 않았다. 라벨은 앱 동작을
`tools/corpus_target_site.py`에서 직접 작성했기 때문에 알려져 있다.

### 5.2 보정 품질 (leave-one-application-out out-of-fold)

```text
                    Brier    ECE
보정 모델           0.1134   0.1146
휴리스틱            0.2150   0.2862
항상 base rate      0.1858     —
```

### 5.3 Ranking 지표

```text
Recall@K          K=1     K=3     K=5     K=10
  B 무작위        0.101   0.303   0.505   0.903
  C reflection    0.122   0.359   0.586   0.928
  D 휴리스틱      0.253   0.631   0.917   1.000
  Proposed        0.405   0.869   0.946   1.000

Precision@K       K=1     K=3     K=5     K=10
  B 무작위        0.247   0.247   0.247   0.247
  C reflection    0.294   0.288   0.285   0.255
  D 휴리스틱      0.607   0.512   0.457   0.279
  Proposed        0.929   0.714   0.471   0.279

MAP@K             K=1     K=3     K=5     K=10
  B 무작위        0.247   0.212   0.274   0.384
  C reflection    0.294   0.254   0.330   0.434
  D 휴리스틱      0.607   0.521   0.649   0.692
  Proposed        0.929   0.845   0.871   0.894

NDCG@K            K=1     K=3     K=5     K=10
  B 무작위        0.247   0.287   0.387   0.559
  C reflection    0.294   0.340   0.452   0.603
  D 휴리스틱      0.607   0.621   0.761   0.804
  Proposed        0.929   0.884   0.911   0.939
```

Baseline A(전수 검증)는 정의상 recall 1.00, 비용 657 요청 / candidate 146개.

**읽는 법:** 차이가 작은 K에서 가장 크다. Precision@1은 0.607 → 0.929인데
Precision@5는 0.457 → 0.471로 거의 같다. **예산이 빠듯할수록 이득이 크다** —
검증 예산이 제약이라는 이 과제의 전제와 맞물린다.

**주의:** K=10은 포화 구간이다. 앱당 candidate가 8~14개뿐이라 대부분을
포함한다. 이 코퍼스에서는 K=1, 3이 정보량 있는 구간이다.

### 5.4 Held-out 성능 (학습에 쓰이지 않은 12개 앱, 앱당 예산 20 요청)

```text
구성                        recall        검증 후보  요청
휴리스틱 prior, 보장 없음   18/33 = 0.55        56    216
보정 모델, 보장 없음        27/33 = 0.82        50    216
보정 모델 + conformal       31/33 = 0.94        35    174
```

**더 적게 검증하면서 더 많이 찾는다.** 후보 −37%, 요청 −19%, recall 0.55 →
0.94. 실측 recall 0.94가 인증 목표 0.90을 만족한다(12개 표본 1회 관측이므로
보장의 검증이 아니라 위반이 없었다는 관찰).

### 5.5 Ablation — 생성 모델 대 판별 모델

```text
                 Brier    ECE      Rec@1   Rec@3   MAP@5   NDCG@5
NB-LLR           0.1837   0.1954   0.280   0.625   0.663   0.765
로지스틱          0.1134   0.1146   0.405   0.869   0.871   0.911
```

NB-LLR의 Brier는 상수 예측기(0.1858)와 사실상 같다. **확률로는 쓸 수 없는데
순위는 무작위(Rec@3 = 0.303)보다 두 배 이상 낫다.** 순위 지표만 봤다면
"쓸 만하다"고 결론냈을 것이다. 예산 배분은 기대 효용을 더해야 하므로 보정된
확률이 필요하다는 ADR-022의 독립적 증거다.

### 5.6 근사 보장 실측

이론 하한은 `½(1−1/e) ≈ 0.316`이지만, 소규모 인스턴스에서 전수 탐색 최적해와
비교한 실측 평균은 **0.95 이상**이다. 보장은 느슨하고 실제 성능은 훨씬 좋다.

---

## 6. 실행과 검증 명령어

모두 저장소 루트에서 실행한다. `PYTHONPATH=src`가 필요하다(편집 가능 설치가
오래된 체크아웃을 가릴 수 있음).

### 6.1 전체 검증

```bash
PYTHONPATH=src python -B -m unittest discover -s tests/unit -t .
```

기대: `Ran 621 tests ... OK`

```bash
python tools/check_format.py && python tools/check_lint.py && PYTHONPATH=src python tools/check_types.py && git diff --check
```

### 6.2 코퍼스 수집 · 학습 · 보정 (전 과정 재현)

```bash
PYTHONPATH=src python tools/build_corpus.py --applications 14
```

출력에 코퍼스 규모, 학습된 가중치, Brier/ECE 비교, conformal 임계값이 전부
나온다. **시드에서 바이트 단위로 재현된다** — 두 번 돌려 `diff`하면 동일하다.

산출물은 `data/corpus/`:

```text
corpus.jsonl              146개 라벨 샘플 (JSON Lines, 정규 순서)
ground-truth/app00..13    앱별 ground truth
model.json                family별 학습된 모델
calibration-report.json   Brier/ECE + reliability bins + baseline 비교
conformal.json            보정된 recall 임계값
ranking-report.json       ranking 지표 비교표
```

### 6.3 Ranking 비교표 (§5.3 재현)

```bash
PYTHONPATH=src python tools/evaluate_ranking.py --corpus data/corpus/corpus.jsonl
```

bug-level 집계로 다시 보려면:

```bash
PYTHONPATH=src python tools/evaluate_ranking.py --bug-level
```

### 6.4 Held-out 성능 (§5.4 재현)

```bash
PYTHONPATH=src python tools/evaluate_heldout.py --budget 20
```

### 6.5 실제 결정 실행 (스크린샷용)

로컬 타겟을 띄우고:

```bash
PYTHONPATH=src python tools/corpus_target_site.py
```

다른 터미널에서 — 휴리스틱 prior:

```bash
PYTHONPATH=src python -m vulnspider decide --url http://127.0.0.1:PORT/ --budget 20 -o decision-prior.json
```

학습 모델 + conformal 보장:

```bash
PYTHONPATH=src python -m vulnspider decide --url http://127.0.0.1:PORT/ --budget 20 --model data/corpus/model.json --conformal data/corpus/conformal.json -o decision-fitted.json
```

출력 예:

```text
vulnspider: decided 3 of 10 candidates (12/20 requests, expected findings 1.85)
vulnspider: decision report: decision-fitted.json
```

`decision-*.json`에 검증 순서, 각 후보의 확률·비용·severity, 예산 사용량,
보장 정보(`threshold`, `conformal_set_size`, `budget_covers_conformal_set`)가
들어 있다.

### 6.6 CLI 전체

```bash
PYTHONPATH=src python -m vulnspider --help
PYTHONPATH=src python -m vulnspider decide --help
PYTHONPATH=src python -m vulnspider corpus --help
```

```text
decide            예산 내에서 검증할 후보를 결정
corpus collect    한 앱을 실행해 라벨 샘플 수집
corpus fit        family별 보정 모델 학습
corpus calibrate  conformal recall 임계값 보정
```

`analyze`와 `-u`는 **변경되지 않았다.**

---

## 7. 명시적 한계

논문에서 먼저 밝히고 시작한다.

- **애플리케이션이 합성이다.** DVWA/WebGoat/Juice Shop이 아니다. 위 수치를
  실제 웹 애플리케이션 성능으로 일반화하면 안 된다. 수집기는 이미 임의의 승인된
  타겟에 대해 동작하므로 확장에 코드 변경은 불필요하다.
- **XSS는 원리적으로 분리 불가능하다.** `xss_raw`와 `xss_escaped`가 모두
  `marker_reflected = 1`을 만든다. 34개 반사 중 실제 취약 14개 — **20개는 어떤
  알고리즘으로도 못 거르는 오탐**이다. `safe_html_encoding_detected`가 필요하다.
- **cost와 severity는 정책이지 측정값이 아니다.**
- **conformal exchangeability**가 앱 간에 약하다.
- **관측된 0과 미관측**이 점수상 구분되지 않는다.

---

## 8. 파일 지도

```text
src/vulnspider/
  scoring/calibration.py   Layer 1  베이지안 로지스틱 + NB-LLR
  decision/
    cost.py                검증 비용 / severity 정책
    candidate.py           결정 단위 (selection 계약의 유일한 진입점)
    greedy.py              Layer 2a 예산 제약 submodular
    voi.py                 Layer 2b 정보 이득 (휴면, ADR-026)
    conformal.py           Layer 3  recall 보장
    policy.py              explore/cut/commit 오케스트레이션
  corpus/
    ground_truth.py        EVALUATION_PROTOCOL 3의 키와 저장소
    collection.py          실행 결과 → 라벨 샘플 조인
    fitting.py             학습 · out-of-fold · 보정 품질
  evaluation/
    metrics.py             Recall/Precision/MAP/NDCG (순수, 동점 기대값)
    baselines.py           Baseline A/B/C/D + bug-level 집계
  cli_decision.py          decide / corpus 명령

tools/
  corpus_target_site.py    라벨 loopback 애플리케이션 생성기
  build_corpus.py          수집 → 학습 → 보정 전 과정
  evaluate_ranking.py      ranking 비교표
  evaluate_heldout.py      미학습 앱 성능

docs/
  DECISION_LOG.md          ADR-021~026
  EVALUATION_PROTOCOL.md   6-A 판정 규칙, 8-B/8-C 측정 결과, 7.1 ablation
  exec-plans/completed/    3단계 실행 계획과 결정 기록
```
