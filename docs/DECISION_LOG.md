# Decision Log

이 문서는 에이전트와 팀원이 반복해서 같은 설계를 재논의하지 않도록 결정 사항을 기록한다.

---

## ADR-001 — InputPoint as atomic observation unit

**Status:** Accepted

**Decision:** FeatureVector는 Endpoint 전체가 아니라 InputPoint에 귀속한다.

**Reason:** 동일 endpoint의 여러 parameter가 서로 다른 응답 신호를 만들 수 있으며, endpoint 단위 feature는 attribution을 오염시킨다.

---

## ADR-002 — Candidate = InputPoint x VulnerabilityType

**Status:** Accepted

**Decision:** 동일 InputPoint에 SQLi/XSS Candidate가 독립적으로 존재할 수 있다.

**Reason:** 취약점 유형별 feature와 score 의미가 다르다.

---

## ADR-003 — Separate RankScore from VerificationConfidence

**Status:** Accepted

**Decision:** RankScore는 후보 우선순위 전용이며 취약 확률로 해석하지 않는다.

**Reason:** 높은 우선순위가 높은 최종 확신도를 의미하지 않는다.

---

## ADR-004 — One-at-a-time Probe

**Status:** Accepted

**Decision:** 기본 Probe는 target InputPoint 하나만 변경한다.

**Reason:** response change attribution 확보.

---

## ADR-005 — Legacy crawler via adapter

**Status:** Historical — Accepted for v0.1; Superseded for the v0.2 primary
path by ADR-012 and ADR-013

**Decision:** 기존 WHSPIDER를 즉시 폐기하거나 본체를 대규모 수정하지 않는다. 먼저 audit 후 adapter로 연결한다.

**Reason:** 검증된 crawling logic은 활용하되 page-centric schema와 old LLM/RAG coupling은 새 시스템으로 전파하지 않는다.

---

## ADR-006 — LLM excluded from v0.1

**Status:** Accepted

**Decision:** 첫 프로토타입에는 LLM payload mutation을 넣지 않는다.

**Reason:** ranking 연구 가설을 독립적으로 검증하고 재현성을 확보한다.

---

## ADR-007 — BAC deferred and separately modeled

**Status:** Accepted

**Decision:** BAC는 v0.1에서 제외하고 향후 AccessCandidate 관계 모델로 다룬다.

**Reason:** SQLi/XSS의 단일 InputPoint injection 모델과 권한 관계 문제는 구조적으로 다르다.

---

## ADR-008 — Type-specific Top-K

**Status:** Superseded by ADR-010

**Decision:** v0.1 기본 selection은 vulnerability type별 Top-K다.

**Reason:** SQLi score와 XSS score가 동일 calibration이라고 가정하지 않는다.

---

## ADR-009 — Docs as system of record

**Status:** Accepted

**Decision:** `AGENTS.md`는 짧은 지도이며 세부 설계는 `docs/`에 둔다.

**Reason:** 거대한 단일 instruction file의 context 낭비와 stale rule 문제를 피한다.

---

## ADR-010 — Cross-type Top-K uses explicit selection priority

**Status:** Accepted

**Decision:** SQLi와 Reflected XSS 결과를 하나의 global Top-K로 선택할 때
raw RankScore를 직접 비교하지 않는다. 각 결과의 exact scorer maximum으로
raw score를 나눈 `selection_priority`를 사용하고 candidate id로 동률을
결정한다. raw RankScore는 그대로 보존한다. 이 결정은 ADR-008의
type-specific-only 기본 selection을 05D CLI에 대해 대체한다.

**Reason:** 현재 SQLi 범위는 0–75, Reflected XSS 범위는 0–45이므로 raw
값의 global 비교는 유형별 scale bias를 만든다. `selection_priority`는
확률이나 Confidence가 아니라 selection 전용 비교 key다.

---

## ADR-011 — HTML dashboard report added to v0.1 scope

**Status:** Accepted

**Decision:** v0.1은 기존 JSON 리포트에 더해, 동일한 검증된
`SelectionOutcome`과 실제로 실행된 baseline/probe 요청·응답으로부터
정적 HTML 대시보드 리포트를 생성할 수 있다 (`vulnspider analyze
--html-output`). 이는 `AGENTS.md`, `docs/PROTOTYPE_V0_1.md`,
`docs/ARCHITECTURE.md`가 명시하던 "dashboard is out of scope"를
대체한다.

**Reason:** 사용자가 CLI JSON 출력과 별도로 사람이 브라우저에서 바로
검토할 수 있는 대시보드 리포트를 명시적으로 요청했다. `PLANS.md`의
스코프 확장 절차(문서 갱신 + ADR + exec-plan)를 따라 의도적으로 범위를
넓힌다.

**Constraints (다른 ADR/규칙과의 충돌 방지):**

- `reporting`은 점수를 재계산하지 않는다(§ARCHITECTURE.md 6). HTML
  리포트는 JSON 리포트와 동일한 `SelectionOutcome`/`ScoreEvidence`만
  사용한다.
- `RankScore`/`selection_priority`는 여전히 vulnerability probability나
  confidence가 아니다(규칙 5-6, ADR-010). HTML 리포트는 "priority"/"rank
  score" 용어만 사용하고 "confidence"/"probability"/"confirmed"를 쓰지
  않는다.
- Focused/multi-payload verification은 계속 out-of-scope다
  (ARCHITECTURE.md §2.2). HTML 리포트의 "Executed requests" 절은 v0.1이
  실제로 보낸 baseline 1건 + probe 1건만 표시하며, 존재하지 않는 다건
  확인용 payload를 만들어 보여주지 않는다.
- BAC/IDOR 후보는 여전히 생성하지 않는다(ADR-007). 대시보드는 scoring이
  실제로 만드는 SQLI/REFLECTED_XSS만 렌더링한다.

**Alternatives considered:** 스코프를 바꾸지 않고 문서와 어긋난 채로
코드만 추가(reject — CODE_REVIEW.md 1번 체크리스트와 충돌); 별도
저장소(vulnspider 목업)에서만 진행(reject — 사용자가 이 저장소에 명시적
요청).

**Consequences:** `AGENTS.md`, `docs/PROTOTYPE_V0_1.md`,
`docs/ARCHITECTURE.md`의 out-of-scope 목록에서 "dashboard"를 제거하고
in-scope Output에 추가해야 한다. `pipeline.AnalysisResult`가
`ProbePlan`/`ResponseSnapshot`을 리포팅을 위해 보존하도록 확장된다
(순수 추가, 기존 필드/시그니처는 유지).

---

## ADR-012 — Native crawler is the v0.2 primary discovery path

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** v0.2의 주 실행 경로는 target URL에서 시작하는 native static
crawler를 사용한다. static crawler가 canonical domain model을 직접
생성하며, 이후 dynamic/browser crawler prototype도 동일 contract에
연결한다.

**Reason:** legacy record 입력은 실시간 scope, redirect, request budget,
hidden input, raw query provenance를 완전하게 보장할 수 없다. v0.2의
discovery 책임과 안전 경계를 명시적인 producer가 소유해야 한다.

**Consequences:** static crawler를 먼저 구현하고 contract와 안전 제한을
검증한 뒤 dynamic crawler를 추가한다. 이 결정은 crawler가 구현됐다는
뜻이 아니며 현재 상태는 **Planned for v0.2**다.

---

## ADR-013 — LegacyCrawlerAdapter is compatibility-only in v0.2

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** `LegacyCrawlerAdapter`는 삭제하지 않지만 v0.2 primary
discovery path에서는 사용하지 않는다. legacy 입력 변환과 regression
비교에만 유지한다.

**Reason:** v0.1 재현성과 과거 데이터 호환은 보존해야 하지만, legacy
schema의 불완전한 provenance를 native discovery contract의 기준으로
삼을 수 없다.

**Consequences:** ADR-005는 v0.1의 Historical 결정으로 남는다. native
crawler 기능을 adapter 내부에 추가하지 않으며 호환 경로 변경은 stable
identity와 provenance를 보존하거나 명시적으로 versioning한다.

---

## ADR-014 — BAC is a separate observation and scoring family

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** BAC를 v0.2 범위에 포함하되 SQLi/XSS payload family에
끼워 넣지 않는다. 역할, 세션, 객체, 접근 관계를 표현하는 별도 observation,
feature, scoring family로 설계한다.

**Reason:** BAC는 단일 InputPoint mutation보다 두 개 이상의 권한
context와 객체 관계가 핵심이며 attribution과 안전 제한이 다르다.

**Consequences:** BAC 후보 모델과 bounded fixture 정책은 구현 전에
contract review가 필요하다. 자동 계정 생성, 권한 변경, destructive
verification은 허용하지 않는다.

---

## ADR-015 — LLM payloads require deterministic validator approval

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** GPT/Gemini를 포함한 모든 LLM 출력은 실행 제안일 뿐이다.
모델이 만든 payload는 deterministic `PayloadValidator`가 target binding,
scope, family, encoding, mutation limit, safety policy를 승인하기 전에는
어떤 transport에도 전달하지 않는다.

**Reason:** provider 응답은 비결정적이고 신뢰할 수 없는 입력이다. 안전과
실행 가능성을 prompt 준수에 의존할 수 없다.

**Consequences:** validator rejection도 실험 결과로 기록한다. LLM은 최종
취약점 판단자가 아니며 focused verification만 구조화된 실행 evidence를
생성할 수 있다.

---

## ADR-016 — RankScore and VerificationConfidence remain independent

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** ADR-003을 v0.2에서도 유지한다. `RankScore`와
`selection_priority`는 검증 순서를 위한 값이고,
`VerificationConfidence`는 focused verification의
`VerificationEvidence`에 deterministic rule을 적용한 별도 값이다.

**Reason:** 높은 ranking 신호를 검증 성공으로 해석하면 평가 leakage와
거짓 확신이 생긴다.

**Consequences:** confidence 계산은 ranking score를 단순 가산하지 않는다.
Confidence rule은 팀 전체가 리뷰하고 구현 owner는 석현이다.

---

## ADR-017 — v0.2 uses canonical cross-owner contracts

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** owner 경계를 넘는 데이터는 versioned canonical contract로
전달한다. 초기 **Proposed Contract**는 `CanonicalDiscoveryResult`,
`RankedCandidateContext`, `VerificationResult`다.

**Reason:** consumer가 upstream 객체, ID, score, evidence, provenance를
재구성하면 attribution과 재현성이 깨진다.

**Consequences:** producer가 construction과 validation을 소유하고,
consumer는 forbidden reconstruction 규칙을 지킨다. contract 변경은
영향받는 producer와 consumer 리뷰가 필요하다.

---

## ADR-018 — Protected base branch and PR-only collaboration

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** 과도기 base는 `prototype/v0.1`이며 main 승격 후에는 `main`을
공식 base로 사용한다. base branch 직접 commit을 금지하고 short-lived
branch와 PR을 사용한다.

**Reason:** 세 owner가 병렬 작업할 때 직접 commit과 암묵적 contract
변경은 통합 위험과 책임 불명을 키운다.

**Consequences:** 기본 merge 방식은 squash다. 기존 commit 보존이 중요한
integration PR은 review 후 merge commit을 사용할 수 있다. contract
변경은 영향 owner 리뷰가 필요하고 network scope 또는 payload 실행
변경은 2인 리뷰를 권장한다.

---

## ADR-019 — Simple CLI defaults to bounded Dynamic discovery

**Status:** Accepted

**Date:** 2026-08-04

**Decision:** `vulnspider -u URL` is a thin adapter over the existing combined
Static + Dynamic + merge + Light Probe pipeline. It uses the reviewed Dynamic
budget defaults except for a simple-adapter maximum link depth of two, allows
only exact same-origin GET URLs extracted from rendered anchors for
crawler-initiated navigation, and allows same-origin GET script/style resources
needed to render those anchors. The advanced
`vulnspider analyze` interface and its exact-grant defaults remain unchanged.

**Reason:** The public one-line command should discover JavaScript-rendered GET
surfaces without requiring users to predict those URLs, while page code must
not gain general navigation or active-transport authority.

**Consequences:** Fetch/XHR, WebSocket, EventSource, POST, form submission,
popup, child-frame documents, cross-origin, and different-port traffic remain
blocked unless an existing explicit advanced grant category permits it. JSON
publication uses same-directory temporary output plus atomic replacement, and
failed or degraded simple scans do not publish a new result.

---

## ADR-020 — One FeatureVector per InputPoint across its probe-ready contexts

**Status:** Accepted

**Date:** 2026-08-10

**Decision:** When one `InputPoint` owns several probe-ready
`InputPointRequestContext` objects, every executed probe run still runs, but
their per-run `FeatureVector` objects are combined into exactly one
`FeatureVector` for that `InputPoint` before candidate generation. Each feature
is combined existentially: the largest observed value wins, ties resolve by
ascending probe-run id, and a feature stays unobserved when no run observed it.
`probe_run_ids` lists every contributing `ResponsePair`, and `details` records
the aggregation version, the participating runs, the run that supplied the
retained value, each run's value, and the unobserved-run count. Aggregation
policy version: `input-point-existential-v1`.

**Context:** `docs/DOMAIN_MODEL.md` §9 already defines a `FeatureVector` as one
`InputPoint` plus the probe runs that produced it, and ADR-002 keeps
`InputPoint x VulnerabilityType` as the ranking atom. Native Static single-seed
crawls happened to bind one context per `InputPoint`, so a per-run vector was
indistinguishable from a per-InputPoint vector. Native Dynamic and Combined
discovery observe the same endpoint parameter through several request
templates, so per-run vectors produced several `ScoringResult` objects sharing
one candidate id. `select_top_k` then collapsed them silently, the same
candidate could appear in both `selected` and `unrankable`, and the reported
summary counted observations instead of candidates.

**Alternatives:** Probe only one deterministically chosen context per
`InputPoint`. Rejected because it discards the observation that discriminates
between contexts, for example a numeric baseline versus an already-broken one.
Fixing only the selection accounting was also rejected because it leaves the
ranking atom split across several feature vectors.

**Consequences:** `AnalysisResult.feature_vectors` holds one vector per
observed `InputPoint`, and several `ProbeObservation` records can reference the
same `feature_vector_id`. Reporting joins by `probe_run_ids` membership instead
of assuming one run per vector. A combined feature value can come from a
different probe run than its sibling feature, so a combined vector is not the
replay of one request pair; `selected_probe_run_id` keeps that explainable.
Single-context analyses are unchanged and keep their previous vector ids.
## ADR-021 — BAC joins the combined Top-K and selection produces the mutation handoff

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** SQLi/Reflected XSS injection 후보와 BAC `AccessCandidate`를 하나의
combined Top-K로 합칠 때 ADR-010의 `selection_priority`(raw_rank_score / exact
scorer maximum)를 그대로 사용한다. BAC의 exact scorer maximum은
`ACCESS_MAX_RANK_SCORE`(=75.0, `access-control-weighted-v1`)이고 candidate id로
동률을 결정한다. Scorer는 기존 것을 재사용한다(`scoring.engine`의 SQLi/XSS,
`access.scoring`의 BAC). `selection.combined.select_combined_top_k()`는 이미
검증된 두 category 선택 결과만 병합하며 어떤 점수도 재계산하지 않는다.
`selection` 모듈은 이 combined Top-K를 mutation 모듈(LLM-assisted Payload
Mutation, owner 석현)로 넘기기 위한 handoff `RankedCandidateContext`
(ADR-017, `docs/TEAM_INTERFACES_V0_2.md` §2)를 `selection.handoff`에서 생성한다.

**Reason:** 검증 우선순위를 세 family에 걸쳐 하나의 순서로 제시하고 mutation
모듈에 단일 handoff로 전달하기 위함이다. `docs/TEAM_INTERFACES_V0_2.md` §2가
열어둔 "BAC가 SQLi/XSS global Top-K에 참여하는지" open decision을 이 ADR로
확정한다. 이는 ADR-010을 BAC family(ADR-014)까지 확장한다.

**Consequences:**

- `selection_priority`는 여전히 selection 전용 비교 key이며 확률이나
  Confidence가 아니다(ADR-010, ADR-016). 세 family의 raw scale이 다르므로 raw
  score를 직접 비교하지 않는다.
- handoff는 selection이 authoritative하게 소유한 필드만 채운다. scope/verification
  envelope(`target_scope_id`, `allowed_verification_policy`)는 selection이 소유하지
  않으므로 fabricate하지 않고 각 owner가 downstream에서 부여한다
  (`docs/TEAM_INTERFACES_V0_2.md` §2 forbidden reconstruction 준수).
- BAC observation pipeline(planner/executor)은 이 결정 범위 밖이며
  discovery/observation owner가 소유한다. `feat/selection-top-k`는 재사용한 BAC
  scorer·features·within-family selector만 가져온다.
- `docs/TEAM_INTERFACES_V0_2.md` §2 "BAC ranking and global selection boundary"와
  "Open contract decisions"의 해당 항목은 이 ADR을 참조하도록 갱신한다.

---

## ADR-022 — Calibrated probability replaces raw/max as the comparison key

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** 후보 비교의 기준을 `raw_rank_score / exact_scorer_maximum`에서
보정된 확률 `P(vulnerable | observed evidence)`로 옮긴다. 확률은
`scoring/calibration.py`의 베이지안 로지스틱 회귀가 생성한다. 기존 휴리스틱
가중치(`SQLI_TERMS`, `XSS_TERMS`, `ACCESS_TERMS`)는 폐기하지 않고 logit
공간으로 rescale하여 Gaussian prior의 평균으로 사용한다.

이 결정은 ADR-003과 ADR-016의 "RankScore를 취약 확률로 해석하지 않는다"를
**decision layer 한정으로** 대체한다. `RankScore`, `selection_priority`,
`select_top_k()`, `select_combined_top_k()`의 의미와 동작은 바뀌지 않는다.

**Reason:** ADR-010과 ADR-021은 SQLi(0..75), Reflected XSS(0..45),
BAC(0..75)를 각자의 최댓값으로 나눠 비교했다. 이 몫이 왜 family 간에
비교 가능한지에 대한 근거는 없으며 ADR-010 본문도 "확률이 아니라 selection
전용 key"라고만 명시했다. 예산 배분은 서로 다른 family의 기대 효용을 실제로
더해야 하므로, 임의 스케일이 아닌 공통 단위가 필요하다. 확률은 그 단위다.

**Alternatives considered:** 가중치 Grid Search(reject — 탐색 대상이 가중치일
뿐이고 feature가 적어 이득이 없다); Learning-to-Rank(reject — 현재 feature
수와 코퍼스 규모에서 과적합하며, 비교군으로만 남긴다); 현행 유지(reject —
family 간 비교를 정당화할 수 없다).

**Consequences:**

- 학습 데이터가 없으면 `CalibratedScorer.from_prior()`의 `logit_mean`은
  `logit(base_rate) + RankScore / prior_scale`로 휴리스틱 순서를 정확히
  재현한다. 코퍼스 확보 전에도 안전하게 채택할 수 있다.
- `probability`는 `logit_mean`의 단조 함수가 아니다. weight posterior를
  적분하므로, 코퍼스가 정밀하게 고정한 가중치에 기댄 점수는 damping을 덜
  받고 거의 관측되지 않은 가중치에 기댄 점수는 base rate 쪽으로 당겨진다.
  휴리스틱 순서가 필요한 소비자는 `logit_mean`을 읽는다.
- ADR-016의 취지는 유지된다. 이 확률은 **검증 전 우선순위 확률**이고
  `VerificationConfidence`는 focused verification 이후의 별개 값이다. 둘을
  합산하거나 서로 대체하지 않는다.
- missing feature는 logit 합에서 제외된다. 관측된 `0.0`과 미관측이 점수상
  구분되지 않는다는 한계는 `CalibrationEvidence.observed`와
  `observed_feature_count`로 노출하고 `FEATURE_SCHEMA.md` §9에 기록한다.

---

## ADR-023 — Budget-constrained sequential selection is the decision layer

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** 고정 Top-K 대신 요청 예산 `B`를 입력으로 받는 결정 계층을
`vulnspider.decision`에 둔다. 세 부분으로 구성한다.

1. 명시적 cost/severity 정책(`decision/cost.py`).
2. 예산 제약 하 submodular 최대화(`decision/greedy.py`). 효용은
   `U(S) = Σ_families Σ_j discount^(j-1) · P · severity`이며, 같은
   `redundancy_key`(동일 서버 코드 경로) 내에서 수확 체감을 적용한다.
   density greedy와 "가장 좋은 단일 후보" 중 나은 쪽을 취해
   `½(1 − 1/e)` 근사를 보장한다. `discount = 1.0`이면 modular가 되고 같은
   절차가 `½` 근사다.
3. Value of Information 기반 순차 probe 선택(`decision/voi.py`).
   `EIG / cost`가 가장 큰 probe부터 실행하고 결과로 posterior를 갱신한다.

**Reason:** 졸업과제의 주장은 "적은 요청으로 검증 가치가 높은 후보를 먼저
검증한다"이고 `EVALUATION_PROTOCOL.md` §6의 주 지표도 request budget 대비
누적 발견이다. 그런데 알고리즘은 budget을 입력으로 받지 않았고 cost 모델도
없었다. 또한 파이프라인이 one-shot이라 첫 probe 결과가 다음 probe를 바꾸지
못해 "선택검증"이 선택에서 멈춰 있었다. 근사 보장이 있는 목적함수 최대화로
바꾸면 "왜 이 순서인가"에 정리로 답할 수 있으며, 이는 rule-based 순위가 줄
수 없는 것이다.

**Alternatives considered:** modular 효용 + 정확한 knapsack DP(reject — 같은
코드 경로의 중복성을 모델링하지 못해 템플릿 라우트 하나가 예산을 독점한다);
MDP/강화학습(reject — 필요한 데이터 규모가 졸업과제 범위를 넘는다);
Thompson Sampling(defer — 온라인 탐색-활용은 후속 작업으로 남긴다).

**Consequences:**

- `decision`은 `selection`의 검증된 출력만 소비하고 어떤 점수도 재계산하지
  않는다(ADR-017, ADR-021). `RankedCandidateContext`가 유일한 진입점이다.
- `decision/policy.py`는 I/O를 하지 않는다. probe 결과는 주입된
  `ProbeOutcomeSource`로 들어오며 transport는 인터페이스 뒤에 남는다.
- cost와 severity 기본값은 측정값이 아니라 문서화된 정책이다. 평가 harness가
  실측 요청 수로 대체해야 한다.
- 예산은 오늘의 고정 Top-K 대비 요청 수를 늘리지 않는다. 안전 경계는 변하지
  않는다.

---

## ADR-024 — Conformal risk control determines the selected set size

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** 선택 집합의 크기를 사람이 고르는 `k` 대신 conformal risk
control로 정한다. 보정 그룹에서 `R̂_n(λ) ≤ α − (1 − α)/n`을 만족하는 가장 큰
확률 임계값 `λ̂`을 선택하고, 그 임계값 이상인 후보를 모두 취한다. 보장은
`E[1 − Recall] ≤ α`다. 손실은 `1 − Recall`이고 positive가 없는 그룹의 손실은
0으로 정의한다. 그룹은 application 단위이며 이는 `EVALUATION_PROTOCOL.md`
§4의 leakage 방지 단위와 같다.

**Reason:** `k`는 지금까지 근거 없는 하이퍼파라미터였고 얼마나 많은 실제
positive가 잘려나가는지와 연결되어 있지 않았다. 과제 제목의 "선택검증"에
대응하려면 "몇 개를 뽑는가"가 알고리즘 안에서 답해져야 한다.

**Consequences:**

- 보장은 `α ≥ 1/(n+1)`일 때만 달성 가능하다. recall 90% 보장에는 보정
  application이 최소 9개 필요하다. 미달이면
  `ConformalThreshold.guarantee_attainable`이 `False`가 되고 임계값은 0.0으로
  떨어져 전부 선택한다. 보장되지 않은 수치를 보장된 것처럼 반환하지 않는다.
- exchangeability 가정은 웹 애플리케이션 간에 약하다. leave-one-app-out 보정과
  실측 위반율 보고를 필수로 하며, 명목 대비 실제 coverage 차이 자체를 결과로
  기록한다. `EVALUATION_PROTOCOL.md` §10에 명시한다.
- 예산이 보장 집합을 감당하지 못할 수 있다.
  `DecisionOutcome.budget_covers_conformal_set`이 이를 보고하며, 이 경우
  보장은 성립하지 않는다.

---

## ADR-025 — Decision layer reaches the CLI through new commands and a corpus

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** 결정 계층을 CLI에서 도달 가능하게 만들되, frozen v0.1 명령 표면은
건드리지 않는다. `analyze`, `-u/--url` simple mode, 그리고 그 플래그들은 그대로
두고 **새 subcommand만 추가**한다.

```text
vulnspider decide            --url ... --budget N [--model M] [--conformal C] -o R
vulnspider corpus collect    --url ... --application-id A --ground-truth G -o C
vulnspider corpus fit        --corpus C -o M [--report Q]
vulnspider corpus calibrate  --corpus C --target-recall R -o T
```

새 패키지 `vulnspider.corpus`가 라벨 코퍼스를 소유한다. Ground truth key는
`docs/EVALUATION_PROTOCOL.md` §3의 6-튜플이며, 코퍼스는 authoritative
`Endpoint`/`InputPoint`에서 키를 만든다. 리포트나 표시 문자열에서 복원하지
않는다.

코퍼스 수집원은 `tools/corpus_target_site.py`가 생성하는 loopback 전용 라벨
애플리케이션이다. `AGENTS.md`의 안전 규칙이 허용하는 유일한 데이터 출처이며,
정답을 아는 이유는 동작을 이 파일에서 직접 작성했기 때문이다 — DVWA/WebGoat가
라벨 코퍼스로 쓰이는 것과 같은 근거다.

**Reason:** 결정 계층이 프로그램적으로만 도달 가능하면 실제로 쓸 수 없고,
Layer 1의 가중치와 Layer 3의 보장은 라벨 데이터 없이는 의미가 없다. 두 결핍은
같은 작업으로 해소된다.

**Alternatives considered:** `analyze`에 `--budget`/`--target-recall` 플래그
추가(reject — frozen 표면 변경이며 `analyze`의 계약이 "Top-K 리포트"라는 의미가
흐려진다); 인터넷 스캔으로 코퍼스 수집(reject — 안전 규칙 위반);
DVWA/WebGoat 컨테이너 자동 구동(defer — Docker 의존성과 사용자 환경 개입이
필요하므로 별도 결정 사항).

**Consequences:**

- 미라벨 후보는 negative가 아니라 **skip**이다. 없는 키는
  `GroundTruthStore.label_for()`가 `None`을 반환하고 수집기가 보고한다. 미라벨을
  안전으로 취급하면 precision이 조작되며, 이는 feature schema가 이미 금지한
  "missing은 관측된 0이 아니다"와 같은 오류다.
- Conformal 보정은 **leave-one-application-out out-of-fold 확률**로 수행한다.
  모델이 이미 라벨을 본 확률로 보정하면 보장이 낙관적으로 부풀려진다.
- `decide`는 Top-K가 아니라 전체 후보를 랭킹한 뒤 예산으로 자른다. 몇 개를
  검증할지는 결정 계층이 계산하는 값이지 입력받는 값이 아니므로 `--top-k`를
  받지 않는다.
- `redundancy_key`는 endpoint fingerprint다. 이는 ADR-023 시점의 한계
  (input point 참조를 기본값으로 사용)를 해소한다.
- 코퍼스 파일은 정규 순서로 기록한다. discovery 순회 순서가 실행마다
  달라지므로, 정렬하지 않으면 동일 `--seed`가 줄 순서만 다른 파일을 만들어
  §8의 재현성 요구를 무력화한다.
- 생성된 코퍼스 산출물(`data/corpus/`)은 저장소에 포함한다. 심사에서 수치의
  출처를 확인할 수 있어야 하고, 크기는 약 129KB로 부담되지 않는다.

---

## New Decision Template

```text
## ADR-XXX — Title

Status: Proposed | Accepted | Rejected | Superseded
Date:

Decision:

Context:

Alternatives:

Consequences:
```
