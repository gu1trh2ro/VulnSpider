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
budget defaults, allows only exact same-origin GET URLs extracted from rendered
anchors for crawler-initiated navigation, and allows same-origin GET
script/style resources needed to render those anchors. The advanced
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
