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

**Status:** Accepted

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
정적 HTML 대시보드 리포트를 생성할 수 있다 (`spiderman analyze
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
