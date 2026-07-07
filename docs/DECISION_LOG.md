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

**Status:** Accepted

**Decision:** v0.1 기본 selection은 vulnerability type별 Top-K다.

**Reason:** SQLi score와 XSS score가 동일 calibration이라고 가정하지 않는다.

---

## ADR-009 — Docs as system of record

**Status:** Accepted

**Decision:** `AGENTS.md`는 짧은 지도이며 세부 설계는 `docs/`에 둔다.

**Reason:** 거대한 단일 instruction file의 context 낭비와 stale rule 문제를 피한다.

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
