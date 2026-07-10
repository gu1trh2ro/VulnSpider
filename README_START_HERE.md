# SPIDERMAN Prototype v0.1 — Start Here

## 1. 이 패키지의 목적

이 폴더는 Codex와 함께 첫 프로토타입을 만들기 위한 **agent-ready repository starter**다.

중요 문서:

```text
AGENTS.md
PLANS.md
CODE_REVIEW.md
docs/ARCHITECTURE.md
docs/DOMAIN_MODEL.md
docs/FEATURE_SCHEMA.md
docs/PROTOTYPE_V0_1.md
docs/EVALUATION_PROTOCOL.md
docs/AI_ENGINEERING_GUIDE.md
docs/DECISION_LOG.md
```

Codex prompt:

```text
prompts/01_LEGACY_AUDIT.md
prompts/02_REPOSITORY_SCAFFOLD.md
prompts/03_DOMAIN_MODEL.md
prompts/04_LEGACY_ADAPTER.md
prompts/05_PROBE_FEATURE_SCORING.md
prompts/06_INDEPENDENT_REVIEW.md
prompts/07_FIX_REVIEW_LOOP.md
```

---

## 2. 첫 작업 전 준비

새 Git repository를 만든다.

권장 구조:

```text
spiderman/
├─ AGENTS.md
├─ PLANS.md
├─ CODE_REVIEW.md
├─ docs/
├─ prompts/
├─ reference/
└─ ...
```

기존 WHSPIDER 코드는 다음에 둔다.

```text
reference/whspider_legacy/
```

처음에는 legacy를 수정하지 않는다.

---

## 3. 실제 실행 순서

### Step 1 — Audit only

Codex에:

```text
prompts/01_LEGACY_AUDIT.md
```

내용을 전달한다.

Audit 결과를 사람이 검토한다.

### Step 2 — Scaffold

```text
prompts/02_REPOSITORY_SCAFFOLD.md
```

### Step 3 — Domain model

```text
prompts/03_DOMAIN_MODEL.md
```

### Step 4 — Legacy adapter

```text
prompts/04_LEGACY_ADAPTER.md
```

### Step 5 — Probe/Feature/Scoring vertical slice

```text
prompts/05_PROBE_FEATURE_SCORING.md
```

### Step 6 — Independent review

새 Codex thread에서:

```text
prompts/06_INDEPENDENT_REVIEW.md
```

### Step 7 — Fix loop

리뷰 findings가 있으면:

```text
prompts/07_FIX_REVIEW_LOOP.md
```

---

## 4. 초보자에게 가장 중요한 규칙

1. 한 prompt에 프로젝트 전체를 맡기지 않는다.
2. 구현 전 plan을 시킨다.
3. "done when"을 쓴다.
4. 테스트 없이 완료를 믿지 않는다.
5. 같은 실수가 두 번 반복되면 문서/테스트/harness를 고친다.
6. 첫 프로토타입에는 LLM mutation과 BAC를 넣지 않는다.
7. 병렬 multi-agent는 repo가 안정된 뒤 도입한다.

---

## 5. Windows/Codex 설정

처음 설정은:

```text
docs/CODEX_SETUP.md
```

를 따른다.

---

## 6. v0.1 Top-K 분석 실행

현재 CLI는 live crawler를 실행하지 않는다. 기존
`LegacyCrawlerAdapter`가 받는 legacy crawl-record JSON 배열을 입력으로
사용하며, localhost/loopback의 허가된 테스트 대상만 Light Probe한다.

```powershell
spiderman analyze `
  --input legacy-records.json `
  --top-k 10 `
  --output result.json
```

출력은 raw RankScore, exact scorer maximum, cross-type
`selection_priority`, 그리고 ScoreEvidence를 구분해 보존한다. 이 값들은
취약 확률이나 최종 Confidence가 아니다.
