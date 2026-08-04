# HTML Dashboard Visual Refresh (charts + Korean copy)

## Goal

`--html-output`으로 생성되는 최종 HTML 대시보드를 (1) 차트 중심으로 더
시각적으로 읽히게 만들고, (2) 기본 설명 문구를 한국어로 바꾼다. 데이터
자체는 그대로 — 이미 검증된 `CombinedSelectionOutcome` / `SelectionOutcome`
과 실제로 전송된 요청 쌍만 사용한다.

## Non-Goals

- 새 점수·새 evidence·새 요청을 만들지 않는다. `reporting`은 여전히 렌더링만
  한다 (`docs/ARCHITECTURE.md` §6, ADR-011/ADR-012).
- 새 서드파티 의존성 없음. 차트는 표준 라이브러리로 생성하는 인라인 SVG/CSS
  이며 CDN·외부 스크립트·폰트를 불러오지 않는다 (단일 정적 파일 유지).
- JS 런타임 의존 없음. 상호작용이 필요한 부분은 순수 CSS/HTML(`<details>`)
  범위에서만.
- `selection_priority`를 confidence/probability/취약 확률/신뢰도로 표현하지
  않는다 (AGENTS.md 규칙 5-6, ADR-010). 한국어 문구에도 동일하게 적용한다.
- v0.1이 실제로 보내지 않은 다건 verification payload를 표시하지 않는다.
- JSON 리포트 스키마·CLI 인자·파이프라인은 건드리지 않는다.

## Context Read

- `AGENTS.md`, `PLANS.md`, `CODE_REVIEW.md`
- `docs/ARCHITECTURE.md` §6, `docs/PROTOTYPE_V0_1.md` §13/§14,
  `docs/DECISION_LOG.md` ADR-010/011/012
- `src/vulnspider/reporting/html_report.py`, `combined_report.py`,
  `json_report.py`, `__init__.py`
- `src/vulnspider/cli.py`
- `tests/unit/test_html_reporting.py`, `tests/unit/test_combined_reporting.py`
- `tests/integration/test_v01_smoke.py`, `tests/integration/test_bac_smoke.py`

## Current State

- CLI는 `write_combined_html_report()`(`combined_report.py`)를 쓰고,
  `combined_report`는 injection 카드/밴드 바/경고/푸터/스타일시트를
  `html_report`의 비공개 헬퍼에서 재사용한다.
- 현재 대시보드의 시각 요소는 stat 타일 5개, 밴드 pill 3개, 후보별 priority
  막대 1개뿐이다. 나머지는 전부 텍스트 목록/표.
- 모든 문구가 영어.
- 243개 테스트 통과 (`python -m unittest discover -s tests`).

## Proposed Changes

1. **`reporting/charts.py` (신규)** — 도메인 의존성이 없는 결정적 차트
   프리미티브. `html_report`/`combined_report` 양쪽에서 공유한다.
   - `escape_text()` (기존 `_esc`의 실체를 이쪽으로 이동)
   - `Slice`/`Bar` frozen dataclass
   - `donut_chart()` — `stroke-dasharray` 기반 인라인 SVG 도넛
   - `bar_chart()` — 가로 막대(라벨/값/비율/캡션)
   - `stacked_bar()` — 점수 구성용 누적 막대
   - `chart_card()`, `CHART_STYLE`
   - 모든 수치는 고정 소수점 포맷으로 직렬화 → 동일 입력 → 동일 문자열.
2. **`reporting/html_report.py`**
   - 차트 섹션 추가: 우선순위 구간 도넛, 유형별 후보 막대, 분석 파이프라인
     요약(funnel) 막대, 선정 후보 우선순위 비교 막대.
   - 후보 카드: 점수 구성 누적 막대, evidence별 기여도 미니 막대,
     baseline/probe 응답 크기·소요 시간 비교 막대 추가.
   - "리포트 읽는 법" 안내 섹션 추가(한국어).
   - 문구 한국어화. 도메인 고유명(SQL Injection / Reflected XSS /
     Broken Access Control)과 식별자는 영어 유지, 주요 섹션 제목은
     `한국어 + 작은 영문` 병기.
   - 스타일시트 확장 + `prefers-color-scheme: dark` 대응.
3. **`reporting/combined_report.py`** — 같은 차트/한국어 문구를 BAC 카드에도
   적용하고, 유형별 분포에 BAC를 포함.
4. **테스트** — 영어 UI 문자열을 단언하던 부분을 새 문구로 갱신하고,
   차트 결정성·escape·금칙어 불변식 테스트를 추가.
5. **문서** — `docs/PROTOTYPE_V0_1.md` §13에 표현 계층 규칙(차트는 기존
   수치의 재표현일 뿐, 한국어 문구에도 금칙어 규칙 적용) 추가.

## Interfaces / Data Changes

```text
reporting.charts (new module, presentation only)
  escape_text(value) -> str
  Slice(label, value, tone) / Bar(label, value_label, ratio, tone, caption)
  donut_chart(slices, *, center_value, center_caption) -> str
  bar_chart(bars) -> str
  stacked_bar(segments) -> str
  chart_card(title, body, *, subtitle="", english="") -> str
  CHART_STYLE: str
```

`build_html_report_context()` / `build_combined_html_report_context()`의 반환
키, JSON 리포트, CLI 인자, 파이프라인 타입은 변경 없음. 차트 집계는 렌더
시점에 기존 context 값에서 계산한다.

## Safety / Scope Impact

- 네트워크 동작 변경 없음. 새 요청 없음. 스코프 가드 변경 없음.
- 외부 리소스 요청 없음(차트가 인라인이므로 리포트를 열어도 아웃바운드
  트래픽이 발생하지 않는다).
- 기존 XSS 방어 유지: 차트 라벨/캡션도 전부 `escape_text()`를 통과시키고,
  색상은 tone 이름 → CSS 변수 화이트리스트 매핑으로만 결정한다(문자열
  직접 보간 금지).

## Test Plan

- unit `tests/unit/test_charts.py`: 도넛/막대/누적막대 결정성, 합계 0 처리,
  비율 clamp(0..1), 라벨 escape, 알 수 없는 tone의 안전한 폴백.
- unit `test_html_reporting.py`: 기존 불변식(결정성·escape·금칙어) 유지 +
  한국어 섹션/차트 마크업 존재, 한국어 금칙 표현(확률/신뢰도/확정) 부재.
- unit `test_combined_reporting.py`: BAC 카드도 동일.
- integration `test_v01_smoke.py`/`test_bac_smoke.py`: 새 문구로 갱신, 차트가
  실제 CLI 출력에 포함되는지 확인.
- negative: 후보 0건, 표시용 맵 미제공, 손상된 outcome → 기존 동작 유지.

## Acceptance Criteria

- [x] 대시보드에 도넛 1종 + 막대 차트 4종 이상이 렌더링된다.
      (도넛 1 + 유형별/파이프라인/우선순위 비교/근거/응답 비교 막대 5종)
- [x] 모든 차트가 인라인이며 외부 리소스를 참조하지 않는다.
- [x] 기본 설명 문구가 한국어다(도메인 고유명/식별자 제외).
- [x] "confidence"/"probability"/"confirmed" 및 한국어 대응 표현(확률/
      신뢰도/확정)이 출력에 없다.
- [x] 동일 입력 → 동일 HTML(결정성) 유지.
- [x] 모든 보간 텍스트가 이스케이프된다.
- [x] `python -m unittest discover -s tests`, `check_format.py`,
      `check_lint.py`, `check_types.py` 모두 통과.

## Progress Log

- 2026-08-04: 요청 접수. 현재 리포트/테스트/제약 확인(243 tests green),
  본 계획 작성.
- 2026-08-04: 구현 완료.
  - `reporting/charts.py` 신규: `escape_text`, `tone_color`, `clamp_ratio`,
    `Slice`/`Bar`/`Segment`, `donut_chart`, `bar_chart`, `stacked_bar`,
    `chart_card`, `CHART_STYLE`.
  - `html_report.py`: 차트 그리드(도넛/유형별/파이프라인) + 우선순위 비교
    카드 + 카드 내부 근거 막대·응답 비교 막대 + "리포트 읽는 법" 안내를
    추가하고, 문구를 한국어로 교체. `_wrap_document`/`_render_masthead`/
    `_compose_card`/`_section_heading`/`_render_guidance`/
    `_unrankable_notice`를 추출해 combined 쪽과 공유.
  - `combined_report.py`: 자체 header/stats/카드/근거/unrankable 렌더링을
    공유 헬퍼 호출로 대체(중복 ~120줄 제거). BAC를 유형별 차트에 포함.
  - 구현 중 실제로 고친 것: (1) `clamp_ratio`가 처음에 `math.isfinite`로
    inf까지 0.0으로 만들어 "값이 최대인 막대가 0폭이 되는" 잘못된 그래프를
    낼 수 있었음 → NaN만 0.0으로, inf는 1.0으로 clamp. (2) BAC 근거 막대가
    injection 쪽과 거의 같은 코드로 복제돼 있어 `_render_evidence_chart(...,
    default_tag=...)`로 통합.
  - 실제 검증: `demo_target_server.py`를 띄우고 `vulnspider analyze
    --input demo_records.json --top-k 6 --html-output`으로 리포트를 생성해
    브라우저에서 확인. 라이트/다크 두 테마, 1200px/546px 폭에서 가로
    스크롤 없음(`scrollWidth == clientWidth`), 도넛 중심 텍스트가 SVG
    중심과 정확히 일치, 차트 4카드·막대 52행·후보 6건 렌더링 확인.
    생성 결과에서 금칙어(영/한) 0건 확인.
  - 최종 검증: 261 tests passed(신규 `tests/unit/test_charts.py` 13개 포함),
    `check_format.py`/`check_lint.py`/`check_types.py` 모두 통과.
  - 커밋은 수행하지 않음(사용자가 명시적으로 요청할 때까지 보류).

## Decision Log

- Decision: 차트는 인라인 SVG/CSS로 직접 생성한다.
  Reason: `pyproject.toml`의 `dependencies = []`와 "단일 정적 HTML" 제약을
  유지하면서, 오프라인·에어갭 환경에서도 리포트가 그대로 열려야 한다.
- Decision: 차트 집계는 렌더 시점에 하고 context 스키마는 유지한다.
  Reason: `build_*_context()`는 공개 API이며, 표시용 집계 때문에 스키마를
  넓히면 JSON 리포트와의 대칭성이 흐려진다.
- Decision: 한국어 문구에도 금칙어 규칙을 그대로 적용한다(확률/신뢰도/확정).
  Reason: 규칙의 의도는 단어가 아니라 표현 자체(AGENTS.md 규칙 5-6).
- Decision: 취약점/점검 유형 이름(SQL Injection, Reflected XSS, Broken
  Access Control), 식별자, feature 이름, URL은 번역하지 않는다. 주요 섹션
  제목만 `한국어 + 작은 영문` 병기.
  Reason: JSON 리포트·docs·테스트가 같은 이름을 쓰고 있어야 대조가 된다.
- Decision: 새 ADR을 만들지 않는다.
  Reason: 아키텍처·스코프·데이터 흐름 변화가 없는 표현 계층 변경이며,
  ADR-011/ADR-012가 이미 정한 제약(재계산 금지, 실제 전송 요청만 표시,
  금칙어) 안에서 이뤄졌다. 대신 `docs/PROTOTYPE_V0_1.md` §13에 차트/언어
  규칙을 명시했다.

## Open Questions

- 없음.
