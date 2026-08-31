# Gate 1C — Risk-tiered Selective POST Replay

## 목적

VulnSpider는 GET-only crawler가 아니다. SPA/API 애플리케이션의 POST
surface도 폭넓게 발견하되, 다음 원칙을 적용한다.

> Discovery는 넓게, Active Execution은 위험도에 따라 제한한다.

최종 POST disposition은 다음과 같다.

- `SAFE_FOR_PROBE`: bounded Light Probe가 가능하다.
- `STRUCTURAL_ONLY`: 발견은 유지하지만 Active Replay는 하지 않는다.
- `BLOCKED_SENSITIVE`: 민감정보 저장과 Active Replay를 모두 금지한다.

Gate 1C는 POST를 모두 structural-only로 되돌리거나 현재 POST 발견 능력을
제거하는 작업이 아니다. Gate 1C-A는 후속 selective replay가 사용할 수 있도록
persistent discovery structure와 ephemeral replay material의 경계를 만든다.

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/GIT_WORKFLOW.md`
- Gate 1C-0 audit 결과와 현재 branch의 POST replay 구현

## 현재 문제

- 관찰된 POST가 reconstruction 가능하면 사실상 모두 `READY`가 된다.
- raw JSON member/query value가 persistent candidate와 canonical object에 남는다.
- structural candidate identity가 raw value에 종속된다.
- 별도 POST replay safety classifier가 없다.
- browser observation budget과 분리된 active POST replay budget이 없다.

## Gate 계획

1. **Gate 1C-A — Canonical identity + secret-safe representation**
   - structural identity를 raw value에서 분리한다.
   - persistent discovery structure와 ephemeral replay material을 분리한다.
   - POST endpoint와 JSON member 발견 능력 및 현재 실행 handoff는 보존한다.
2. **Gate 1C-B — POST Replay Policy classifier**
   - `SAFE_FOR_PROBE`, `STRUCTURAL_ONLY`, `BLOCKED_SENSITIVE`를 판정한다.
3. **Gate 1C-C — READY / NOT_READY handoff**
   - classifier 결과를 기존 readiness/context 계약에 연결한다.
4. **Gate 1C-D — Bounded POST Light Probe**
   - 독립적인 replay budget과 bounded execution을 적용한다.
5. **Gate 1C-E — Golden POST E2E**
   - 실제 browser observation, selective replay, state-change 및 secret leakage
     경계를 end-to-end로 검증한다.

Gate 1C-A에서는 classifier나 최종 readiness 정책을 구현 완료된 사실로 기록하지
않는다.

## Interfaces / Data Changes

- `BlockedPostJsonCandidate`는 method/origin/path/resource/member/query-name
  structure만 소유한다.
- `EphemeralRequestMaterial`은 정확한 replay URL/query/JSON body를 소유하되
  canonical identity, equality, repr 및 artifact serialization에서 제외한다.
- `NetworkDiscoveryCollection`과 worker pickle은 structural owner ID에 연결된
  explicit transient sidecar를 운반한다.
- `RequestTemplate`은 persistent structural fields와 실행 전용 accessors를
  분리한다. 기존 canonical `to_dict()` schema는 바꾸지 않는다.

## Safety / Scope Impact

- 새로운 host, method, browser authority 또는 transport 권한을 추가하지 않는다.
- 기존 exact-origin, loopback, blocked-before-transport POST 관찰 경계를 유지한다.
- 현재 replay 경로를 유지하지만 classifier와 별도 active POST budget은 후속
  Gate 전까지 추가하지 않는다.
- credential/security-token 이름을 좁게 확장하며 일반 `id`/`key` 이름은
  차단하지 않는다.

## Test Plan

- 제품 변경 전 structural ID/value leakage/CSRF-XSRF RED를 확보한다.
- POST canonicalization, domain identity, sensitive policy, planner execution,
  worker handoff와 crawl report leakage만 표적으로 검증한다.
- rendered DOM, same-origin navigation, GET/HEAD fetch/XHR를 독립 대조군으로
  검증한다.
- 전체 891-test suite는 이 Gate 요청에 따라 실행하지 않는다.

## Acceptance Criteria

- [x] 동일 structure/different values 및 JSON key ordering이 같은 candidate ID다.
- [x] InputPoint identity가 raw value와 무관하게 deterministic하다.
- [x] candidate repr/pickle 및 canonical/crawl artifact에 raw sentinel이 없다.
- [x] explicit transient material만 worker IPC에서 정확한 replay value를 운반한다.
- [x] POST Endpoint/InputPoint 발견과 현재 execution handoff가 유지된다.
- [x] CSRF/XSRF 이름은 차단되고 일반 `id`/`key`는 과잉 차단되지 않는다.
- [x] 표적 POST/worker/SPA 테스트와 diff/static 검증 결과를 기록한다.

## 현재 협업 충돌 영역

Gate 1C 기간에는 다음 파일을 coordination 대상으로 취급한다.

- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/dynamic_crawler.py`
- `src/vulnspider/discovery/network_canonicalization.py`
- `src/vulnspider/discovery/html_extractor.py`
- `src/vulnspider/discovery/contracts.py`
- `src/vulnspider/discovery/merge.py`
- `src/vulnspider/sensitive.py`
- `src/vulnspider/observation/planner.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/reporting/crawl_report.py`

이 영역을 동시에 변경하는 작업은 먼저 현재 diff와 Gate 소유권을 확인한다.

## 명시적 Non-goals

- nested JSON replay
- GraphQL mutation
- multipart replay
- authenticated POST automation 확대
- external target support
- 새로운 vulnerability type
- JSON focused verification 확대

## Gate 1C-A 불변식

- Structural POST candidate identity는 raw member value와 JSON key ordering에
  의존하지 않는다.
- 기존 InputPoint의 구조적 deterministic identity 계약을 유지한다.
- raw JSON value와 token/password/CSRF-like sentinel은 persistent candidate,
  canonical discovery serialization, crawl artifact, discovery snapshot 및 일반
  report에 남지 않는다.
- replay에 필요한 baseline material은 명시적인 ephemeral execution material로
  분리하며 structural identity나 일반 artifact serialization에 포함하지 않는다.
- POST Endpoint/JSON member discovery와 POST-independent SPA/GET/HEAD 동작을
  유지한다.

## 진행 기록

- 2026-08-31: Gate 1C-0 설계 감사에서 최종 정책을 risk-tiered selective POST
  replay로 확정했다.
- 2026-08-31: Gate 1C-A 분리 경계는 value-free
  `BlockedPostJsonCandidate`/persistent `RequestTemplate`과, 일반 repr 및 artifact
  serialization에서 제외되는 명시적 `EphemeralRequestMaterial` sidecar로 정했다.
  sidecar는 현재 POST 실행 handoff를 유지하기 위해 live discovery result와 worker
  IPC pickle에서만 전달한다.
- 2026-08-31: 제품 수정 전 Gate 테스트 7개를 실행해 11개 assertion/subtest
  failure를 재현했다. 구조가 같고 값만 다른 candidate ID, candidate repr 및
  canonical artifact의 raw sentinel, CSRF/XSRF 이름 인식이 RED였다. JSON key
  ordering과 기존 InputPoint 구조 ID는 이미 PASS였다.
- 2026-08-31: 구조 candidate에서 member/query value를 제거하고, canonical JSON
  body는 member별 `null` structural binding으로 저장하며 InputPoint baseline은
  `None`으로 유지했다. planner만 execution sidecar의 정확한 query/JSON 값을
  사용한다. merge는 동일 structural template에 sidecar가 있는 경우 이를
  실행 경로로 보존한다.
- 2026-08-31: targeted Gate/POST/sensitive/domain/worker/planner/SPA 대조군 37개가
  PASS했다. 별도 SPA 대조군 8개도 PASS했고 format/lint 및 in-memory dependency
  stub을 사용한 type-hint 검증이 PASS했다. 저장소 기본 type checker의 최초
  실행은 base PR #19 환경의 undeclared `tqdm` 의존성 때문에 import 전에
  중단됐다. 전체 test suite는 실행하지 않았다.
- 2026-08-31: persistent candidate pickle, canonical `to_dict()`, discovery
  snapshot 및 crawl report에는 sentinel이 없음을 확인했다. worker IPC pickle은
  의도적으로 explicit transient sidecar를 운반하며, 일반 artifact serialization과
  repr에서는 해당 값을 숨긴다.
- 2026-08-31: 첫 independent Gate Review에서 sidecar URL이 structural owner에
  결속되지 않아 외부 URL로 바뀔 수 있는 High finding을 발견했다. POST 전용,
  scheme/authority/path, fragment 부재, URL/query pair, structural query/JSON name
  일치를 도메인 경계에서 검증하고 5개 fail-closed 회귀를 추가했다. 재리뷰는
  18개 표적 테스트와 이전 bypass 재현 차단을 확인하고 `PASS`를 판정했다.
- 2026-08-31: Gate 1C-B 제품 코드 전 classifier matrix를 추가하고, policy
  module 부재로 1개 import error를 재현했다. 빈 JSON object가 두 weak semantic
  signal만으로 SAFE가 되는 추가 RED도 재현했다.
- 2026-08-31: value-free `PostReplayPolicyFeatures`, 전용 disposition/reason
  model과 pure classifier를 추가했다. classifier/sensitive, Gate 1C-A
  identity/artifact/sidecar/planner/pipeline/worker, submit-gate, BAC live-cookie와
  artifact-redaction 표적 회귀 36개가 PASS했다. format/lint와 새 policy module의
  공개 type-hint 검증도 PASS했다. 저장소 전체 type-hint 검사는 기존 `cli.py`의
  undeclared `tqdm` import에서 module 검사 전에 중단됐다. 전체 unittest suite는
  실행하지 않았다.
- 2026-08-31: independent review 중 percent-encoded path, camelCase
  action/credential name, literal mutation, Gate 1C-A가 camel boundary를 제거한
  `cartAdd` → `cartadd` state semantic 우회를 발견했다. 각 case를 RED로 재현한 뒤
  UTF-8 percent-decoded path tokenization, camel boundary 보존, precomputed
  credential-material flag, direct mutation token과 concatenated context/action
  판정을 추가했다. 재리뷰에서는 GraphQL non-goal이 action/member positive
  evidence로 SAFE가 되는 gap과 concatenated context substring 과잉 판정을
  발견했다. explicit/path GraphQL fail-closed reason을 추가하고 concatenated
  판정을 exact context/action compound로 좁혔다. 수정 후 위 36개 표적 회귀가
  PASS했다.
- 2026-08-31: fresh independent Gate Review는 최종 snapshot에서 BLOCKER/MAJOR
  없음과 `APPROVE`를 판정했다. production feature builder가 raw observation에서
  GraphQL/credential/action flags를 생성하는 wiring 회귀는 Gate 1C-C의
  non-blocking test gap으로 남겼다.

## Gate 1C-A 후속 경계

- Gate 1C-B 전에는 POST replay classifier나 최종 disposition을 구현하지 않는다.
- Gate 1C-C에서 sidecar가 없는 persisted/reloaded template의 `READY` 의미와
  execution handoff를 확정한다.
- Gate 1C-D에서 현재 active POST 횟수를 별도 budget으로 제한하고 sidecar
  lifetime을 더 좁힐 수 있는지 재검토한다.

## Gate 1C-B classifier contract

Gate 1C-B는 `discovery/post_replay_policy.py`의 순수 policy component로
구현한다. 이 component는 현재 discovery readiness나 active transport를
변경하지 않는다.

입력은 다음 value-free structural feature로 제한한다.

- method와 query-free path
- normalized JSON member/query/header/cookie names
- fetch/XHR resource provenance와 optional UI action intent
- exact authorized loopback origin 여부
- normalized content type/charset
- top-level object/scalar shape와 reconstruction completeness
- credential value/header/cookie presence flag
- explicit GraphQL semantics flag

결과는 `PostReplayDisposition`과 deterministic primary
`PostReplayReasonCode`의 pair다. 민감 field/header/cookie가 가장 먼저
`BLOCKED_SENSITIVE`를 결정한다. method/origin/provenance/JSON shape/reconstruction
실패와 state-changing 또는 ambiguous semantics는 `STRUCTURAL_ONLY`다.
`SAFE_FOR_PROBE`는 모든 structural prerequisite를 만족하고, 주입 가능한
top-level member가 있으며, path/action/member 중 서로 다른 최소 두 signal
source에서 positive read-only evidence가 있을 때만 승인한다.

Gate 1C-B의 classifier result는 아직 `ProbeReadiness`, planner, pipeline 또는
POST execution budget에 연결하지 않는다. 해당 wiring은 Gate 1C-C/D 범위다.

## Gate 1C-B acceptance criteria

- [x] `/api/search` + `keyword`, `/api/filter` + `category,page`가
  `SAFE_FOR_PROBE`다.
- [x] update/cart/checkout, nested JSON, ambiguous endpoint와 빈 JSON object가
  `STRUCTURAL_ONLY`다.
- [x] password/token/authorization/session/CSRF/XSRF semantics가
  `BLOCKED_SENSITIVE`다.
- [x] `product_id`, `category`, `page`, `key`, `license_key`는 secret로
  과잉 차단되지 않는다.
- [x] 동일 member/shape의 scalar value 변화는 feature, disposition과 reason을
  바꾸지 않는다.
- [x] classifier는 기존 readiness와 active replay handoff를 변경하지 않는다.
- [x] GraphQL path/explicit semantics는 non-goal로 `STRUCTURAL_ONLY`다.

## Decision Log

- Decision: structural candidate와 exact replay value는 structural owner ID로
  연결한 explicit sidecar로 분리한다.
- Reason: 최소한의 변경으로 deterministic identity와 artifact secret boundary를
  만들면서 현재 READY/planner handoff를 유지할 수 있다.
- Decision: persistent JSON binding은 member별 `null`, InputPoint baseline은
  `None`으로 표현한다.
- Reason: member 발견 구조와 기존 context ownership을 보존하면서 observed raw
  value를 canonical artifact에서 제거한다.
- Decision: Gate 1C-B POST disposition은 GET value-elision enum을 재사용하지
  않고 별도 `PostReplayDisposition`으로 표현한다.
- Reason: 기존 enum은 이미 허용된 GET의 value 보존 여부를 뜻하며, POST active
  replay 권한과 민감 차단을 함께 표현하지 못한다.
- Decision: SAFE positive evidence는 keyword 개수가 아니라 path/action/member의
  서로 다른 signal source 두 개 이상을 요구한다.
- Reason: 단일 약한 keyword로 SAFE를 승인하지 않으면서 search/filter JSON API의
  실용적 positive coverage를 유지한다.

## Open Questions

- persisted artifact를 다시 읽을 때 transient material이 없는 template의
  readiness/execution disposition은 Gate 1C-C에서 결정한다.
- sidecar lifetime 단축과 독립 POST replay budget은 Gate 1C-D에서 결정한다.
