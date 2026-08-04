# VulnSpider - Start Here

## Repository status

This repository retains the **Completed and Frozen v0.1 checkpoint** and now
also contains the in-progress v0.2 Native Discovery implementation.

- **Implemented:** the `prototype/v0.1` legacy-record analysis path, JSON
  report, optional HTML report, Native Static Discovery, bounded combined
  Native Static plus Native Dynamic Discovery, final loopback E2E acceptance,
  and the simple Dynamic-first CLI adapter.
- **Still planned for v0.2:** BAC prioritization and LLM-assisted focused
  verification.
- **Historical:** the Prompt 01-07 sequence that produced and reviewed v0.1.

Planning documents do not imply that later v0.2 milestones are implemented.

## Read first

New contributors should read these documents in order:

1. [AGENTS.md](AGENTS.md) - frozen scope, authorized v0.2 scope, safety, and
   Git rules.
2. [Architecture](docs/ARCHITECTURE.md) - implemented v0.1, target v0.2, and
   legacy path.
3. [Prototype v0.1](docs/PROTOTYPE_V0_1.md) - the completed v0.1 checkpoint.
4. [Prototype v0.2](docs/PROTOTYPE_V0_2.md) - the authorized v0.2 plan.
5. [Team Interfaces v0.2](docs/TEAM_INTERFACES_V0_2.md) - proposed cross-owner
   contracts.
6. [Git Workflow](docs/GIT_WORKFLOW.md) - branch, PR, review, and
   secret-handling policy.
7. [Decision Log](docs/DECISION_LOG.md) - accepted and superseded decisions.

Use `docs/DOMAIN_MODEL.md`, `docs/FEATURE_SCHEMA.md`, and
`docs/EVALUATION_PROTOCOL.md` when changing their respective boundaries.

## Implemented analysis entry points

The default user command runs the existing combined discovery and Light Probe
pipeline and atomically writes `vulnspider-result.json` in the current
directory:

```powershell
vulnspider -u http://127.0.0.1:8080/
vulnspider -u http://127.0.0.1:8080/ -o result.json
vulnspider -u http://127.0.0.1:8080/ --static-only
```

Simple Dynamic mode automatically admits only rendered GET anchors on the
exact root origin and GET script/style resources on that same origin. Existing
page, depth, elapsed-time, navigation, and request-decision budgets remain in
force. Fetch/XHR, WebSocket, EventSource, POST, form submission, popup, child
frame traversal, cross-origin, and different-port traffic remain blocked by
default. Existing `--dynamic-allow-navigation` and
`--dynamic-allow-resource` flags add explicit advanced grants.

The JSON report is rendered completely into a same-directory temporary file
and replaces the requested destination only after success. Failed or degraded
simple scans do not publish a partial result. Successful simple scans print
only a bounded summary and the resolved output path; reports and diagnostics
do not print raw DOM or sensitive form values.

The frozen compatibility path consumes legacy crawl records, then performs
authorized localhost/loopback Light Probes:

```text
Legacy record JSON
  -> LegacyCrawlerAdapter
  -> Endpoint / InputPoint / RequestTemplate / InputPointRequestContext
  -> baseline + one-at-a-time probe
  -> minimal differential / reflection / SQL features
  -> SQLi and Reflected XSS scoring
  -> deterministic global Top-K by selection_priority
  -> JSON report
  -> optional HTML report
```

```powershell
vulnspider analyze `
  --input legacy-records.json `
  --top-k 10 `
  --output result.json `
  --html-output result.html
```

`--html-output` is optional. The HTML renderer displays the same validated
`SelectionOutcome`, `ScoreEvidence`, and executed baseline/probe provenance as
the JSON path. It does not recompute scores or confirm vulnerabilities.
Equivalent JSON and HTML output paths are rejected before either report is
written.

An authorized loopback URL uses Native Static Discovery by default. Bounded
Native Dynamic Discovery is explicit opt-in and merges its validated result
with the policy-bound Static result before the unchanged canonical analysis
consumer runs:

```powershell
vulnspider analyze `
  --url http://127.0.0.1:8080/ `
  --dynamic `
  --dynamic-allow-navigation http://127.0.0.1:8080/search `
  --dynamic-allow-resource script=http://127.0.0.1:8080/app.js `
  --top-k 10 `
  --output result.json
```

Without `--dynamic`, `--url` remains Static-only and never requires
Playwright. Dynamic authority and policy options are invalid without the
opt-in flag and with `--input`. Explicit Dynamic capability/configuration,
integrity, and validated degradation paths use exit codes 2, 3, and 4
respectively.

## Implemented and not implemented

### Implemented

- Legacy crawl-record JSON input.
- Direct authorized URL input through bounded Native Static Discovery.
- Explicit `--dynamic` combined Native Discovery with exact, immutable
  navigation/resource authority and lazy Playwright capability checking.
- Dynamic-first `vulnspider -u URL` adapter with rendered same-origin GET
  anchor navigation, same-origin script/style loading, atomic default JSON,
  and `--static-only` compatibility.
- Combined canonical handoff to the existing READY-context analysis consumer;
  NOT_READY contexts remain non-executable.
- `LegacyCrawlerAdapter` normalization into canonical v0.1 domain models.
- Deterministic probe planning and loopback-only baseline/probe execution.
- Minimal differential, reflection, and SQL signal extraction.
- Independent SQLi and Reflected XSS scoring with `ScoreEvidence`.
- Deterministic global Top-K using `selection_priority`.
- JSON report and optional escaped HTML report.
- Unit and integration coverage for the implemented path.

### Planned for v0.2, not implemented

- BAC preprocessing, features, scoring, and role/session orchestration.
- Feature cache and automated quantitative ranking evaluation.
- GPT/Gemini comparison harness.
- LLM-assisted payload mutation and payload validation.
- Focused verification, `VerificationEvidence`, and
  `VerificationConfidence`.
- Rule-based confidence updates.

Fine-tuning is **Deferred** unless the v0.2 API comparison and failure analysis
meet the decision gate in [Prototype v0.2](docs/PROTOTYPE_V0_2.md).

## Historical v0.1 build process

The Prompt 01-07 flow is retained as project history, not as the current
onboarding workflow:

1. `prompts/01_LEGACY_AUDIT.md`
2. `prompts/02_REPOSITORY_SCAFFOLD.md`
3. `prompts/03_DOMAIN_MODEL.md`
4. `prompts/04_LEGACY_ADAPTER.md`
5. `prompts/05_PROBE_FEATURE_SCORING.md`
6. `prompts/06_INDEPENDENT_REVIEW.md`
7. `prompts/07_FIX_REVIEW_LOOP.md`

These files document how v0.1 was built and reviewed. New v0.2 work starts from
the current code and the v0.2 documents, not by replaying the prompts.

## Development checks

```text
python -B -m unittest discover -s tests
python tools/check_format.py
python tools/check_lint.py
python tools/check_types.py
git diff --check
```

Windows and Codex setup details remain in `docs/CODEX_SETUP.md`.
