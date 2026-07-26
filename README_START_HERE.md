# VulnSpider - Start Here

## Repository status

This repository is the **Completed and Frozen v0.1 checkpoint** for
VulnSpider. It is no longer an empty starter repository.

- **Implemented:** the `prototype/v0.1` legacy-record analysis path, JSON
  report, and optional HTML report.
- **Planned for v0.2:** native discovery, BAC prioritization, and
  LLM-assisted focused verification.
- **Historical:** the Prompt 01-07 sequence that produced and reviewed v0.1.

Planning documents do not imply that v0.2 production code exists.

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

## Implemented v0.1 path

The current CLI does not crawl a target URL. It consumes an array of legacy
crawl records, then performs authorized localhost/loopback Light Probes:

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

## Implemented and not implemented

### Implemented

- Legacy crawl-record JSON input.
- `LegacyCrawlerAdapter` normalization into canonical v0.1 domain models.
- Deterministic probe planning and loopback-only baseline/probe execution.
- Minimal differential, reflection, and SQL signal extraction.
- Independent SQLi and Reflected XSS scoring with `ScoreEvidence`.
- Deterministic global Top-K using `selection_priority`.
- JSON report and optional escaped HTML report.
- Unit and integration coverage for the implemented path.

### Planned for v0.2, not implemented

- Direct target URL input.
- Native static crawler.
- Native dynamic/browser crawler prototype.
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
