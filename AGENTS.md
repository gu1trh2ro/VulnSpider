# AGENTS.md

## Mission

Build **SPIDERMAN**, a graduation-project prototype for input-point-based web vulnerability candidate prioritization and selective verification.

The core research contribution is **ranking what should be verified first**, not building a generic full-coverage vulnerability scanner and not delegating final vulnerability judgment to an LLM.

## Read First

Before making non-trivial changes, read the smallest relevant set of documents:

- `docs/ARCHITECTURE.md` — system boundaries and dependency direction
- `docs/DOMAIN_MODEL.md` — Endpoint, InputPoint, Candidate, Evidence, Finding
- `docs/FEATURE_SCHEMA.md` — v0.1 feature definitions and missing-value rules
- `docs/PROTOTYPE_V0_1.md` — exact first-prototype scope and acceptance criteria
- `docs/EVALUATION_PROTOCOL.md` — experiment rules and leakage prevention
- `docs/DECISION_LOG.md` — accepted architectural decisions
- `PLANS.md` — execution-plan rules for complex tasks
- `CODE_REVIEW.md` — review checklist

Treat `docs/` as the repository system of record. Do not silently contradict it.

## Core Pipeline

```text
Scope & Safety Guard
  -> Discovery
  -> Attack Surface Normalization
  -> Endpoint + InputPoint
  -> Baseline / One-at-a-time Light Probe
  -> Response Normalization
  -> Feature Extraction
  -> Feature Vector
  -> VulnerabilityCandidate generation
  -> Type-specific Scoring
  -> Top-K Selection
  -> JSON Report
```

Prototype v0.1 stops here. Focused exploitation, LLM payload mutation, BAC automation, dashboard, and broad active scanning are out of scope unless a later task explicitly changes the scope.

## Non-Negotiable Domain Rules

1. `Page != Endpoint != InputPoint != VulnerabilityCandidate`.
2. The atomic observation unit is `InputPoint`.
3. The atomic ranking unit is `InputPoint x VulnerabilityType`.
4. Change only one InputPoint per probe request unless a documented experiment explicitly requires otherwise.
5. `RankScore` means "verification priority", not "probability of vulnerability".
6. `VerificationConfidence` is a later concept and must not be derived by simply adding RankScore to verification bonuses.
7. SQLi and Reflected XSS use independent scorers.
8. BAC is not part of v0.1 and must not be forced into the injection-candidate model.
9. Missing feature != observed zero. Preserve observation state.
10. Every score must be explainable through feature contributions.

## Safety and Scope Rules

- Operate only on explicitly authorized local test targets.
- Default allowed hosts: `localhost`, `127.0.0.1`, and explicitly configured local Docker targets.
- Never expand scope because of redirects, suffix matching, discovered external links, or model suggestions.
- Do not add destructive verification behavior.
- Do not add data modification, deletion, account creation, persistence, shell execution, or denial-of-service behavior.
- v0.1 Light Probes must be observational and low-impact.
- Preserve configurable crawl depth, request count, delay, and timeout limits.
- Do not reuse a crawler's HTTP error-handling assumptions inside the Probe Executor.

## Legacy Code Policy

- `reference/whspider_legacy/` is previous WHS project code.
- Treat legacy code as read-only by default.
- First audit it, then reuse through adapters where practical.
- Prefer `LegacyCrawlerAdapter` over invasive refactoring.
- Do not reuse the old LLM/RAG pipeline by default.
- Do not reuse the old database schema as the new domain schema.

## Engineering Rules

- Python-first implementation.
- Use explicit typed models for core domain objects.
- Keep network I/O behind interfaces so unit tests do not require live targets.
- Prefer deterministic functions for normalization, feature extraction, scoring, and explanations.
- Keep modules small and dependency direction explicit.
- Do not add a dependency without documenting why the standard library or existing dependency is insufficient.
- Do not perform broad unrelated refactors in feature tasks.
- Keep generated artifacts and experimental caches out of source modules.

## Required Verification Loop

For every meaningful implementation task:

1. Inspect relevant docs and existing code.
2. State or write a short plan before coding.
3. Add or update tests.
4. Run the narrowest relevant test set.
5. Run formatting, linting, and type checks when configured.
6. Review the diff against `CODE_REVIEW.md`.
7. Fix findings.
8. Re-run verification.
9. Update docs or `docs/DECISION_LOG.md` if behavior or architecture changed.

Never claim completion without reporting the checks actually run and their outcomes.

## Definition of Done

A task is done only when:

- requested behavior exists,
- scope constraints are preserved,
- relevant tests pass,
- edge cases are documented or tested,
- no unrelated changes remain,
- the diff has been reviewed,
- documentation matches implementation.

## When You Are Unsure

Do not guess hidden repository behavior. Inspect code, tests, fixtures, and docs first.

For a complex or ambiguous change, create an execution plan under `docs/exec-plans/active/` using `PLANS.md`, keep progress and decisions current, and move it to `completed/` when finished.
