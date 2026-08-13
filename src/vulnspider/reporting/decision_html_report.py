"""The full scan report, ranked by the decision layer.

This is the same report `analyze --html-output` produces -- endpoint, why it
ranks where it does, the baseline and probe requests that were actually
executed with their responses, and general guidance -- but ordered and cut by
the calibrated decision layer instead of the heuristic `selection_priority`.

Everything that renders a candidate is reused from ``html_report``: the
endpoint line, the executed-requests table, the guidance text, the document
shell and the stylesheet. Only three things differ, and they are exactly the
things the decision layer changes:

* the score is a calibrated probability, so the caption reads
  "probability · expected value · request cost" rather than "raw N / max M";
* evidence is the per-feature log-odds contribution rather than a weighted
  term;
* a decision summary and the recall guarantee replace the priority-band bar.

Like the v0.1 report it **displays authoritative results and recomputes
nothing** (``docs/ARCHITECTURE.md``). Probabilities, ordering, constraints and
the guarantee all come from the already validated ``DecisionOutcome``; the
endpoint, input-point and probe-run maps only supply provenance to display.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import DecisionOutcome
from vulnspider.domain import Endpoint, InputPoint, VulnerabilityType
from vulnspider.reporting.html_report import (
    GENERAL_GUIDANCE,
    VULNERABILITY_LABELS,
    ProbeRun,
    _DOCUMENT_STYLE,
    _endpoint_context,
    _esc,
    _fmt_number,
    _fmt_percent,
    _priority_band,
    _render_candidates,
    _render_warnings,
    _requests_context,
)
from vulnspider.scoring.calibration import CalibratedProbability, CalibratedScorer

DECISION_HTML_REPORT_VERSION = "decision-html-v1"

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = {}
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = {}
_EMPTY_PROBE_RUNS: Mapping[str, ProbeRun] = {}
_EMPTY_PROBABILITIES: Mapping[str, CalibratedProbability] = {}
_EMPTY_MODELS: Mapping[str, CalibratedScorer] = {}

_CONSTRAINT_LABEL = {
    "top_k": "Top-K reached",
    "budget": "request budget exhausted",
    "both": "Top-K and budget both reached",
    "none": "every candidate fitted",
}


def build_decision_report_context(
    outcome: DecisionOutcome,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    """Assemble the render context from one validated decision outcome."""

    if not isinstance(outcome, DecisionOutcome):
        raise TypeError("outcome must be a DecisionOutcome")
    outcome.validate()

    return {
        "target": target,
        "elapsed_seconds": elapsed_seconds,
        "warnings": list(warnings),
        "models": _models_context(models),
        "outcome": outcome,
        "candidates": [
            _candidate_context(
                candidate,
                rank=rank,
                input_points=input_points,
                endpoints=endpoints,
                probe_runs=probe_runs,
                calibrated=probabilities.get(candidate.candidate_id),
            )
            for rank, candidate in enumerate(outcome.selection.selected, start=1)
        ],
        "deferred": _unselected_contexts(outcome, input_points, endpoints),
    }


def render_decision_html_report(
    outcome: DecisionOutcome,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
) -> str:
    """Render the full decision-ranked scan report as one HTML document."""

    context = build_decision_report_context(
        outcome,
        target=target,
        input_points=input_points,
        endpoints=endpoints,
        probe_runs=probe_runs,
        probabilities=probabilities,
        models=models,
        warnings=warnings,
        elapsed_seconds=elapsed_seconds,
    )
    return _render_document(context)


def write_decision_html_report(
    outcome: DecisionOutcome,
    destination: str | Path,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probe_runs: Mapping[str, ProbeRun] = _EMPTY_PROBE_RUNS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
) -> None:
    """Write the decision-ranked scan report to ``destination``."""

    Path(destination).write_text(
        render_decision_html_report(
            outcome,
            target=target,
            input_points=input_points,
            endpoints=endpoints,
            probe_runs=probe_runs,
            probabilities=probabilities,
            models=models,
            warnings=warnings,
            elapsed_seconds=elapsed_seconds,
        ),
        encoding="utf-8",
    )


def _models_context(models: Mapping[str, CalibratedScorer]) -> str:
    trained = sorted(
        (family, scorer.training_samples) for family, scorer in models.items()
    )
    if not trained:
        return "heuristic prior (no corpus)"
    if all(count == 0 for _family, count in trained):
        return "heuristic prior (zero-data posterior)"
    detail = ", ".join(f"{family} n={count}" for family, count in trained)
    return f"fitted from corpus ({detail})"


def _family_type(family: str) -> VulnerabilityType | None:
    try:
        return VulnerabilityType(family)
    except ValueError:
        return None


def _candidate_context(
    candidate: DecisionCandidate,
    *,
    rank: int,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probe_runs: Mapping[str, ProbeRun],
    calibrated: CalibratedProbability | None,
) -> dict[str, Any]:
    """One candidate in the shape ``html_report._render_candidate`` expects."""

    probability = float(candidate.probability)
    input_point = input_points.get(candidate.subject_ref)
    endpoint = (
        endpoints.get(input_point.endpoint_id) if input_point is not None else None
    )
    family_type = _family_type(candidate.family)
    return {
        "rank": rank,
        "candidate_id": candidate.candidate_id,
        "feature_vector_id": candidate.feature_vector_ref,
        "vulnerability_type": candidate.family,
        "vulnerability_label": (
            VULNERABILITY_LABELS.get(family_type, candidate.family)
            if family_type is not None
            else candidate.family
        ),
        "selection_priority": probability,
        "priority_band": _priority_band(probability),
        # The v0.1 caption reads "raw N / max M", which says nothing about a
        # probability. Say what the allocator actually weighed instead.
        "caption": (
            f"probability &middot; expected value "
            f"{candidate.expected_value:.2f} &middot; "
            f"{_fmt_number(candidate.verification_cost)} requests"
        ),
        "raw_rank_score": probability,
        "raw_rank_score_max": 1.0,
        "endpoint": _endpoint_context(endpoint, input_point),
        "evidence": _evidence_contexts(candidate, calibrated),
        "requests": _requests_context(candidate.feature_vector_ref, probe_runs),
        "general_guidance": (
            GENERAL_GUIDANCE.get(family_type) if family_type is not None else None
        ),
    }


def _evidence_contexts(
    candidate: DecisionCandidate,
    calibrated: CalibratedProbability | None,
) -> list[dict[str, Any]]:
    """Per-feature log-odds contributions, in the v0.1 evidence shape.

    Unobserved features are kept in the list. A reader must be able to tell
    "checked and absent" from "never measured"; dropping the latter would make
    a report that silently reads as if everything had been observed.
    """

    if calibrated is None:
        return []
    return [
        {
            "vulnerability_type": candidate.family,
            "feature_name": item.feature_name,
            "feature_value": item.feature_value,
            "observed": item.observed,
            "weight": item.weight,
            "contribution": item.logit_contribution,
            "reason": item.reason,
            "signal_on": (
                item.observed
                and item.feature_value is not None
                and item.feature_value > 0.0
            ),
        }
        for item in sorted(calibrated.evidence, key=lambda e: e.feature_name)
    ]


def _unselected_contexts(
    outcome: DecisionOutcome,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
) -> list[dict[str, Any]]:
    """Every scored candidate that did not make the cut, and why.

    ``selection.deferred`` only holds candidates the selector saw and passed
    over. Anything the conformal threshold removed never reached the selector,
    so reporting deferred alone would silently drop them and leave a reader
    unable to account for the difference between "scored" and "selected".
    """

    selected = {item.candidate_id for item in outcome.selection.selected}
    deferred = {item.candidate_id for item in outcome.selection.deferred}
    threshold = None if outcome.conformal is None else outcome.conformal.threshold
    rows = []
    for candidate in outcome.scored:
        if candidate.candidate_id in selected:
            continue
        if candidate.candidate_id in deferred:
            reason = "ranked below the cut"
        elif threshold is not None:
            reason = f"below the recall threshold {threshold:.4f}"
        else:
            reason = "not selected"
        rows.append(
            _deferred_context(candidate, input_points, endpoints, reason=reason)
        )
    return sorted(rows, key=lambda item: (-item["probability"], item["location"]))


def _deferred_context(
    candidate: DecisionCandidate,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    *,
    reason: str,
) -> dict[str, Any]:
    input_point = input_points.get(candidate.subject_ref)
    endpoint = (
        endpoints.get(input_point.endpoint_id) if input_point is not None else None
    )
    if input_point is None:
        location = candidate.candidate_id
    elif endpoint is None:
        location = f"{input_point.location.value.lower()}.{input_point.name}"
    else:
        location = (
            f"{endpoint.method.value} {endpoint.path} "
            f"{input_point.location.value.lower()}.{input_point.name}"
        )
    return {
        "location": location,
        "family": candidate.family,
        "probability": float(candidate.probability),
        "verification_cost": candidate.verification_cost,
        "reason": reason,
    }


def _render_document(context: Mapping[str, Any]) -> str:
    target = context["target"]
    title = "VulnSpider decision report" + (f" — {target}" if target else "")
    sections = [
        _render_header(context),
        _render_stats(context["outcome"]),
        _render_guarantee(context["outcome"]),
        _render_warnings(context["warnings"]),
        '<h2 class="section">Verification order</h2>',
        _render_candidates(context["candidates"]),
        _render_deferred(context["deferred"]),
        _render_footer(context),
    ]
    body = "\n\n".join(section for section in sections if section)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_DOCUMENT_STYLE}</style>\n"
        f'</head>\n<body>\n<div class="wrap">\n\n{body}\n\n</div>\n</body>\n</html>\n'
    )


def _render_header(context: Mapping[str, Any]) -> str:
    target = context["target"]
    outcome = context["outcome"]
    target_line = (
        f'<div class="target">target &rarr; {_esc(target)}</div>' if target else ""
    )
    return (
        '<header class="masthead">\n'
        '  <div class="brand">\n'
        "    <h1>VulnSpider</h1>"
        f'<span class="ver">decision report &middot; '
        f"{_esc(outcome.policy_version)}</span>\n"
        "  </div>\n"
        '  <div class="tagline">Candidates ranked by calibrated probability and '
        "selected under an explicit constraint. Verification priority, not "
        "confirmed findings.</div>\n"
        f"  {target_line}\n"
        f'  <div class="target">model &rarr; {_esc(context["models"])}</div>\n'
        "</header>"
    )


def _render_stats(outcome: DecisionOutcome) -> str:
    selection = outcome.selection
    cells = (
        (_fmt_number(outcome.initial_candidates), "candidates scored"),
        (_fmt_number(len(selection.selected)), "selected"),
        (
            "—" if selection.top_k is None else _fmt_number(selection.top_k),
            "top-k",
        ),
        (
            "—" if selection.budget is None else _fmt_number(selection.budget),
            "request budget",
        ),
        (_fmt_number(selection.spent_cost), "requests committed"),
        (f"{selection.expected_findings:.2f}", "expected findings"),
    )
    items = "\n".join(
        f'  <div class="stat"><div class="n">{_esc(value)}</div>'
        f'<div class="l">{_esc(label)}</div></div>'
        for value, label in cells
    )
    ratio = (
        "no combined bound is claimed for two active constraints"
        if selection.approximation_ratio is None
        else f"at least {_fmt_percent(selection.approximation_ratio)}% of the "
        "optimum for this objective"
    )
    limit = _CONSTRAINT_LABEL.get(
        selection.binding_constraint, selection.binding_constraint
    )
    return (
        f'<section class="stats">\n{items}\n</section>\n'
        f'<div class="notice small">Selection stopped because {_esc(limit)}. '
        f"Approximation guarantee: {_esc(ratio)}.</div>"
    )


def _render_guarantee(outcome: DecisionOutcome) -> str:
    conformal = outcome.conformal
    if conformal is None:
        return (
            '<div class="notice"><div class="lab">Recall guarantee</div>'
            "None requested. The selected set size is controlled by top-k and "
            "the request budget only.</div>"
        )
    if not conformal.guarantee_attainable:
        return (
            '<div class="notice"><div class="lab">Recall guarantee</div>'
            "<b>Not in force.</b> A target risk of "
            f"{_fmt_percent(conformal.target_risk)}% needs more calibration "
            f"applications than the "
            f"{_fmt_number(conformal.calibration_groups)} available, so no "
            "threshold was certified and every candidate was kept.</div>"
        )
    covered = (
        "the budget covers that set"
        if outcome.budget_covers_conformal_set
        else "<b>the budget does not cover that set, so the guarantee does not "
        "hold for this run</b>"
    )
    return (
        '<div class="notice"><div class="lab">Recall guarantee</div>'
        f"At least {_fmt_percent(1.0 - conformal.target_risk)}% of true findings "
        f"are expected to survive the cut at probability "
        f"{conformal.threshold:.4f}, calibrated on "
        f"{_fmt_number(conformal.calibration_groups)} applications "
        f"(empirical risk {conformal.empirical_risk:.4f}). The guaranteed set "
        f"holds {_fmt_number(outcome.conformal_set_size)} candidates and "
        f"{covered}.</div>"
    )


def _render_deferred(deferred: Sequence[Mapping[str, Any]]) -> str:
    if not deferred:
        return ""
    rows = "\n".join(
        f'    <tr><td class="pl">{_esc(item["location"])}</td>'
        f'<td class="role">{_esc(item["family"])}</td>'
        f'<td class="status">{item["probability"]:.4f}</td>'
        f'<td class="status">{_fmt_number(item["verification_cost"])}</td>'
        f'<td>{_esc(item["reason"])}</td></tr>'
        for item in deferred
    )
    return (
        f'<h2 class="section">Not selected ({len(deferred)})</h2>\n'
        '<div class="notice"><table class="rec">\n'
        "  <tr><th>location</th><th>family</th><th>probability</th>"
        "<th>requests</th><th>why not</th></tr>\n"
        f"{rows}\n</table>\n"
        "<i>Ranked below the cut. Not a statement that they are safe.</i></div>"
    )


def _render_footer(context: Mapping[str, Any]) -> str:
    outcome = context["outcome"]
    return (
        "<footer>"
        f"{_esc(DECISION_HTML_REPORT_VERSION)} &middot; "
        f"{_esc(outcome.selection.selector_version)} &middot; "
        f"{context['elapsed_seconds']:.2f}s<br>"
        '<span class="warn">Probabilities are pre-verification priorities '
        "(ADR-016). No candidate here is a confirmed vulnerability.</span>"
        "</footer>"
    )
