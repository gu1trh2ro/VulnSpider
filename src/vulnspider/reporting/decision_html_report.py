"""Static HTML report for a decision-layer run.

`analyze --html-output` renders a `SelectionOutcome` -- the heuristic
`selection_priority` ordering. That report is frozen and unchanged. This one
renders a :class:`~vulnspider.decision.policy.DecisionOutcome` instead, so a
`decide` run produces the same kind of browsable artifact for the calibrated
path: probabilities rather than priorities, the constraint that actually
stopped the selection, and the recall guarantee when one was calibrated.

Like the v0.1 report it **displays authoritative results and recomputes
nothing** (`docs/ARCHITECTURE.md`). Every number comes from the already
validated ``DecisionOutcome``; the endpoint and input-point maps are used only
to render where a candidate lives, and a candidate whose subject is missing
from those maps degrades to showing its identifier rather than guessing.

The document shell and stylesheet are shared with the v0.1 report so both
artifacts look like the same tool. They are imported rather than duplicated;
that is the only coupling, and it is presentation-only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from vulnspider.decision.policy import DecisionOutcome
from vulnspider.domain import Endpoint, InputPoint
from vulnspider.reporting.html_report import (
    _DOCUMENT_STYLE,
    _esc,
    _fmt_number,
    _fmt_percent,
)
from vulnspider.scoring.calibration import CalibratedProbability, CalibratedScorer

DECISION_HTML_REPORT_VERSION = "decision-html-v1"

_EMPTY_INPUT_POINTS: Mapping[str, InputPoint] = {}
_EMPTY_ENDPOINTS: Mapping[str, Endpoint] = {}
_EMPTY_PROBABILITIES: Mapping[str, CalibratedProbability] = {}
_EMPTY_MODELS: Mapping[str, CalibratedScorer] = {}

# Probability bands for the colour cue. These are display thresholds only and
# carry no decision meaning -- the selector already decided.
_BAND_HIGH = 0.7
_BAND_MEDIUM = 0.4

_CONSTRAINT_LABEL = {
    "top_k": "Top-K reached",
    "budget": "request budget exhausted",
    "both": "Top-K and budget both reached",
    "none": "every candidate fitted",
}


def render_decision_html_report(
    outcome: DecisionOutcome,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
) -> str:
    """Render one decision outcome as a standalone HTML document."""

    if not isinstance(outcome, DecisionOutcome):
        raise TypeError("outcome must be a DecisionOutcome")
    outcome.validate()

    selection = outcome.selection
    sections = [
        _render_header(target, outcome, models),
        _render_stats(outcome),
        _render_guarantee(outcome),
        _render_warnings(warnings),
        '<h2 class="section">Verification order</h2>',
        _render_selected(
            outcome,
            input_points=input_points,
            endpoints=endpoints,
            probabilities=probabilities,
        ),
        _render_deferred(outcome, input_points=input_points, endpoints=endpoints),
        _render_footer(elapsed_seconds, selection.selector_version),
    ]
    body = "\n\n".join(section for section in sections if section)
    title = "VulnSpider decision" + (f" — {target}" if target else "")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_DOCUMENT_STYLE}</style>\n"
        f'</head>\n<body>\n<div class="wrap">\n\n{body}\n\n</div>\n</body>\n</html>\n'
    )


def write_decision_html_report(
    outcome: DecisionOutcome,
    destination: str | Path,
    *,
    target: str = "",
    input_points: Mapping[str, InputPoint] = _EMPTY_INPUT_POINTS,
    endpoints: Mapping[str, Endpoint] = _EMPTY_ENDPOINTS,
    probabilities: Mapping[str, CalibratedProbability] = _EMPTY_PROBABILITIES,
    models: Mapping[str, CalibratedScorer] = _EMPTY_MODELS,
    warnings: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
) -> None:
    """Write the decision report to ``destination``."""

    Path(destination).write_text(
        render_decision_html_report(
            outcome,
            target=target,
            input_points=input_points,
            endpoints=endpoints,
            probabilities=probabilities,
            models=models,
            warnings=warnings,
            elapsed_seconds=elapsed_seconds,
        ),
        encoding="utf-8",
    )


def _band(probability: float) -> str:
    if probability >= _BAND_HIGH:
        return "high"
    if probability >= _BAND_MEDIUM:
        return "medium"
    return "low"


def _location(
    candidate: Any,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
) -> str:
    """Where this candidate lives, or its identifier when unknown."""

    point = input_points.get(candidate.subject_ref)
    if point is None:
        return candidate.candidate_id
    endpoint = endpoints.get(point.endpoint_id)
    if endpoint is None:
        return f"{point.location.value.lower()}:{point.name}"
    return (
        f"{endpoint.method.value} {endpoint.path} "
        f"[{point.location.value.lower()}:{point.name}]"
    )


def _render_header(
    target: str,
    outcome: DecisionOutcome,
    models: Mapping[str, CalibratedScorer],
) -> str:
    trained = sorted(
        (family, scorer.training_samples) for family, scorer in models.items()
    )
    if not trained:
        model_line = "model: heuristic prior (no corpus)"
    elif all(count == 0 for _family, count in trained):
        model_line = "model: heuristic prior (zero-data posterior)"
    else:
        detail = ", ".join(f"{family} n={count}" for family, count in trained)
        model_line = f"model: fitted ({detail})"
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
        f"  {target_line}\n"
        f'  <div class="target">{_esc(model_line)}</div>\n'
        "</header>"
    )


def _render_stats(outcome: DecisionOutcome) -> str:
    selection = outcome.selection
    budget = (
        "unbounded" if selection.budget is None else _fmt_number(selection.budget)
    )
    top_k = "unbounded" if selection.top_k is None else _fmt_number(selection.top_k)
    ratio = (
        "not claimed"
        if selection.approximation_ratio is None
        else _fmt_percent(selection.approximation_ratio) + "%"
    )
    cells = (
        ("candidates scored", _fmt_number(outcome.initial_candidates)),
        ("selected", _fmt_number(len(selection.selected))),
        ("top-k", top_k),
        ("request budget", budget),
        ("requests committed", _fmt_number(selection.spent_cost)),
        ("expected findings", f"{selection.expected_findings:.2f}"),
        ("limited by", _CONSTRAINT_LABEL.get(
            selection.binding_constraint, selection.binding_constraint
        )),
        ("approximation bound", ratio),
    )
    items = "\n".join(
        f'  <div class="stat"><span class="k">{_esc(label)}</span>'
        f'<span class="v">{_esc(value)}</span></div>'
        for label, value in cells
    )
    return f'<section class="stats">\n{items}\n</section>'


def _render_guarantee(outcome: DecisionOutcome) -> str:
    conformal = outcome.conformal
    if conformal is None:
        return (
            '<section class="warnings"><p>No recall guarantee was requested. '
            "Selection size is controlled by top-k and budget only.</p></section>"
        )
    if not conformal.guarantee_attainable:
        return (
            '<section class="warnings"><p><strong>No recall guarantee is in '
            f"force.</strong> A target risk of {_fmt_percent(conformal.target_risk)}% "
            f"needs more calibration applications than the "
            f"{_fmt_number(conformal.calibration_groups)} available, so every "
            "candidate above threshold 0 was kept.</p></section>"
        )
    covered = (
        "the budget covers it"
        if outcome.budget_covers_conformal_set
        else "<strong>the budget does not cover it, so the guarantee does not "
        "hold for this run</strong>"
    )
    return (
        '<section class="warnings"><p>'
        f"Recall guarantee: at least "
        f"{_fmt_percent(1.0 - conformal.target_risk)}% of true findings are "
        f"expected to survive the cut at probability "
        f"{conformal.threshold:.4f}, calibrated on "
        f"{_fmt_number(conformal.calibration_groups)} applications. The guaranteed "
        f"set holds {_fmt_number(outcome.conformal_set_size)} candidates and "
        f"{covered}.</p></section>"
    )


def _render_warnings(warnings: Sequence[str]) -> str:
    if not warnings:
        return ""
    items = "\n".join(f"  <li>{_esc(warning)}</li>" for warning in warnings)
    return f'<section class="warnings">\n<ul>\n{items}\n</ul>\n</section>'


def _render_selected(
    outcome: DecisionOutcome,
    *,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    probabilities: Mapping[str, CalibratedProbability],
) -> str:
    selected = outcome.selection.selected
    if not selected:
        return (
            '<section class="warnings"><p>No candidate was selected. Either the '
            "constraints left no room or no candidate carried observed "
            "evidence.</p></section>"
        )
    rows = "\n".join(
        _render_candidate(
            candidate,
            order=order,
            input_points=input_points,
            endpoints=endpoints,
            calibrated=probabilities.get(candidate.candidate_id),
        )
        for order, candidate in enumerate(selected, start=1)
    )
    return f'<section class="candidates">\n{rows}\n</section>'


def _render_candidate(
    candidate: Any,
    *,
    order: int,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
    calibrated: CalibratedProbability | None,
) -> str:
    probability = float(candidate.probability)
    band = _band(probability)
    location = _location(candidate, input_points, endpoints)
    facts = (
        ("probability", f"{probability:.4f}"),
        ("severity", _fmt_number(candidate.severity)),
        ("requests", _fmt_number(candidate.verification_cost)),
        ("expected value", f"{candidate.expected_value:.2f}"),
    )
    fact_html = "".join(
        f'<span class="chip"><b>{_esc(label)}</b> {_esc(value)}</span>'
        for label, value in facts
    )
    return (
        f'<article class="cand {band}">\n'
        f'  <div class="cand-head">\n'
        f'    <span class="rank">#{order}</span>\n'
        f'    <span class="vt">{_esc(candidate.family)}</span>\n'
        f'    <span class="loc">{_esc(location)}</span>\n'
        f'    <span class="score">{_fmt_percent(probability)}%</span>\n'
        f"  </div>\n"
        f'  <div class="chips">{fact_html}</div>\n'
        f"{_render_evidence(calibrated)}"
        f"</article>"
    )


def _render_evidence(calibrated: CalibratedProbability | None) -> str:
    """Why the model believes this, feature by feature.

    Shows unobserved features too. A reader must be able to tell "checked and
    absent" from "never measured" -- conflating them is the mistake the feature
    schema exists to prevent.
    """

    if calibrated is None:
        return ""
    rows = []
    for item in calibrated.evidence:
        if item.observed:
            value = _fmt_number(item.feature_value or 0.0)
            contribution = f"{item.logit_contribution or 0.0:+.3f}"
            state = "obs"
        else:
            value = "not observed"
            contribution = "—"
            state = "missing"
        rows.append(
            f'    <tr class="{state}"><td>{_esc(item.feature_name)}</td>'
            f"<td>{_esc(value)}</td><td>{_esc(contribution)}</td></tr>"
        )
    return (
        '  <table class="evidence">\n'
        "    <tr><th>feature</th><th>value</th><th>logit</th></tr>\n"
        + "\n".join(rows)
        + "\n  </table>\n"
    )


def _render_deferred(
    outcome: DecisionOutcome,
    *,
    input_points: Mapping[str, InputPoint],
    endpoints: Mapping[str, Endpoint],
) -> str:
    deferred = outcome.selection.deferred
    if not deferred:
        return ""
    rows = "\n".join(
        f"    <tr><td>{_esc(_location(candidate, input_points, endpoints))}</td>"
        f"<td>{_esc(candidate.family)}</td>"
        f"<td>{float(candidate.probability):.4f}</td>"
        f"<td>{_fmt_number(candidate.verification_cost)}</td></tr>"
        for candidate in sorted(
            deferred, key=lambda item: (-float(item.probability), item.candidate_id)
        )
    )
    return (
        f'<h2 class="section">Not selected ({len(deferred)})</h2>\n'
        '<section class="unrankable">\n  <table class="evidence">\n'
        "    <tr><th>location</th><th>family</th><th>probability</th>"
        "<th>requests</th></tr>\n"
        f"{rows}\n  </table>\n</section>"
    )


def _render_footer(elapsed_seconds: float, selector_version: str) -> str:
    return (
        '<footer class="foot">'
        f"{_esc(DECISION_HTML_REPORT_VERSION)} &middot; "
        f"{_esc(selector_version)} &middot; "
        f"{elapsed_seconds:.2f}s &middot; "
        "probabilities are pre-verification priorities, not confirmed findings"
        "</footer>"
    )
