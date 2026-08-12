"""CLI surface for the decision layer and the labeled corpus.

Kept out of ``cli.py`` deliberately. ``AGENTS.md`` freezes the v0.1 command
surface, and ADR-025 adds commands rather than changing `analyze`, `-u`, or any
of their flags. This module owns the new subcommands and the glue that turns a
live ``AnalysisResult`` into decision-layer input.

The glue never reconstructs anything. It holds the in-memory analysis and walks
the same authoritative path a consumer would: rank through ``select_top_k`` and
``select_combined_top_k``, project through ``build_mutation_handoff``, and read
features from the ``FeatureVector`` the pipeline actually produced.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from vulnspider.access.selection import select_top_k_access
from vulnspider.corpus.collection import (
    CollectionResult,
    CorpusError,
    append_corpus,
    collect_labeled_samples,
    read_corpus,
    write_corpus,
)
from vulnspider.corpus.fitting import (
    CorpusFittingError,
    calibrate_from_corpus,
    evaluate_calibration,
    fit_family_scorers,
    out_of_fold_predictions,
    prior_family_scorers,
    scorers_as_mapping,
    scorers_from_mapping,
)
from vulnspider.corpus.ground_truth import GroundTruthError, read_ground_truth
from vulnspider.decision.candidate import (
    DecisionCandidate,
    decision_candidate_from_context,
)
from vulnspider.decision.conformal import ConformalError, ConformalThreshold
from vulnspider.decision.cost import SeverityPolicy, VerificationCostPolicy
from vulnspider.decision.policy import DecisionOutcome, run_decision_layer
from vulnspider.domain import stable_fingerprint
from vulnspider.pipeline import AnalysisResult
from vulnspider.scoring.calibration import CalibratedScorer, CalibrationError
from vulnspider.selection import (
    build_mutation_handoff,
    select_combined_top_k,
    select_top_k,
)

DECISION_REPORT_VERSION = "decision-report-v1"

DEFAULT_TOP_K = 10
DEFAULT_TARGET_RISK = 0.1
DEFAULT_DISCOUNT = 0.5

# Families the injection pipeline can currently produce candidates for. BAC
# has a scorer but no observation pipeline yet (ADR-014), so it never appears
# in an AnalysisResult and is deliberately not listed.
_FAMILIES = ("SQLI", "REFLECTED_XSS")


class DecisionCLIError(ValueError):
    """Raised for user-facing decision or corpus command errors."""


def build_decision_candidates(
    analysis: AnalysisResult,
    scorers: Mapping[str, CalibratedScorer],
    *,
    cost_policy: VerificationCostPolicy | None = None,
    severity_policy: SeverityPolicy | None = None,
) -> tuple[DecisionCandidate, ...]:
    """Project one analysis into decision-layer candidates.

    Every candidate the scoring layer produced is ranked -- not just a Top-K --
    because choosing how many to verify is the decision layer's job, not a
    parameter it inherits. Candidates with no observed evidence stay unrankable
    and get no budget, which is the same rule ``select_top_k`` already applies.

    ``redundancy_key`` is the endpoint fingerprint, so diminishing returns apply
    across input points that share a route rather than only across the two
    readings of one input point.
    """

    results = analysis.scoring_results
    if not results:
        return ()

    rank_all = len(results)
    injection = select_top_k(results, k=rank_all)
    access = select_top_k_access((), k=rank_all)
    combined = select_combined_top_k(injection, access, k=rank_all)
    handoff = build_mutation_handoff(
        combined,
        selection_run_id=_selection_run_id(analysis),
    )

    vectors = {vector.id or "": vector for vector in analysis.feature_vectors}
    endpoint_by_point = {
        point.id or "": point.endpoint_fingerprint
        for point in analysis.input_points
    }

    candidates: list[DecisionCandidate] = []
    for context in handoff.contexts:
        scorer = scorers.get(context.family)
        if scorer is None:
            raise DecisionCLIError(
                f"no calibrated model for family {context.family!r}"
            )
        vector = vectors.get(context.feature_vector_id or "")
        if vector is None:
            raise DecisionCLIError(
                f"analysis has no feature vector {context.feature_vector_id!r}"
            )
        candidates.append(
            decision_candidate_from_context(
                context,
                scorer.probability(vector.features),
                cost_policy=cost_policy,
                severity_policy=severity_policy,
                redundancy_key=endpoint_by_point.get(context.candidate_subject_ref),
            )
        )
    return tuple(candidates)


def decision_report(
    outcome: DecisionOutcome,
    *,
    target_url: str,
    models: Mapping[str, CalibratedScorer],
) -> dict[str, Any]:
    """Serialize a decision outcome without recomputing any of it."""

    return {
        "report_version": DECISION_REPORT_VERSION,
        "target": target_url,
        "policy_version": outcome.policy_version,
        "models": {
            family: {
                "model_version": scorer.model_version,
                "training_samples": scorer.training_samples,
            }
            for family, scorer in sorted(models.items())
        },
        "constraints": {
            "top_k": outcome.selection.top_k,
            "verification_budget": outcome.selection.budget,
            "binding_constraint": outcome.selection.binding_constraint,
            "verification_spent": outcome.selection.spent_cost,
            "exploration_spent": outcome.exploration_requests_spent,
            "total_requests": outcome.total_requests_spent,
        },
        "guarantee": (
            None
            if outcome.conformal is None
            else {
                **outcome.conformal.as_mapping(),
                "conformal_set_size": outcome.conformal_set_size,
                "budget_covers_conformal_set": outcome.budget_covers_conformal_set,
            }
        ),
        "selection": {
            "selector_version": outcome.selection.selector_version,
            "candidates_scored": outcome.initial_candidates,
            "selected": len(outcome.selection.selected),
            "deferred": len(outcome.selection.deferred),
            "utility": outcome.selection.utility,
            "expected_findings": outcome.selection.expected_findings,
            "approximation_ratio": outcome.selection.approximation_ratio,
            "discount": outcome.selection.discount,
        },
        "verification_order": [
            {
                "order": position,
                "candidate_id": candidate.candidate_id,
                "family": candidate.family,
                "probability": candidate.probability,
                "severity": candidate.severity,
                "verification_cost": candidate.verification_cost,
                "selection_rank": candidate.selection_rank,
            }
            for position, candidate in enumerate(
                outcome.selection.selected, start=1
            )
        ],
        "information_gains": [
            {
                "probe_id": gain.probe_id,
                "candidate_id": gain.candidate_id,
                "prior_probability": gain.prior_probability,
                "expected_information_gain_bits": gain.expected_information_gain,
                "information_density": gain.information_density,
                "request_cost": gain.request_cost,
            }
            for gain in outcome.information_gains
        ],
    }


def collect_from_analysis(
    analysis: AnalysisResult,
    *,
    application_id: str,
    ground_truth_path: Path,
) -> CollectionResult:
    """Join one analysis run's observed features to ground truth."""

    ground_truth = read_ground_truth(ground_truth_path)
    scored = tuple(
        (
            result.candidate.input_point_id,
            result.feature_vector_id,
            result.candidate.vulnerability_type.value,
        )
        for result in analysis.scoring_results
    )
    return collect_labeled_samples(
        application_id=application_id,
        endpoints=analysis.endpoints,
        input_points=analysis.input_points,
        feature_vectors=analysis.feature_vectors,
        scored_candidates=scored,
        ground_truth=ground_truth,
    )


def load_models(path: Path | None, families: Sequence[str]) -> dict[
    str, CalibratedScorer
]:
    """Load fitted models, or fall back to the heuristic prior."""

    if path is None:
        return prior_family_scorers(families)
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        raise DecisionCLIError(f"{path} must contain a JSON object")
    return scorers_from_mapping(payload)


def load_conformal(path: Path | None) -> ConformalThreshold | None:
    """Load a calibrated conformal threshold, if one was supplied."""

    if path is None:
        return None
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        raise DecisionCLIError(f"{path} must contain a JSON object")
    return ConformalThreshold.from_mapping(payload)


def add_decision_subcommands(subparsers: argparse._SubParsersAction) -> None:
    """Register `decide` and `corpus` on the existing parser."""

    decide = subparsers.add_parser(
        "decide",
        help="Rank, budget, and cut candidates for an authorized target.",
        description=(
            "Run the analysis pipeline for an authorized localhost or loopback "
            "target, then allocate a verification request budget across the "
            "resulting candidates using the calibrated decision layer."
        ),
    )
    decide.add_argument("--url", required=True, help="Authorized target root URL.")
    decide.add_argument(
        "--top-k",
        required=True,
        type=int,
        help="Number of candidates to select. The primary control.",
    )
    decide.add_argument(
        "--budget",
        type=int,
        default=None,
        help=(
            "Optional verification request budget. Candidates cost different "
            "amounts, so this caps request spend rather than list length; "
            "whichever limit binds first stops the selection."
        ),
    )
    decide.add_argument(
        "--discount",
        type=float,
        default=DEFAULT_DISCOUNT,
        help=(
            "Per-endpoint diminishing-returns factor in (0, 1]; 1.0 disables "
            f"redundancy modelling (default: {DEFAULT_DISCOUNT})."
        ),
    )
    decide.add_argument(
        "--model",
        type=Path,
        default=None,
        help="Fitted model JSON from 'corpus fit' (default: heuristic prior).",
    )
    decide.add_argument(
        "--conformal",
        type=Path,
        default=None,
        help="Calibrated threshold JSON from 'corpus calibrate'.",
    )
    decide.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Decision report JSON destination.",
    )
    _add_crawl_bounds(decide)

    corpus = subparsers.add_parser(
        "corpus",
        help="Collect a labeled corpus, fit models, calibrate the guarantee.",
        description=(
            "Build the labeled corpus the calibrated scorer and the conformal "
            "guarantee are estimated from."
        ),
    )
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)

    collect = corpus_commands.add_parser(
        "collect",
        help="Run one authorized target and append labeled samples.",
    )
    collect.add_argument("--url", required=True, help="Authorized target root URL.")
    collect.add_argument(
        "--application-id",
        required=True,
        help="Group key for this application (leakage control unit).",
    )
    collect.add_argument(
        "--ground-truth",
        type=Path,
        required=True,
        help="Ground truth JSON for this application.",
    )
    collect.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Corpus JSON Lines destination.",
    )
    collect.add_argument(
        "--append",
        action="store_true",
        help="Append to an existing corpus instead of overwriting it.",
    )
    _add_crawl_bounds(collect)

    fit = corpus_commands.add_parser(
        "fit",
        help="Fit one calibrated model per family from a corpus.",
    )
    fit.add_argument("--corpus", type=Path, required=True, help="Corpus JSONL.")
    fit.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Fitted model JSON destination.",
    )
    fit.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional out-of-fold calibration quality report destination.",
    )

    calibrate = corpus_commands.add_parser(
        "calibrate",
        help="Calibrate the conformal recall threshold from a corpus.",
    )
    calibrate.add_argument(
        "--corpus", type=Path, required=True, help="Corpus JSONL."
    )
    calibrate.add_argument(
        "--target-recall",
        type=float,
        default=1.0 - DEFAULT_TARGET_RISK,
        help=(
            "Recall to guarantee, in (0, 1) "
            f"(default: {1.0 - DEFAULT_TARGET_RISK})."
        ),
    )
    calibrate.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Calibrated threshold JSON destination.",
    )


def run_decide_command(
    args: argparse.Namespace,
    *,
    transport: Any = None,
    crawler: Any = None,
    crawler_transport: Any = None,
) -> int:
    """Handle `vulnspider decide`."""

    if args.top_k < 0:
        raise DecisionCLIError("--top-k must not be negative")
    if args.budget is not None and args.budget < 0:
        raise DecisionCLIError("--budget must not be negative")
    if not 0.0 < args.discount <= 1.0:
        raise DecisionCLIError("--discount must lie inside (0, 1]")

    analysis = _analyze(
        args,
        transport=transport,
        crawler=crawler,
        crawler_transport=crawler_transport,
    )
    models = load_models(args.model, _FAMILIES)
    conformal = load_conformal(args.conformal)
    candidates = build_decision_candidates(analysis, models)
    outcome = run_decision_layer(
        candidates,
        top_k=args.top_k,
        verification_budget=args.budget,
        conformal=conformal,
        discount=args.discount,
    )
    write_json(
        decision_report(outcome, target_url=args.url, models=models),
        args.output,
    )
    spend = (
        f"{outcome.selection.spent_cost} requests"
        if args.budget is None
        else f"{outcome.selection.spent_cost}/{args.budget} requests"
    )
    print(
        f"vulnspider: selected {len(outcome.selection.selected)} of "
        f"{outcome.initial_candidates} candidates "
        f"(top-k {args.top_k}, {spend}, "
        f"expected findings {outcome.selection.expected_findings:.2f}, "
        f"limited by {outcome.selection.binding_constraint})"
    )
    if conformal is not None and not outcome.budget_covers_conformal_set:
        print(
            "vulnspider: warning: budget does not cover the conformal set of "
            f"{outcome.conformal_set_size}; the recall guarantee does not hold",
        )
    print(f"vulnspider: decision report: {args.output}")
    return 0


def run_corpus_command(
    args: argparse.Namespace,
    *,
    transport: Any = None,
    crawler: Any = None,
    crawler_transport: Any = None,
) -> int:
    """Handle `vulnspider corpus {collect,fit,calibrate}`."""

    if args.corpus_command == "collect":
        return _run_corpus_collect(
            args,
            transport=transport,
            crawler=crawler,
            crawler_transport=crawler_transport,
        )
    if args.corpus_command == "fit":
        return _run_corpus_fit(args)
    if args.corpus_command == "calibrate":
        return _run_corpus_calibrate(args)
    raise DecisionCLIError(f"unsupported corpus command: {args.corpus_command}")


def _run_corpus_collect(
    args: argparse.Namespace,
    *,
    transport: Any,
    crawler: Any,
    crawler_transport: Any,
) -> int:
    analysis = _analyze(
        args,
        transport=transport,
        crawler=crawler,
        crawler_transport=crawler_transport,
    )
    result = collect_from_analysis(
        analysis,
        application_id=args.application_id,
        ground_truth_path=args.ground_truth,
    )
    written = (
        append_corpus(result.samples, args.output)
        if args.append
        else write_corpus(result.samples, args.output)
    )
    print(
        f"vulnspider: collected {written} labeled samples for "
        f"{args.application_id} ({result.positives} vulnerable, "
        f"{result.negatives} safe)"
    )
    if result.unlabeled_keys:
        print(
            f"vulnspider: warning: {len(result.unlabeled_keys)} discovered "
            "candidates have no ground truth entry and were skipped"
        )
        for key in result.unlabeled_keys[:10]:
            print(
                f"  unlabeled: {key.method} {key.canonical_path} "
                f"{key.parameter_location}:{key.parameter_name} "
                f"{key.vulnerability_type}"
            )
    if result.unrankable_candidates:
        print(
            f"vulnspider: {result.unrankable_candidates} candidates had no "
            "observed feature and were not collected"
        )
    print(f"vulnspider: corpus: {args.output}")
    return 0


def _run_corpus_fit(args: argparse.Namespace) -> int:
    dataset = read_corpus(args.corpus)
    if not dataset.samples:
        raise DecisionCLIError(f"{args.corpus} contains no samples")
    scorers = fit_family_scorers(dataset)
    if not scorers:
        raise DecisionCLIError("corpus contains no family with a known prior")
    write_json(scorers_as_mapping(scorers), args.output)

    counts = dataset.counts()
    print(
        f"vulnspider: fitted {len(scorers)} family models from "
        f"{counts['samples']} samples across {counts['groups']} applications "
        f"({counts['positives']} vulnerable, {counts['negatives']} safe)"
    )
    for family, scorer in sorted(scorers.items()):
        weights = ", ".join(
            f"{name}={weight:+.3f}"
            for name, weight in zip(
                scorer.feature_space.feature_names,
                scorer.weights,
                strict=True,
            )
        )
        print(f"  {family}: intercept={scorer.intercept:+.3f} {weights}")

    if args.report is not None:
        if len(dataset.groups) < 2:
            raise DecisionCLIError(
                "a calibration report needs at least two applications"
            )
        report = evaluate_calibration(out_of_fold_predictions(dataset))
        write_json(report.as_mapping(), args.report)
        print(
            f"vulnspider: out-of-fold Brier={report.brier_score:.4f} "
            f"ECE={report.expected_calibration_error:.4f} "
            f"({report.samples} predictions)"
        )
        print(f"vulnspider: calibration report: {args.report}")
    print(f"vulnspider: model: {args.output}")
    return 0


def _run_corpus_calibrate(args: argparse.Namespace) -> int:
    if not 0.0 < args.target_recall < 1.0:
        raise DecisionCLIError("--target-recall must lie strictly inside (0, 1)")
    dataset = read_corpus(args.corpus)
    if len(dataset.groups) < 2:
        raise DecisionCLIError(
            "conformal calibration needs at least two applications"
        )
    threshold = calibrate_from_corpus(
        dataset,
        target_risk=1.0 - args.target_recall,
    )
    write_json(threshold.as_mapping(), args.output)

    if threshold.guarantee_attainable:
        print(
            f"vulnspider: threshold={threshold.threshold:.4f} guarantees "
            f"recall >= {args.target_recall:.2f} "
            f"(empirical risk {threshold.empirical_risk:.4f} <= "
            f"{threshold.corrected_risk_bound:.4f}, "
            f"{threshold.calibration_groups} applications)"
        )
    else:
        needed = int(1.0 / (1.0 - args.target_recall)) - 1
        print(
            f"vulnspider: warning: recall {args.target_recall:.2f} cannot be "
            f"certified with {threshold.calibration_groups} applications; "
            f"at least {needed} are required. Selecting everything instead."
        )
    print(f"vulnspider: conformal threshold: {args.output}")
    return 0


def _analyze(
    args: argparse.Namespace,
    *,
    transport: Any,
    crawler: Any,
    crawler_transport: Any,
) -> AnalysisResult:
    from vulnspider.discovery import CrawlPolicy
    from vulnspider.pipeline import analyze_url

    defaults = CrawlPolicy()
    policy = CrawlPolicy(
        max_pages=defaults.max_pages if args.max_pages is None else args.max_pages,
        max_depth=defaults.max_depth if args.max_depth is None else args.max_depth,
        max_requests=(
            defaults.max_requests
            if args.max_requests is None
            else args.max_requests
        ),
    )
    return analyze_url(
        args.url,
        top_k=1,
        crawl_policy=policy,
        crawler=crawler,
        crawler_transport=crawler_transport,
        transport=transport,
    )


def _add_crawl_bounds(parser: argparse.ArgumentParser) -> None:
    """Discovery bounds. `top_k` is deliberately absent: how many candidates to
    verify is what the decision layer computes, not something it is told."""

    parser.add_argument(
        "--max-pages", type=int, default=None, help="Maximum pages to crawl."
    )
    parser.add_argument(
        "--max-depth", type=int, default=None, help="Maximum crawl depth."
    )
    parser.add_argument(
        "--max-requests", type=int, default=None, help="Maximum crawl requests."
    )


def _selection_run_id(analysis: AnalysisResult) -> str:
    fingerprint = stable_fingerprint(
        "decision-selection-run",
        str(len(analysis.scoring_results)),
        *sorted(vector.id or "" for vector in analysis.feature_vectors),
    )
    return f"sel_{fingerprint[:16]}"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DecisionCLIError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise DecisionCLIError(f"{path} is not valid JSON: {exc}") from exc


def write_json(payload: Mapping[str, Any], path: Path) -> None:
    """Write a decision or corpus artifact as indented JSON."""

    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


__all__ = [
    "DECISION_REPORT_VERSION",
    "DEFAULT_DISCOUNT",
    "DEFAULT_TARGET_RISK",
    "DEFAULT_TOP_K",
    "ConformalError",
    "CorpusError",
    "CorpusFittingError",
    "DecisionCLIError",
    "GroundTruthError",
    "CalibrationError",
    "add_decision_subcommands",
    "build_decision_candidates",
    "calibrate_from_corpus",
    "collect_from_analysis",
    "decision_report",
    "evaluate_calibration",
    "fit_family_scorers",
    "load_conformal",
    "load_models",
    "out_of_fold_predictions",
    "read_corpus",
    "run_decision_layer",
    "append_corpus",
    "write_corpus",
    "scorers_as_mapping",
    "write_json",
]
