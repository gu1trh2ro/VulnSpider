"""Local fine-tuned LLM payload proposer (LLM-assisted focused verification).

This is the real-model drop-in for the provider-neutral
:class:`~vulnspider.verification.proposal.PayloadProposer` boundary. Where
:class:`~vulnspider.verification.proposal.DeterministicMutationProposer` emits a
fixed, allowlisted variant set, this proposer asks the locally hosted,
fine-tuned ``vulnspider-3b`` GGUF model (Seokhyeon's ``payload_verifier``
module, run through ``llama-cpp-python``) to *suggest* same-family variant
values, then maps each suggestion onto a
:class:`~vulnspider.verification.proposal.PayloadProposal`.

The safety boundary is unchanged and non-negotiable (`docs/PROTOTYPE_V0_2.md`
§4.3, `AGENTS.md`): **model output is untrusted input**. Nothing this proposer
returns reaches the network until the deterministic
:class:`~vulnspider.verification.validator.PayloadValidator` accepts it, and the
orchestrator -- not the model -- owns the transport, the loopback guard, the
prior, and the final confidence number. This class only replaces *which values
are suggested*; every downstream gate stays in force.

The prompt is kept byte-for-byte compatible with the format the model was
fine-tuned on (`payload_verifier_v2/generate_dataset.py`): the trained system
prompt plus a minimal candidate JSON (candidate id, vulnerability type, and the
one request-context the proposer is allowed to see). The model has internalised
the per-type rules, so the deterministic ``(Assume Type-specific rules are
applied here)`` sentinel from training is reused verbatim rather than re-sending
the full rule text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from vulnspider.domain import InputLocation, VulnerabilityType
from vulnspider.verification.proposal import (
    MutationFamily,
    MutationProposalError,
    MutationSubject,
    PayloadProposal,
)

PROVIDER_LOCAL_LLM = "local-llm-vulnspider-3b"
LLM_PROPOSER_VERSION = "local-llm-mutation-v1"

# Environment variable the CLI consults for the GGUF model path when
# ``--llm-model`` is not given.
LLM_MODEL_PATH_ENV = "VULNSPIDER_LLM_MODEL"

# Defaults mirror the active ``LocalPayloadMutator`` in ``payload_verifier`` and
# the model's ``Modelfile`` (``num_ctx 4096``, ``temperature 0.1``).
DEFAULT_N_CTX = 4096
DEFAULT_N_GPU_LAYERS = -1
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_TOKENS = 2048
DEFAULT_MAX_RETRIES = 3

# Upper bound on how many suggestions we turn into proposals for one candidate.
# The model emits 3 (XSS) or 4 (SQLi) by design; the cap only guards against a
# model that ignores its instructions and floods the validator.
MAX_LLM_PROPOSALS = 6

# The only families this proposer maps onto, keyed by the two vulnerability
# types the focused-verification proposer path handles (BAC has its own module).
# The validator independently enforces this same family/type table.
_FAMILY_FOR_TYPE: dict[VulnerabilityType, MutationFamily] = {
    VulnerabilityType.SQLI: MutationFamily.SQL_META,
    VulnerabilityType.REFLECTED_XSS: MutationFamily.HTML_SENTINEL,
}

# Trained system prompt, vendored verbatim from
# ``payload_verifier_v2/src/payload_verifier/prompts.py`` (``SYSTEM_PROMPT``) so
# the merged pipeline needs only the GGUF model and ``llama-cpp-python`` -- not
# the standalone experimental package -- at run time. Keep in sync if the model
# is retrained on a new system prompt.
SYSTEM_PROMPT = (
    "You are a defensive payload mutation component for an\n"
    "authorized web security verification pipeline.\n\n"
    "Generate only safe and non-destructive verification values.\n\n"
    "Never generate payloads that:\n"
    "- modify, delete, insert, or extract data\n"
    "- use stacked SQL queries\n"
    "- use UNION-based SQL extraction\n"
    "- use time-delay SQL functions\n"
    "- execute JavaScript\n"
    "- access cookies, localStorage, or sessionStorage\n"
    "- load external resources\n"
    "- create destructive HTTP requests\n"
    "- invent resource identifiers\n"
    "- invent authorization contexts\n"
    "- modify the target host\n"
    "- modify the target path\n"
    "- modify the HTTP method\n\n"
    "The application code will insert your generated value into\n"
    "the exact input position.\n\n"
    "Return JSON only."
)

_TRAINING_RULES_SENTINEL = "(Assume Type-specific rules are applied here)"


class LlamaChatClient(Protocol):
    """The subset of ``llama_cpp.Llama`` this proposer calls.

    Declared as a Protocol so a fake client can be injected in tests without
    loading a multi-gigabyte model or importing ``llama_cpp``.
    """

    def create_chat_completion(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> dict[str, Any]:
        ...


class LLMProposerError(MutationProposalError):
    """Raised when the local model cannot be loaded or driven honestly."""


def build_candidate_prompt(subject: MutationSubject) -> dict[str, Any]:
    """Build the minimal candidate JSON the model was fine-tuned to read.

    Mirrors ``payload_verifier_v2/generate_dataset.py``: the key order and the
    ``request_context`` shape are the ones the model saw in training. Only the
    fields a proposer is allowed to know are populated; the URL is a loopback
    placeholder that never reaches the network (the orchestrator builds the real
    request from the retained baseline ``RequestInstance``).
    """

    location = InputLocation(subject.parameter_location)
    method = "GET" if location == InputLocation.QUERY else "POST"
    original_value = subject.baseline_value
    if location == InputLocation.QUERY:
        url = f"http://127.0.0.1/test?{subject.parameter_name}={original_value or ''}"
    else:
        url = "http://127.0.0.1/test"
    return {
        "candidate_id": subject.candidate_id,
        "vulnerability_type": VulnerabilityType(subject.vulnerability_type).value,
        "metadata": {},
        "request_context": {
            "method": method,
            "url": url,
            "parameter_name": subject.parameter_name,
            "parameter_location": location.value.lower(),
            "original_value": original_value,
        },
        "access_context": None,
    }


def build_user_prompt(subject: MutationSubject) -> str:
    """The trained user message: the minimal candidate plus the rules sentinel."""

    candidate_json = json.dumps(build_candidate_prompt(subject), indent=2)
    return (
        "Generate safe verification values for the following candidate.\n\n"
        f"Candidate:\n{candidate_json}\n\n"
        f"{_TRAINING_RULES_SENTINEL}"
    )


def _extract_json_object(content: str) -> dict[str, Any]:
    """Parse the model response, tolerating stray text around the JSON object."""

    text = content.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(text[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("model response was not a JSON object")
    return parsed


def map_payloads_to_proposals(
    subject: MutationSubject,
    payloads: list[dict[str, Any]],
) -> tuple[PayloadProposal, ...]:
    """Turn the model's ``payloads`` array into validated-candidate proposals.

    Each suggested ``value`` becomes one :class:`PayloadProposal` in the single
    family allowed for the candidate type. A reflected-XSS suggestion carries
    its own value as the reflection marker so the reused feature extractor can
    attribute a reflection to it; a SQLi suggestion carries no marker. Entries
    without a usable string value are dropped -- the model occasionally emits a
    null-valued row, which cannot be sent.
    """

    family = _FAMILY_FOR_TYPE.get(VulnerabilityType(subject.vulnerability_type))
    if family is None:
        return ()
    is_reflection = family == MutationFamily.HTML_SENTINEL
    proposals: list[PayloadProposal] = []
    for payload in payloads:
        if len(proposals) >= MAX_LLM_PROPOSALS:
            break
        if not isinstance(payload, dict):
            continue
        value = payload.get("value")
        if not isinstance(value, str) or not value:
            continue
        rationale = payload.get("rationale")
        if not isinstance(rationale, str) or not rationale:
            rationale = "Local model suggested a same-family verification value."
        kind = payload.get("kind")
        if isinstance(kind, str) and kind:
            rationale = f"[{kind}] {rationale}"
        proposals.append(
            PayloadProposal(
                candidate_id=subject.candidate_id,
                input_point_id=subject.input_point_id,
                vulnerability_type=subject.vulnerability_type,
                family=family,
                variant_index=len(proposals),
                mutated_value=value,
                based_on_value=subject.baseline_value,
                reflection_marker=value if is_reflection else None,
                rationale=rationale,
                provider=PROVIDER_LOCAL_LLM,
                proposer_version=LLM_PROPOSER_VERSION,
            )
        )
    return tuple(proposals)


@dataclass
class LocalLLMMutationProposer:
    """PayloadProposer backed by the local fine-tuned ``vulnspider-3b`` GGUF.

    The model is loaded lazily on the first :meth:`propose` call (or eagerly by
    passing an already-built ``llm``), so importing this module never pulls in
    ``llama_cpp`` and constructing the proposer is cheap. A proposal round that
    fails (model error, empty output, unparseable JSON) degrades to *no
    proposals* for that candidate rather than raising: the orchestrator then
    records the candidate as not-executed and keeps its prior, exactly as it
    would for a candidate the deterministic proposer could not mutate.
    """

    model_path: str | None = None
    n_ctx: int = DEFAULT_N_CTX
    n_gpu_layers: int = DEFAULT_N_GPU_LAYERS
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_retries: int = DEFAULT_MAX_RETRIES
    verbose: bool = False
    llm: LlamaChatClient | None = None
    _warnings: list[str] = field(default_factory=list, init=False, repr=False)

    @property
    def warnings(self) -> tuple[str, ...]:
        """Non-fatal issues seen during the most recent proposals, for the log."""

        return tuple(self._warnings)

    def _ensure_llm(self) -> LlamaChatClient:
        if self.llm is not None:
            return self.llm
        if not self.model_path:
            raise LLMProposerError(
                "no local model available: pass model_path (the vulnspider-3b "
                f"GGUF) or set ${LLM_MODEL_PATH_ENV}"
            )
        try:
            from llama_cpp import Llama
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise LLMProposerError(
                "llama-cpp-python is not installed; install it and the "
                "vulnspider-3b GGUF to use the local LLM proposer"
            ) from exc
        try:
            self.llm = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_gpu_layers=self.n_gpu_layers,
                verbose=self.verbose,
            )
        except Exception as exc:  # pragma: no cover - environment dependent
            raise LLMProposerError(
                f"could not load local GGUF model at {self.model_path}: {exc}"
            ) from exc
        return self.llm

    def propose(self, subject: MutationSubject) -> tuple[PayloadProposal, ...]:
        if not isinstance(subject, MutationSubject):
            raise LLMProposerError("subject must be a MutationSubject")
        self._warnings = []
        if VulnerabilityType(subject.vulnerability_type) not in _FAMILY_FOR_TYPE:
            return ()
        llm = self._ensure_llm()
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(subject)},
        ]
        for attempt in range(1, self.max_retries + 1):
            try:
                response = llm.create_chat_completion(
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                content = response["choices"][0]["message"]["content"]
                if not content:
                    raise ValueError("model returned an empty response")
                parsed = _extract_json_object(content)
                raw_payloads = parsed.get("payloads")
                if not isinstance(raw_payloads, list) or not raw_payloads:
                    raise ValueError("model returned no payloads")
                proposals = map_payloads_to_proposals(subject, raw_payloads)
                if not proposals:
                    raise ValueError("model payloads carried no usable values")
                return proposals
            except Exception as exc:  # noqa: BLE001 - degrade, don't crash the run
                self._warnings.append(
                    f"attempt {attempt}/{self.max_retries} failed: {exc}"
                )
                continue
        return ()
