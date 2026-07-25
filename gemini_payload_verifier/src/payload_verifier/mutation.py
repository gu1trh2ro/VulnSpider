from __future__ import annotations
import json, uuid
from collections import Counter
from .models import Candidate, VerificationGroup, VulnerabilityType

def _rules(c: Candidate) -> str:
    common = "Generate exactly 3 or 4 non-destructive candidates. Return only schema JSON."
    if c.vulnerability_type == VulnerabilityType.SQLI:
        return common + """
SQLI: exactly 4 payloads: 2 true_condition and 2 false_condition.
Use boolean/behavior comparison only. No comments, UNION, time delay, stacked query,
data extraction or modification."""
    if c.vulnerability_type == VulnerabilityType.XSS:
        return common + """
XSS: exactly 3 payloads: 1 control and 2 reflection_marker.
Markers must contain xss-probe and be inert. No script, event handler, javascript URL,
external URL, SVG/iframe, cookie/storage access, or executable browser code."""
    return common + """
BAC: exactly 4 payloads: 1 authorization_control and 3 authorization_variant.
payload must come from resources[].value and auth_context_id from auth_contexts[].context_id.
Include same-role/different-resource and different-role/restricted-resource comparisons.
Never invent IDs, roles, users, tokens, cookies or headers."""

def _shape(c: Candidate, g: VerificationGroup) -> None:
    roles = Counter(x.payload_role for x in g.payloads)
    ok = (
        c.vulnerability_type == VulnerabilityType.SQLI and len(g.payloads)==4 and roles["true_condition"]==2 and roles["false_condition"]==2
    ) or (
        c.vulnerability_type == VulnerabilityType.XSS and len(g.payloads)==3 and roles["control"]==1 and roles["reflection_marker"]==2
    ) or (
        c.vulnerability_type == VulnerabilityType.BAC and len(g.payloads)==4 and roles["authorization_control"]==1 and roles["authorization_variant"]==3
    )
    if not ok:
        raise ValueError("Gemini output does not match required 3~4 payload role composition.")

class PayloadMutationService:
    def __init__(self, llm): self.llm=llm
    def mutate(self, candidate: Candidate) -> VerificationGroup:
        prompt = _rules(candidate) + "\nCandidate:\n" + json.dumps(candidate.model_dump(mode="json"),ensure_ascii=False,indent=2)
        group = VerificationGroup.model_validate(self.llm.generate(prompt, VerificationGroup))
        group.candidate_id=candidate.candidate_id
        group.vulnerability_type=candidate.vulnerability_type
        group.target.parameter_name=candidate.request_context.parameter_name
        group.target.parameter_location=candidate.request_context.parameter_location
        group.target.parameter_occurrence=candidate.request_context.parameter_occurrence
        group.verification_type={
            VulnerabilityType.SQLI:"boolean_response_comparison",
            VulnerabilityType.XSS:"dangerous_context_check",
            VulnerabilityType.BAC:"role_resource_comparison"
        }[candidate.vulnerability_type]
        if not group.verification_group_id:
            group.verification_group_id=f"group_{uuid.uuid4().hex[:12]}"
        _shape(candidate,group)
        return group
