from __future__ import annotations
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field, HttpUrl

class VulnerabilityType(str, Enum):
    SQLI="SQLI"; XSS="XSS"; BAC="BAC"

class RequestContext(BaseModel):
    method: Literal["GET","POST"]
    url: HttpUrl
    parameter_name: str
    parameter_location: Literal["query","body","header","path"]
    parameter_occurrence: int = Field(default=0, ge=0)
    original_value: str
    headers: dict[str,str] = Field(default_factory=dict)
    body: dict[str,Any] | None = None
    content_type: Literal["form","json"] = "form"

class EvidenceItem(BaseModel):
    feature: str
    value: float|int|bool|str

class BaselineSummary(BaseModel):
    status_code: int|None=None
    response_length: int|None=None
    body_fingerprint: str|None=None

class AuthContext(BaseModel):
    context_id: str
    role: str
    principal_id: str|None=None
    headers: dict[str,str] = Field(default_factory=dict)

class ResourceDescriptor(BaseModel):
    value: str
    owner_principal_id: str|None=None
    required_role: str|None=None
    expected_access: Literal["allow","deny","unknown"]="unknown"

class Candidate(BaseModel):
    candidate_id: str
    vulnerability_type: VulnerabilityType
    request_context: RequestContext
    observed_evidence: list[EvidenceItem]
    baseline_response: BaselineSummary|None=None
    verification_hints: dict[str,Any] = Field(default_factory=dict)
    auth_contexts: list[AuthContext] = Field(default_factory=list)
    resources: list[ResourceDescriptor] = Field(default_factory=list)

    initial_rank_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

class Target(BaseModel):
    parameter_name: str
    parameter_location: Literal["query","body","header","path"]
    parameter_occurrence: int=0

class PayloadItem(BaseModel):
    payload_id: str
    payload: str
    payload_role: Literal["true_condition","false_condition","control","reflection_marker","authorization_control","authorization_variant"]
    expected_observation: str
    rationale: str
    destructive: bool=False
    auth_context_id: str|None=None
    expected_access: Literal["allow","deny","unknown"]="unknown"

class VerificationGroup(BaseModel):
    verification_group_id: str
    candidate_id: str
    vulnerability_type: VulnerabilityType
    target: Target
    verification_type: Literal["boolean_response_comparison","dangerous_context_check","role_resource_comparison"]
    payloads: list[PayloadItem] = Field(min_length=3,max_length=4)
    generation_rationale: str

class RejectedPayload(BaseModel):
    payload_id: str
    payload: str
    reasons: list[str]

class ValidationResult(BaseModel):
    verification_group_id: str
    candidate_id: str
    allowed_payloads: list[PayloadItem]
    rejected_payloads: list[RejectedPayload]
    executable: bool
    validator_version: str="prototype-3.0"

class RequestResult(BaseModel):
    payload_id: str
    payload_role: str
    payload: str
    auth_context_id: str|None=None
    auth_role: str|None=None
    principal_id: str|None=None
    expected_access: str="unknown"
    status_code: int|None
    response_length: int|None
    elapsed_ms: float|None
    body_sha256: str|None
    normalized_body_sha256: str|None=None
    content_type: str|None=None
    sql_error_pattern: bool=False
    reflected: bool=False
    escaped_reflection: bool=False
    reflection_contexts: list[str]=Field(default_factory=list)
    dangerous_contexts: list[str]=Field(default_factory=list)
    access_granted: bool=False
    execution_error: str|None=None

class VerificationObservations(BaseModel):
    status_code_difference: bool
    response_length_difference_ratio: float
    elapsed_time_difference_ratio: float
    body_fingerprint_difference: bool
    sql_error_pattern: bool
    reflected: bool=False
    escaped_reflection: bool=False
    reflection_contexts: list[str]=Field(default_factory=list)
    dangerous_contexts: list[str]=Field(default_factory=list)
    role_bypass_detected: bool=False
    resource_bypass_detected: bool=False
    authorization_mismatches: list[str]=Field(default_factory=list)
    repeatable: bool
    successful_requests: int
    total_requests: int

class VerificationRecord(BaseModel):
    verification_id: str
    candidate_id: str
    vulnerability_type: VulnerabilityType
    verification_type: str
    request_results: list[RequestResult]
    observations: VerificationObservations
    verification_result: Literal["supporting","inconclusive","contradicting","execution_failed"]
    reason: str

class ConfidenceUpdateRecord(BaseModel):
    candidate_id: str
    vulnerability_type: VulnerabilityType

    initial_rank_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    verification_bonus: float = Field(
        ge=0.0,
        le=1.0,
    )

    safety_encoding_penalty: float = Field(
        ge=0.0,
        le=1.0,
    )

    inconsistency_penalty: float = Field(
        ge=0.0,
        le=1.0,
    )

    raw_confidence: float

    final_confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    confidence_delta: float

    confidence_level: Literal[
        "very_low",
        "low",
        "medium",
        "high",
        "critical",
    ]

    decision: Literal[
        "confirmed_candidate",
        "needs_review",
        "discard_candidate",
        "retry_required",
    ]

    bonus_reasons: list[str] = Field(
        default_factory=list
    )

    penalty_reasons: list[str] = Field(
        default_factory=list
    )