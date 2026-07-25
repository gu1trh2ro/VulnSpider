from __future__ import annotations

from .models import (
    Candidate,
    ConfidenceUpdateRecord,
    VerificationRecord,
    VulnerabilityType,
)


class ConfidenceUpdater:
    """Focused Verification 결과를 이용해 후보 confidence를 갱신한다."""

    RESULT_BASE_BONUS = {
        "supporting": 0.15,
        "inconclusive": 0.02,
        "contradicting": 0.00,
        "execution_failed": 0.00,
    }

    RESULT_BONUS_CAP = {
        "supporting": 0.35,
        "inconclusive": 0.08,
        "contradicting": 0.00,
        "execution_failed": 0.00,
    }

    XSS_CONTEXT_BONUS = {
        "event_handler_attribute": 0.15,
        "javascript_string_or_code": 0.15,
        "srcdoc_attribute": 0.14,
        "html_markup_candidate": 0.12,
        "attribute_breakout_candidate": 0.10,
        "url_attribute": 0.08,
        "css_context": 0.06,
        "comment_breakout_candidate": 0.04,
    }

    def update(
        self,
        candidate: Candidate,
        verification: VerificationRecord,
    ) -> ConfidenceUpdateRecord:
        initial = candidate.initial_rank_score

        evidence_bonus, bonus_reasons = self._verification_evidence_bonus(
            candidate.vulnerability_type,
            verification,
        )

        base_bonus = self.RESULT_BASE_BONUS[
            verification.verification_result
        ]

        bonus_cap = self.RESULT_BONUS_CAP[
            verification.verification_result
        ]

        verification_bonus = min(
            base_bonus + evidence_bonus,
            bonus_cap,
        )

        safety_penalty, safety_reasons = (
            self._safety_encoding_penalty(
                candidate.vulnerability_type,
                verification,
            )
        )

        inconsistency_penalty, inconsistency_reasons = (
            self._inconsistency_penalty(verification)
        )

        raw_confidence = (
            initial
            + verification_bonus
            - safety_penalty
            - inconsistency_penalty
        )

        final_confidence = self._clamp(raw_confidence)

        return ConfidenceUpdateRecord(
            candidate_id=candidate.candidate_id,
            vulnerability_type=candidate.vulnerability_type,
            initial_rank_score=initial,
            verification_bonus=round(verification_bonus, 4),
            safety_encoding_penalty=round(safety_penalty, 4),
            inconsistency_penalty=round(
                inconsistency_penalty,
                4,
            ),
            raw_confidence=round(raw_confidence, 4),
            final_confidence=round(final_confidence, 4),
            confidence_delta=round(
                final_confidence - initial,
                4,
            ),
            confidence_level=self._level(final_confidence),
            decision=self._decision(
                final_confidence,
                verification.verification_result,
            ),
            bonus_reasons=bonus_reasons,
            penalty_reasons=(
                safety_reasons
                + inconsistency_reasons
            ),
        )

    def _verification_evidence_bonus(
        self,
        vulnerability_type: VulnerabilityType,
        verification: VerificationRecord,
    ) -> tuple[float, list[str]]:
        if vulnerability_type == VulnerabilityType.SQLI:
            return self._score_sqli(verification)

        if vulnerability_type == VulnerabilityType.XSS:
            return self._score_xss(verification)

        return self._score_bac(verification)

    def _score_sqli(
        self,
        verification: VerificationRecord,
    ) -> tuple[float, list[str]]:
        obs = verification.observations
        bonus = 0.0
        reasons: list[str] = []

        if obs.repeatable:
            bonus += 0.03
            reasons.append("SQLi 검증 결과가 반복 재현됨")

        if obs.status_code_difference:
            bonus += 0.06
            reasons.append("true/false 상태 코드 차이")

        if obs.response_length_difference_ratio >= 0.20:
            bonus += 0.06
            reasons.append("true/false 응답 길이 차이")

        if obs.body_fingerprint_difference:
            bonus += 0.07
            reasons.append("true/false 정규화 본문 차이")

        if obs.elapsed_time_difference_ratio >= 0.50:
            bonus += 0.03
            reasons.append("true/false 응답 시간 차이")

        if obs.sql_error_pattern:
            bonus += 0.02
            reasons.append("SQL 오류 패턴 탐지")

        return min(bonus, 0.20), reasons

    def _score_xss(
        self,
        verification: VerificationRecord,
    ) -> tuple[float, list[str]]:
        obs = verification.observations
        bonus = 0.0
        reasons: list[str] = []

        if obs.reflected:
            bonus += 0.03
            reasons.append("XSS 마커 원문 반사")

        if obs.repeatable:
            bonus += 0.03
            reasons.append("XSS 반사가 반복 재현됨")

        context_bonus = max(
            (
                self.XSS_CONTEXT_BONUS.get(context, 0.0)
                for context in obs.dangerous_contexts
            ),
            default=0.0,
        )

        if context_bonus > 0:
            bonus += context_bonus
            reasons.append(
                "XSS 위험 문맥 탐지: "
                + ", ".join(obs.dangerous_contexts)
            )

        return min(bonus, 0.20), reasons

    def _score_bac(
        self,
        verification: VerificationRecord,
    ) -> tuple[float, list[str]]:
        obs = verification.observations
        bonus = 0.0
        reasons: list[str] = []

        if obs.role_bypass_detected:
            bonus += 0.14
            reasons.append("역할 기반 권한 우회 탐지")

        if obs.resource_bypass_detected:
            bonus += 0.14
            reasons.append("다른 소유자의 리소스 접근 탐지")

        mismatch_count = len(
            obs.authorization_mismatches
        )

        if mismatch_count > 0:
            bonus += min(mismatch_count * 0.03, 0.06)
            reasons.append(
                f"권한 정책 불일치 {mismatch_count}건"
            )

        if obs.repeatable:
            bonus += 0.04
            reasons.append("BAC 검증 결과가 반복 재현됨")

        return min(bonus, 0.20), reasons

    def _safety_encoding_penalty(
        self,
        vulnerability_type: VulnerabilityType,
        verification: VerificationRecord,
    ) -> tuple[float, list[str]]:
        obs = verification.observations
        penalty = 0.0
        reasons: list[str] = []

        # Safety Encoding Penalty는 XSS에만 적용
        if vulnerability_type != VulnerabilityType.XSS:
            return 0.0, reasons

        if obs.escaped_reflection:
            penalty += 0.20
            reasons.append(
                "XSS 반사값에 HTML encoding이 적용됨"
            )

        if (
            obs.reflected
            and not obs.dangerous_contexts
        ):
            penalty += 0.05
            reasons.append(
                "마커가 반사됐지만 위험 문맥이 확인되지 않음"
            )

        return min(penalty, 0.30), reasons

    def _inconsistency_penalty(
        self,
        verification: VerificationRecord,
    ) -> tuple[float, list[str]]:
        obs = verification.observations
        penalty = 0.0
        reasons: list[str] = []

        if not obs.repeatable:
            penalty += 0.15
            reasons.append(
                "검증 결과가 반복 재현되지 않음"
            )

        if obs.successful_requests == 0:
            penalty += 0.25
            reasons.append(
                "성공한 검증 요청이 없음"
            )

        elif obs.successful_requests < obs.total_requests:
            failed_count = (
                obs.total_requests
                - obs.successful_requests
            )

            failure_ratio = (
                failed_count / obs.total_requests
            )

            penalty += min(
                failure_ratio * 0.15,
                0.15,
            )

            reasons.append(
                f"검증 요청 {failed_count}건 실패"
            )

        return min(penalty, 0.30), reasons

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(value, 1.0))

    @staticmethod
    def _level(score: float) -> str:
        if score >= 0.85:
            return "critical"

        if score >= 0.70:
            return "high"

        if score >= 0.40:
            return "medium"

        if score >= 0.20:
            return "low"

        return "very_low"

    @staticmethod
    def _decision(
        score: float,
        verification_result: str,
    ) -> str:
        if verification_result == "execution_failed":
            return "retry_required"

        if score >= 0.75:
            return "confirmed_candidate"

        if score >= 0.40:
            return "needs_review"

        return "discard_candidate"