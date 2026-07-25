\
from __future__ import annotations
from .confidence import ConfidenceUpdater

from .gemini_client import GeminiStructuredClient
from .models import Candidate, ValidationResult, VerificationGroup, VerificationRecord
from .mutation import PayloadMutationService
from .validator import PayloadValidator
from .verifier import FocusedVerifier


class SelectiveVerificationPipeline:
    def __init__(self) -> None:
        self.mutator = PayloadMutationService(GeminiStructuredClient())
        self.validator = PayloadValidator()
        self.verifier = FocusedVerifier()
        self.confidence_updater = ConfidenceUpdater()

    async def run(
        self, candidate: Candidate
    ) -> tuple[VerificationGroup, ValidationResult, VerificationRecord]:
        mutation = self.mutator.mutate(candidate)
        validation = self.validator.validate(candidate, mutation)
        verification = await self.verifier.verify(candidate, validation)
        confidence_update = self.confidence_updater.update(candidate,verification)
        return mutation, validation, verification, confidence_update
