from __future__ import annotations
from .confidence import ConfidenceUpdater
import os
from .gemini_client import GeminiStructuredClient
from .openai_client import OpenAIStructuredClient
from .models import Candidate, ValidationResult, VerificationGroup, VerificationRecord
from .mutation import PayloadMutationService
from .validator import PayloadValidator
from .verifier import FocusedVerifier

def create_llm_client():
    provider = os.getenv(
        "LLM_PROVIDER",
        "gemini",
    ).strip().lower()

    if provider == "gemini":
        return GeminiStructuredClient()

    if provider == "openai":
        return OpenAIStructuredClient()

    raise ValueError(
        f"Unsupported LLM_PROVIDER: {provider}"
    )


class SelectiveVerificationPipeline:
    def __init__(self) -> None:
        llm = create_llm_client()

        self.mutator = PayloadMutationService(llm)
        self.validator = PayloadValidator()
        self.verifier = FocusedVerifier()
        self.confidence_updater = ConfidenceUpdater()

    async def run(self, candidate: Candidate):
        mutation = self.mutator.mutate(candidate)
        validation = self.validator.validate(candidate, mutation)
        verification = await self.verifier.verify(candidate, validation)
        confidence_update = self.confidence_updater.update(candidate,verification)
        return mutation, validation, verification, confidence_update
