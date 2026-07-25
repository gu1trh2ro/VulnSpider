from __future__ import annotations

import os
from typing import TypeVar

from openai import OpenAI
from pydantic import BaseModel


T = TypeVar("T", bound=BaseModel)


class OpenAIStructuredClient:
    def __init__(
        self,
        model: str | None = None,
    ) -> None:
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not configured"
            )

        self.model = (
            model
            or os.getenv("OPENAI_MODEL")
            or "gpt-5.6"
        )

        self.client = OpenAI(
            api_key=api_key
        )

    def generate(
        self,
        prompt: str,
        response_model: type[T],
    ) -> T:
        response = self.client.responses.parse(
            model=self.model,
            input=[
                {
                    "role": "developer",
                    "content": (
                        "You are a security verification assistant "
                        "for authorized local testing only. "
                        "Generate only non-destructive verification "
                        "payloads and strictly follow the output schema."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            text_format=response_model,
        )

        parsed = response.output_parsed

        if parsed is None:
            raise RuntimeError(
                "OpenAI returned no structured output"
            )

        return parsed