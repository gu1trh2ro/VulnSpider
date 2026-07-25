\
from __future__ import annotations

import os
from google import genai
from google.genai import types
from pydantic import BaseModel


class GeminiStructuredClient:
    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
        self.client = genai.Client(api_key=api_key or os.getenv("GEMINI_API_KEY"))

    def generate(self, prompt: str, schema: type[BaseModel]) -> BaseModel:
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )
        if response.parsed is not None:
            return response.parsed
        return schema.model_validate_json(response.text)
