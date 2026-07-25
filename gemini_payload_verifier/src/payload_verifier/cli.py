\
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from dotenv import load_dotenv

from .models import Candidate
from .pipeline import SelectiveVerificationPipeline


def dump_json(path: Path, value: object) -> None:
    if hasattr(value, "model_dump"):
        data = value.model_dump(mode="json")
    else:
        data = value
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


async def main_async() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_json", type=Path)
    parser.add_argument("--out", type=Path, default=Path("output"))
    args = parser.parse_args()

    load_dotenv()
    candidate = Candidate.model_validate_json(
        args.candidate_json.read_text(encoding="utf-8")
    )
    args.out.mkdir(parents=True, exist_ok=True)

    pipeline = SelectiveVerificationPipeline()
    mutation, validation, verification, confidence_update = await pipeline.run(candidate)

    dump_json(args.out / "01_mutation.json", mutation)
    dump_json(args.out / "02_validation.json", validation)
    dump_json(args.out / "03_verification.json", verification)
    dump_json(args.out / "04_confidence_update.json", confidence_update)

    print(json.dumps(verification.model_dump(mode="json"), ensure_ascii=False, indent=2))
    print(json.dumps(confidence_update.model_dump(mode="json"), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main_async())
