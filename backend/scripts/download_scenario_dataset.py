"""Scenario RAG 공개 데이터셋을 내려받고 무결성을 검증합니다."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import urllib.request
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(f"{args.output.suffix}.download")
    request = urllib.request.Request(
        args.url,
        headers={"User-Agent": "ScamFlow-deployment/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            with temporary.open("wb") as destination:
                shutil.copyfileobj(response, destination)
        actual = sha256(temporary)
        if actual.lower() != args.sha256.lower():
            raise ValueError(
                f"Scenario dataset checksum mismatch: expected={args.sha256}, actual={actual}"
            )
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"Scenario dataset ready: {args.output} ({args.output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
