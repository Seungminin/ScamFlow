"""smishing.csv 기반 Scenario RAG 인덱스를 미리 생성합니다."""

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.rag.scenario_rag import ScenarioRag  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="ScamFlow Scenario RAG index builder")
    parser.add_argument("--csv", type=Path, help="smishing.csv 경로")
    parser.add_argument("--index-dir", type=Path, help="인덱스 저장 디렉터리")
    parser.add_argument("--force", action="store_true", help="기존 인덱스를 다시 생성")
    args = parser.parse_args()

    repository = ScenarioRag(csv_path=args.csv, index_dir=args.index_dir)
    count = repository.build_index(force=args.force)
    print(f"Scenario RAG index ready: {count:,} documents")
    print(f"Index directory: {repository.index_dir}")


if __name__ == "__main__":
    main()
