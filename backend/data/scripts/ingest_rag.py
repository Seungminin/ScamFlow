"""공식 대응정보를 Supabase에 선택적으로 적재하는 무토큰 스크립트."""

import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

from app.services.embeddings import local_embedding

DATA_PATH = Path(__file__).parents[1] / "official_response_guides.json"
def main() -> None:
    load_dotenv(Path(__file__).parents[2] / ".env")
    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    candidates = [
        os.getenv("SUPABASE_SECRET_KEY", ""),
        os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""),
        os.getenv("SUPABASE_KEY", ""),
    ]
    supabase_key = next(
        (key for key in candidates if key.startswith("sb_secret_")),
        next((key for key in candidates if key and not key.startswith("sb_publishable_")), ""),
    )
    if not supabase_url or not supabase_key:
        raise SystemExit("SUPABASE_URL과 서버용 SUPABASE_SECRET_KEY를 설정하세요.")
    documents = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    rows = [
        {
            "id": item["id"],
            "agency": item["agency"],
            "title": item["title"],
            "content": item["content"],
            "source_url": item["url"],
            "phone": item.get("phone"),
            "tags": item["tags"],
            "embedding": local_embedding(f"{item['title']} {item['content']} {' '.join(item['tags'])}"),
        }
        for item in documents
    ]
    headers = {
        "apikey": supabase_key,
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates",
    }
    if not supabase_key.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {supabase_key}"
    response = httpx.post(
        f"{supabase_url}/rest/v1/scam_documents?on_conflict=id",
        headers=headers,
        json=rows,
        timeout=30,
    )
    response.raise_for_status()
    print(f"공식 대응정보 {len(rows)}건을 적재했습니다.")


if __name__ == "__main__":
    main()
