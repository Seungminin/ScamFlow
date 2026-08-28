"""공식 기관 대응정보를 우선하는 경량 로컬 RAG."""

import json
import re
from pathlib import Path

from app.services.embeddings import local_embedding
from app.services.supabase import supabase_gateway


class OfficialKnowledgeRepository:
    def __init__(self, data_path: Path | None = None):
        self.data_path = data_path or Path(__file__).parents[2] / "data" / "official_response_guides.json"
        self._documents = json.loads(self.data_path.read_text(encoding="utf-8"))

    async def search(self, query: str, scam_type: str, stage: str, limit: int = 3) -> list[dict]:
        remote = await self._search_supabase(query, limit)
        if remote:
            return remote
        return self._search_local(query, scam_type, stage, limit)

    async def _search_supabase(self, query: str, limit: int) -> list[dict]:
        response = await supabase_gateway.rpc(
            "match_scam_documents",
            {"query_embedding": local_embedding(query), "match_count": limit},
        )
        if not response:
            return []
        return [
            {
                "agency": item["agency"],
                "title": item["title"],
                "content": item["content"],
                "url": item["source_url"],
                "phone": item.get("phone"),
                "similarity": item.get("similarity"),
                "retrieval": "supabase-pgvector",
            }
            for item in response
        ]

    def _search_local(self, query: str, scam_type: str, stage: str, limit: int) -> list[dict]:
        tokens = set(re.findall(r"[가-힣A-Za-z0-9]+", query.lower()))
        scored: list[tuple[int, dict]] = []
        for document in self._documents:
            searchable = f"{document['title']} {document['content']} {' '.join(document['tags'])}".lower()
            score = sum(1 for token in tokens if len(token) > 1 and token in searchable)
            score += 4 if scam_type in document["tags"] else 0
            score += 3 if stage in document["tags"] else 0
            scored.append((score, document))
        scored.sort(key=lambda item: item[0], reverse=True)
        documents = [document for score, document in scored[:limit] if score > 0] or [self._documents[0]]
        return [{**document, "retrieval": "local-fallback"} for document in documents]
