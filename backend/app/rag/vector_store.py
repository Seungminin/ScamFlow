"""외부 DB 없이 재사용 가능한 float32 파일 기반 벡터 저장소."""

import heapq
import json
from array import array
from collections.abc import Callable, Iterable
from pathlib import Path
from threading import Lock


class PersistentVectorStore:
    """문서 JSONL과 정규화 벡터를 별도 파일로 저장하고 메모리에 한 번만 로드합니다."""

    def __init__(
        self,
        index_dir: Path,
        embedding: Callable[[str], list[float]],
        embedding_version: str,
        dimensions: int,
    ) -> None:
        self.index_dir = index_dir
        self.embedding = embedding
        self.embedding_version = embedding_version
        self.dimensions = dimensions
        self.manifest_path = index_dir / "manifest.json"
        self.documents_path = index_dir / "documents.jsonl"
        self.vectors_path = index_dir / "vectors.f32"
        self._documents: list[dict] | None = None
        self._vectors: array | None = None
        self._lock = Lock()

    def is_current(self, source_fingerprint: str) -> bool:
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return bool(
            self.documents_path.exists()
            and self.vectors_path.exists()
            and manifest.get("source_fingerprint") == source_fingerprint
            and manifest.get("embedding_version") == self.embedding_version
            and int(manifest.get("dimensions", 0)) == self.dimensions
        )

    def build(self, documents: Iterable[dict], source_fingerprint: str) -> int:
        self.index_dir.mkdir(parents=True, exist_ok=True)
        temporary_documents = self.index_dir / "documents.jsonl.tmp"
        temporary_vectors = self.index_dir / "vectors.f32.tmp"
        count = 0
        with temporary_documents.open("w", encoding="utf-8") as document_file, temporary_vectors.open("wb") as vector_file:
            for document in documents:
                vector = self.embedding(str(document["document_text"]))
                if len(vector) != self.dimensions:
                    raise ValueError("RAG 임베딩 차원이 설정과 일치하지 않습니다.")
                document_file.write(json.dumps(document, ensure_ascii=False) + "\n")
                array("f", vector).tofile(vector_file)
                count += 1
        temporary_documents.replace(self.documents_path)
        temporary_vectors.replace(self.vectors_path)
        manifest = {
            "format": "scamflow-local-vector-store-v1",
            "count": count,
            "dimensions": self.dimensions,
            "embedding_version": self.embedding_version,
            "source_fingerprint": source_fingerprint,
        }
        temporary_manifest = self.index_dir / "manifest.json.tmp"
        temporary_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary_manifest.replace(self.manifest_path)
        self._documents = None
        self._vectors = None
        return count

    def load(self) -> int:
        with self._lock:
            if self._documents is not None and self._vectors is not None:
                return len(self._documents)
            documents = [
                json.loads(line)
                for line in self.documents_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            vectors = array("f")
            with self.vectors_path.open("rb") as vector_file:
                vectors.fromfile(vector_file, len(documents) * self.dimensions)
            if len(vectors) != len(documents) * self.dimensions:
                raise ValueError("RAG 벡터 파일 크기가 manifest와 일치하지 않습니다.")
            self._documents = documents
            self._vectors = vectors
            return len(documents)

    def search(self, query: str, limit: int = 5) -> list[dict]:
        self.load()
        if not self._documents or self._vectors is None:
            return []
        query_vector = self.embedding(query)
        dimensions = self.dimensions
        vectors = self._vectors

        def scored_documents():
            for document_index, document in enumerate(self._documents or []):
                offset = document_index * dimensions
                similarity = sum(
                    query_vector[dimension] * vectors[offset + dimension]
                    for dimension in range(dimensions)
                )
                yield similarity, document_index, document

        best = heapq.nlargest(max(1, limit), scored_documents(), key=lambda item: item[0])
        return [{**document, "similarity": round(max(-1.0, min(1.0, similarity)), 4)} for similarity, _, document in best]
