"""한국어 문자 n-gram을 포함하는 무비용 로컬 RAG 임베딩."""

import hashlib
import math
import re

from app.services.embeddings import DIMENSIONS

EMBEDDING_VERSION = "scamflow-korean-hash-ngram-v1"


def korean_rag_embedding(text: str) -> list[float]:
    """한국어 띄어쓰기 변형에도 견디는 결정론적 256차원 벡터를 만듭니다."""
    normalized = re.sub(r"\s+", " ", text.lower()).strip()
    vector = [0.0] * DIMENSIONS
    tokens = re.findall(r"[가-힣A-Za-z0-9]+", normalized)
    for token in tokens:
        _accumulate(vector, f"token:{token}", 2.0)
        compact = re.sub(r"[^가-힣a-z0-9]", "", token)
        for size, weight in ((2, 0.8), (3, 1.0), (4, 0.6)):
            if len(compact) < size:
                continue
            for index in range(len(compact) - size + 1):
                _accumulate(vector, f"char{size}:{compact[index:index + size]}", weight)
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [value / norm for value in vector]


def _accumulate(vector: list[float], feature: str, weight: float) -> None:
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    index = int.from_bytes(digest[:4], "big") % DIMENSIONS
    vector[index] += -weight if digest[4] & 1 else weight
