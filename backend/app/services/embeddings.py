"""RAG 적재와 검색에서 공통으로 사용하는 무비용 임베딩."""

import hashlib
import math
import re

DIMENSIONS = 256


def local_embedding(text: str) -> list[float]:
    """동일 입력에 동일한 결과를 내는 해시 기반 검색 벡터를 생성합니다."""
    vector = [0.0] * DIMENSIONS
    for token in re.findall(r"[가-힣A-Za-z0-9]+", text.lower()):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:2], "big") % DIMENSIONS
        vector[index] += -1.0 if digest[2] % 2 else 1.0
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [value / norm for value in vector]
