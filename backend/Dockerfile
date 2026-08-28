# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

RUN pip install --no-cache-dir uv==0.9.18
COPY pyproject.toml uv.lock ./
COPY app ./app
COPY data ./data
COPY scripts ./scripts
RUN uv sync --frozen --no-dev

# Render의 Git 빌드에는 로컬에서 생성한 Scenario RAG 파일이 없으므로,
# 공개 원본을 체크섬 검증 후 내려받아 인덱스를 이미지에 미리 포함합니다.
ARG INSTALL_SCENARIO_RAG=true
ARG SCENARIO_DATASET_URL=https://huggingface.co/datasets/jmjmjm3/kor-smishing-message/resolve/main/smishing.csv
ARG SCENARIO_DATASET_SHA256=e33c76044be3b9a0b177b5d0d2d3886e1d376057dc676da2cc457b0d7aa77a5f
RUN if [ "$INSTALL_SCENARIO_RAG" = "true" ]; then \
      .venv/bin/python scripts/download_scenario_dataset.py \
        --url "$SCENARIO_DATASET_URL" \
        --sha256 "$SCENARIO_DATASET_SHA256" \
        --output data/smishing.csv && \
      .venv/bin/python scripts/build_rag_index.py \
        --csv data/smishing.csv \
        --index-dir data/rag/scenario; \
    fi

EXPOSE 8000
CMD ["sh", "-c", ".venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
