# ScamFlow RAG 운영 가이드

## 구조

ScamFlow는 서로 역할이 다른 두 개의 RAG를 사용합니다.

1. **Scenario RAG**: `smishing.csv`의 정상/스미싱 사례를 검색해 Agent가 생성한 사기 가설을 보강합니다. 검색 결과는 참고 근거이며 그 자체가 최종 판단이 되지 않습니다.
2. **Response Policy RAG**: 사기 가능성 판정이 끝난 뒤 `scenario + exposure_stage + risk_level`로 즉시 대응 행동을 검색합니다. 사기 점수 계산에는 사용하지 않습니다.

전체 흐름은 다음과 같습니다.

`Scenario Hypothesis → Scenario RAG → Tool Verification → Evidence Fusion → Scam Likelihood → Exposure Stage → Response Policy RAG → Next Action → Solar 설명`

Scenario RAG는 유사도와 검색 label 합의가 충분하고, 원문에 금전·인증정보·링크·앱 설치 등 실질적인 위험 행동 요구가 있을 때만 점수 근거로 사용합니다. 일상 대화와 직접 통화 의사가 있고 위험 행동 요구가 없으면 검색 결과를 점수와 Solar 설명에 반영하지 않습니다.

## 데이터와 임베딩

- 원본 CSV: 프로젝트 루트의 `smishing.csv`
- 필드: `content`, `label`, `explanation`, `type`
- 빈 `type`: `미분류`로 정규화
- `explanation`의 `$$스미싱 여부$$`, `$$설명$$` 표시자: 인덱싱 전 제거
- 임베딩: 한국어 토큰과 2~4글자 자모를 조합한 로컬 256차원 hash embedding
- 외부 유료 embedding API: 사용하지 않음
- Vector DB: `documents.jsonl + vectors.f32 + manifest.json`로 구성된 로컬 영속 백터 저장소
- 인덱스 위치: `backend/data/rag/scenario/`

CSV 해시와 embedding 버전이 동일하면 서버를 다시 실행해도 임베딩을 반복하지 않습니다.

## 인덱스 생성

기존 프로젝트의 `.venv`를 사용합니다.

```bash
cd backend
../.venv/bin/python scripts/build_rag_index.py
```

원본 CSV가 바뀌어 강제로 재생성할 때:

```bash
cd backend
../.venv/bin/python scripts/build_rag_index.py --force
```

`RAG_AUTO_BUILD_INDEX=true`면 RAG ON 첫 요청 시 인덱스가 없을 때 자동 생성합니다. 첫 요청 지연을 피하려면 위 스크립트를 미리 실행하세요.

## Scenario RAG ON/OFF와 백엔드 실행

`backend/.env`에서 전환합니다.

```dotenv
# Scenario RAG 유사 사례 검색만 중지
RAG_ENABLED=false

# Scenario RAG 유사 사례 검색 보강
RAG_ENABLED=true
```

Response Policy RAG와 기존 공식 대응정보 RAG는 이 값과 관계없이 계속 실행됩니다. Response Policy는 최종 Scam Likelihood를 바꾸지 않고, 판정 후 Next Action만 선택합니다.

설정을 바꾼 뒤에는 백엔드를 재시작합니다.

```bash
cd backend
../.venv/bin/uvicorn app.main:app --reload
```

## 비교 방법

1. `RAG_ENABLED=false`로 같은 입력 케이스를 분석해 Scenario RAG OFF 결과를 저장합니다. Response Policy RAG는 이 경우에도 실행됩니다.
2. `RAG_ENABLED=true`로 바꾸고 백엔드를 재시작한 뒤 동일한 입력과 피해 단계로 Scenario RAG ON 결과를 분석합니다.
3. `POST /api/v1/analyze` 응답의 `rag.scenario_results`, `rag.response_policy`, `recommended_actions`, `risk_breakdown.scenario_rag`를 확인합니다.
4. 사기 유형, Scam Likelihood, Exposure Stage, 첫 번째 Next Action을 OFF/ON 결과에서 비교합니다.

개발 환경 로그에는 Scenario query/검색 문서와 similarity, Agent 가설, Tool 결과, Scam Likelihood, Exposure Stage, Response Policy, 최종 권고 행동이 남습니다.

## Fallback

- CSV/인덱스 로드 실패: Scenario RAG만 생략하고 기존 Agent + Rule + Solar로 판단
- Response Policy JSON 로드 실패: 기존 `SafetyPolicy`의 행동 안내 사용
- Solar/외부 Tool 실패: 로컬 규칙과 검색 근거로 응답 유지

Document Parse는 이 구조에서 사용하지 않습니다.
