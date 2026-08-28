# ScamFlow 금융사기 대응 Agent

> 금융사기 의심 상황을 **Detection → Explanation → Verification → Action → Recovery** 순서로 안내하는 안전 중심 AI Agent입니다.

## 기존 예제 및 UI 분석

- `starter_code`는 Python 3.11, FastAPI, LangGraph, Upstage Solar, Supabase(pgvector), Gradio를 사용하는 교육용 Agent 구조입니다.
- 설정은 `pydantic-settings`, API 입출력은 Pydantic schema, 비동기 처리는 FastAPI와 `httpx`, 테스트는 `pytest` 스타일을 사용합니다.
- 원본은 실제 Graph/API/Tool 구현이 비어 있는 출발점이므로 `backend/app` 아래에 Graph, Tool, Service, API 계층을 같은 스타일로 보완합니다.
- `scamflow.zip`은 Jetpack Compose 모바일 UI이며 네이비·블루 기반 신뢰 색상, 입력/분석/결과/긴급대응 화면, 2×3 Quick Action, 가족·기관·URL 확인 Dialog를 핵심 경험으로 사용합니다.
- 웹에서는 모바일 UI의 정보 구조와 기능을 유지하면서 데스크톱에서도 읽기 쉬운 반응형 2열 레이아웃으로 확장합니다.

## 개발 계획

### 1. 기반 구조와 실행 환경

- [x] Starter Code의 구조·의존성·코딩 스타일 분석
- [x] Compose UI의 화면 상태·컬러·핵심 상호작용 분석
- [x] 기존 FastAPI 진입점과 설정 구조를 ScamFlow 도메인으로 전환
- [x] 환경변수 예시와 로컬 실행 절차 정리
- [x] API 키가 없어도 Rule Engine 기반으로 실행되는 무비용 기본 모드 제공

### 2. Agent State와 LangGraph Flow

- [x] `ScamFlowState`에 세션, 최근 사용자 Context, 구조화 입력, 피해 단계, 사기 유형, 위험도, 근거, Tool 결과, 승인 대기 Action을 명시
- [x] Supabase 우선·인메모리 폴백 State 저장소를 구성해 후속 대화와 서버 재시작에도 상황 유지
- [x] Detection → Explanation → Verification → Action → Recovery 노드 구성
- [x] 피해 단계 및 위험도에 따라 Action/Recovery로 분기하는 Edge 구현
- [x] Agent Orchestrator가 Context에 따라 URL·전화번호·Multimodal Tool을 선택하고, 저위험 입력에서는 불필요한 Tool 호출을 생략
- [x] Detection 이후 위험도·피해 단계에 따라 공식 RAG 검색 여부를 조건부로 결정
- [x] 부족한 정보가 있을 때 추가 질문을 생성하고 State에 반영
- [x] 새 상담 시작 시 새 세션 ID를 즉시 적용하고 이전 피해 단계·탐지 결과·메시지 Context를 완전히 분리

### 3. 하이브리드 생성형 AI 전략

- [x] 1차 판단은 결정론적 Rule Engine으로 수행해 핵심 안전 규칙을 LLM과 분리
- [x] `UPSTAGE_API_KEY`가 있을 때 Solar를 유형·위험표현 후보 분석과 설명·추가 질문 생성에 선택적으로 사용
- [x] Solar 호출은 짧은 JSON 출력, 낮은 토큰 상한, 규칙 결과 재검증으로 비용 최소화
- [x] 키가 없거나 API가 실패하면 완전한 로컬 응답으로 안전하게 폴백
- [x] 이미지 입력은 Upstage Document Digitization OCR을 선택적으로 사용하고 추출 텍스트를 동일 분석 Flow에 연결

### 4. Scam Detection과 Tool

- [x] 가족사칭·기관사칭·대출·택배/스미싱·투자·원격제어 앱 패턴 탐지
- [x] 위험 표현과 판단 근거를 원문에서 추출
- [x] 관계어 단독 판정을 제거하고 신규 연락처·통화 회피·긴급성·금전/개인정보 요구의 복합 Evidence로 가족사칭 판정
- [x] Solar와 로컬 분석이 Positive Evidence와 Normal/Negative Evidence를 구조적으로 함께 반환
- [x] 대화·URL·전화번호·송금 요구·긴급성·사칭·개인정보·앱 설치 요청을 구조화 Context로 추출
- [x] URL 구조·단축 URL·IP 주소·의심 TLD를 검사하는 Tool 구현
- [x] VirusTotal 기존 분석 보고서를 조회하는 URL 평판 Tool 구현
- [x] 전화번호를 Supabase 공식 기관 연락처 원장과 비교하는 Tool 구현
- [x] 공식 기관 지식 검색 Tool과 출처 메타데이터 제공
- [x] Tool 선택과 실행 결과를 응답에 표시해 판단 과정의 투명성 확보
- [x] URL Risk·Situation Risk·Scam Context Risk를 독립 계산하고, URL과 피싱 정황이 함께 높을 때만 결합 가산
- [x] 단순 max 대신 Evidence 강도·개수와 URL·Situation 가중치를 융합하고 악성 URL·피해 단계는 Safety Floor로 재검증

### 5. Safety Policy와 승인 기반 Action

- [x] 송금 안전 보증·금융거래 허용을 금지하는 Policy 구현
- [x] 송금 완료, 개인정보 입력, 앱 설치 단계의 긴급 규칙을 Rule Engine에서 강제
- [x] 가족사칭 시 메시지 속 새 번호가 아닌 기존 신뢰 연락처 확인을 우선 권고
- [x] 전화·문자·신고·외부 페이지 이동은 실행 전 `pending_action`으로 저장
- [x] 사용자의 명시적 승인 API를 거친 뒤에만 외부 Action 링크 제공
- [x] 실제 통화·신고가 자동 완료된 것처럼 표현하지 않도록 결과 상태 구분

### 6. 공식 대응정보 RAG

- [x] 경찰청 112, 금융감독원 1332, KISA 118 등 공식 대응 절차를 로컬 지식 문서로 구성
- [x] 피해 단계와 질의 키워드 기반의 무비용 로컬 검색 구현
- [x] Supabase pgvector RPC를 실제 RAG 검색 경로로 연결하고 로컬 검색은 장애 폴백으로 유지
- [x] Agent 세션, 공식 연락처, Tool 감사 로그를 Supabase에 영속화
- [x] LLM의 기억보다 검색 결과와 Safety Policy를 응답 작성에 우선 사용
- [x] 응답에 참조 기관과 공식 URL 표시
- [x] 지급정지, 개인정보 노출, 명의도용 통신가입·대출, 악성앱 복구 자료를 포함한 공식 문서 11건 구성
- [x] 보강 문서를 Supabase에 적재하고 원격 pgvector 검색 결과를 실제 연동으로 검증

### 7. 웹 UI/UX

- [x] Compose의 입력·분석·결과·긴급대응 화면을 반응형 웹으로 재현
- [x] 텍스트, URL/전화번호, 이미지 업로드 입력 모드 구현
- [x] 이미지 Drag & Drop, 미리보기, 재선택·삭제, 형식 및 10MB 용량 검증 구현
- [x] 5단계 피해 상황 선택과 세션 Context 표시
- [x] 분석 단계 진행 표시와 위험 점수·사기 유형·위험 및 정상·완화 Evidence 제공
- [x] 입력 확인 → 위험 분석 → 근거 분석 → 공식정보 확인 → 행동 검증 작업 상태 표시
- [x] Multimodal AI → Agent → Solar/RAG → Safety Policy 역할 시각화
- [x] 가장 필요한 Next Action과 단계별 행동 카드 제공
- [x] 송금 여부 선택을 Agent State에 반영하고 후속 Flow 자동 실행
- [x] 6개 Quick Action 및 확인 Modal 구현
- [x] 실제 외부 Action 전 승인 Modal 구현
- [x] 모바일·태블릿·데스크톱, 키보드 조작, 접근성 레이블 대응

### 8. 검증과 품질

- [x] Rule Engine, Safety Policy, State 유지, Tool 선택 단위 테스트
- [x] FastAPI 분석·세션·승인·OCR API 테스트
- [x] 대표 시나리오 7종(정상 URL 클릭, 가족사칭, 기관사칭, 스미싱, 개인정보 입력, 앱 설치, 송금 완료) 검증
- [x] 정상 가족 대화 오탐 방지와 새 상담 Context 초기화 회귀 테스트
- [x] Solar Pro 3, Document Parse, Supabase pgvector, VirusTotal 실제 연동 스모크 테스트 제공
- [x] Python lint 및 전체 테스트 실행
- [x] 웹 페이지 빌드/응답 및 주요 상호작용 확인

## 설계 원칙

```text
User Input
  → Context Understanding
  → Agent Orchestrator
      → Conditional Tool Selection (VirusTotal / 공식번호 / Multimodal)
  → Rule Detection + Solar Candidate Analysis
  → Risk Fusion (URL / Situation / Scam Context 분리)
  → Risk Explanation
  → Situation Classification
  → Conditional Official RAG Retrieval
  → Safety Policy Validation
  → Next Action / Recovery
  → User Approval Gate
```

- **Rule-first**: 긴급 대응과 금전 관련 판단은 LLM 출력과 무관하게 규칙으로 확정합니다.
- **RAG-first**: 신고·복구 절차는 공식 출처 검색 결과를 먼저 사용합니다.
- **Human-in-the-loop**: 실제 전화, 신고, 메시지, 외부 이동은 사용자 승인 없이 실행하지 않습니다.
- **Zero-cost baseline**: 기본 분석·검색·UI는 로컬에서 작동합니다. Solar와 Supabase는 설정 시 활성화되는 선택 기능입니다.

## 기술 구성

| 영역 | 구성 |
|---|---|
| API | FastAPI + Pydantic |
| Agent | LangGraph StateGraph |
| 최종 안전 판단 | Python Rule/Safety Engine |
| 생성형 AI | Upstage Solar (`solar-pro3`, 유형·표현 후보 및 설명) |
| OCR | Upstage Document Digitization (선택 사용) |
| DB/RAG | Supabase Postgres + pgvector RPC, 로컬 폴백 |
| URL 평판 | VirusTotal API v3 기존 보고서 조회 |
| Web UI | Next.js App Router + React + TypeScript |
| Test | pytest + pytest-asyncio |

## 비용 전략

API 키가 없으면 모든 핵심 기능은 로컬 Rule Engine과 로컬 RAG로 동작해 토큰 비용이 발생하지 않습니다. Solar는 키가 있을 때만 짧은 설명 보강에 사용하며, 무료 크레딧을 초과하면 실제 비용이 발생할 수 있으므로 `ENABLE_SOLAR=false`로 즉시 비활성화할 수 있습니다. “항상 0원”이 필요한 운영 환경에서는 Solar/OCR을 끄고 로컬 모드를 사용합니다.

## 빠른 시작

백엔드와 프론트엔드를 각각 별도의 VS Code 터미널에서 실행합니다.

### 1. FastAPI 백엔드

```bash
cd backend
uv sync --extra dev
uv run uvicorn app.main:app --reload
```

`uv`가 없다면 일반 가상환경에서도 실행할 수 있습니다.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m uvicorn app.main:app --reload
```

- Swagger API: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Check: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

### 2. Next.js 프론트엔드

```bash
cd frontend
npm install
npm run dev
```

- 웹 서비스: [http://localhost:3000](http://localhost:3000)
- 로컬의 `/api/*` 요청은 Next.js rewrite를 통해 `http://127.0.0.1:8000`으로 전달됩니다.

## 배포와 CI/CD

- Vercel: `frontend`를 Root Directory로 사용하는 Next.js 프로젝트
- Render: `render.yaml`과 `backend/Dockerfile`을 사용하는 Docker Web Service
- Supabase: 기존 Postgres·pgvector 프로젝트를 서버에서만 사용
- GitHub Actions: `main`, `develop`의 Backend 테스트·lint, Frontend lint·build, Docker image build 검증
- 배포 정책: `develop`은 통합·Vercel Preview, `main`은 운영 배포

환경변수, 브랜치 운영 및 배포 후 점검 방법은 [DEPLOYMENT.md](DEPLOYMENT.md)를 참고합니다.

### Solar와 OCR 활성화

`.env.example`을 `.env`로 복사한 뒤 키와 옵션을 설정합니다.

```dotenv
UPSTAGE_API_KEY=up_xxx
LLM_MODEL=solar-pro3
ENABLE_SOLAR=true
ENABLE_SOLAR_DETECTION=true
ENABLE_OCR=true
SOLAR_MAX_TOKENS=350
```

Solar는 사기 유형·위험 표현의 후보와 설명을 생성합니다. 그러나 기존 위험도를 낮추거나 피해 단계별 하한선·긴급 Action·승인 규칙을 변경할 수 없습니다. OCR은 Upstage Document Digitization 결과를 같은 분석 Flow의 입력으로 사용합니다.

### Supabase DB 활성화

1. Supabase 프로젝트를 생성합니다.
2. `backend`에서 CLI를 연결하고 migration을 적용합니다.
3. 공식 대응문서를 적재합니다.

```bash
cd backend
supabase login
supabase link --project-ref YOUR_PROJECT_REF
supabase db push

source .venv/bin/activate
python -m data.scripts.ingest_rag
```

`backend/.env`에는 서버 전용 secret key를 설정합니다. 이 키는 프론트엔드나 `NEXT_PUBLIC_*` 환경변수에 넣으면 안 됩니다.

```dotenv
ENABLE_SUPABASE=true
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SECRET_KEY=sb_secret_xxx
```

신규 Supabase 프로젝트에서는 backend에 `sb_secret_...` 키를 사용합니다. Legacy 프로젝트만 `SUPABASE_SERVICE_ROLE_KEY`에 service_role JWT를 넣습니다. `sb_publishable_...` 키는 RLS를 우회하지 못하므로 서버 저장용으로 선택되지 않습니다.

적용되는 테이블은 `scam_sessions`, `scam_documents`, `official_contacts`, `tool_audit_logs`입니다. 키가 없거나 연결이 실패하면 세션과 RAG는 인메모리·로컬 JSON으로 폴백합니다.

### URL 평판 API 활성화

VirusTotal에는 URL을 새로 제출하지 않고 이미 존재하는 분석 보고서만 조회합니다.

```dotenv
ENABLE_URL_REPUTATION=true
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_API_KEY
```

`not_found` 또는 `no_detection`은 안전 판정이 아닙니다. 악성 탐지가 있을 때만 Safety Engine이 위험도를 상향하며, 외부 API 결과가 기존 위험도를 낮추지는 않습니다.

## 주요 API

| Method | Path | 설명 |
|---|---|---|
| `POST` | `/api/v1/analyze` | 텍스트·URL·전화번호 분석 |
| `POST` | `/api/v1/analyze/image` | 캡처 OCR 후 분석 |
| `GET` | `/api/v1/sessions/{session_id}` | 현재 Agent State 조회 |
| `DELETE` | `/api/v1/sessions/{session_id}` | 새 상담을 위한 State 초기화 |
| `POST` | `/api/v1/actions/request` | 외부 Action 승인 요청 생성 |
| `POST` | `/api/v1/actions/approve` | 사용자 승인 또는 취소 처리 |

## 프로젝트 구조

```text
backend/
├── app/                       # FastAPI, LangGraph, Rule, Tool, Service
├── data/                      # 공식 대응정보와 Supabase RAG 스키마
├── supabase/migrations/       # DB 테이블·pgvector RPC migration
├── tests/                     # Agent·API 테스트
├── pyproject.toml
└── Dockerfile
frontend/
├── app/                       # Next.js App Router 화면·스타일·메타데이터
├── lib/api.ts                 # API 호출 공통 모듈
├── next.config.mjs            # 로컬 FastAPI rewrite
├── package.json
└── .env.example
```

## 테스트

```bash
cd backend
uv run pytest
```

현재 테스트는 주요 사기 유형, 분리된 위험축, 정상 URL 클릭 회귀, 의심 URL·피싱 정황 결합, 조건부 Tool/RAG 선택, LangGraph 분기, 세션 유지, 외부 Action 승인, OCR 비활성 폴백을 검증합니다. `/api/v1/health`의 `integrations`에서 Solar, OCR, Supabase, VirusTotal 활성 상태도 확인할 수 있습니다.

실제 키와 외부 API까지 확인하려면 민감정보가 없는 테스트 이미지를 준비한 뒤 다음 명령을 실행합니다. 이 명령은 이미지 파일을 Upstage Document Parse로 전송합니다.

```bash
cd backend
python -m scripts.smoke_live_integrations --image /absolute/path/to/safe-test.png
```

출력에는 키나 OCR 원문을 포함하지 않고, 연동 성공 여부·모델명·문서 수·검색 방식만 표시합니다.

### Docker 실행

```bash
docker build -t scamflow-agent backend
docker run --rm -p 8000:8000 --env-file backend/.env scamflow-agent
```

FastAPI 애플리케이션이므로 일반적인 Python 컨테이너 호스팅 환경에 배포할 수 있습니다. 운영 환경의 환경변수에 Supabase secret key와 필요한 API 키를 서버 비밀값으로 등록해야 합니다.

## Vercel 배포

Vercel에서 저장소를 Import한 뒤 **Root Directory를 `frontend`로 지정**합니다. 공식 Vercel monorepo 방식과 동일하게 프론트엔드 디렉터리만 Next.js 프로젝트로 배포됩니다.

배포된 FastAPI 주소를 다음 환경변수에 설정합니다.

```dotenv
SCAMFLOW_BACKEND_URL=https://your-scamflow-api.example.com
```

Next.js의 `/api/*` rewrite가 해당 FastAPI 서버로 요청을 전달하므로 브라우저에는 백엔드 주소가 직접 노출되지 않습니다. FastAPI는 Render, Railway, Fly.io 또는 다른 Python 컨테이너 환경에 별도로 배포해야 합니다.
