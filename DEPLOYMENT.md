# ScamFlow 배포 운영 가이드

## 배포 구조

- `main`: 운영 브랜치. GitHub CI 성공 후 Render가 FastAPI를 배포하고 Vercel이 Next.js 운영 배포를 생성합니다.
- `develop`: 통합·검증 브랜치. GitHub CI와 Vercel Preview 배포를 사용합니다.
- Backend: Render Docker Web Service (`backend/Dockerfile`)
- Frontend: Vercel Next.js Project (Root Directory: `frontend`)
- Database: 기존 Supabase 프로젝트

기능 브랜치를 장기간 유지하지 않고 필요한 변경은 `develop`에서 검증한 뒤 Pull Request로 `main`에 병합합니다.

## Render

저장소 루트의 `render.yaml`을 Blueprint로 연결합니다. 서비스는 Singapore 리전에 생성되고 `/api/v1/health`가 준비 상태 확인에 사용됩니다. `autoDeployTrigger: checksPass`이므로 `main`의 GitHub CI가 성공한 커밋만 배포됩니다.

Blueprint 생성 시 다음 비밀 환경변수를 Render Dashboard에 입력합니다.

```text
UPSTAGE_API_KEY
SUPABASE_URL
SUPABASE_SECRET_KEY
GOOGLE_SAFE_BROWSING_API_KEY
KISA_WHOIS_API_KEY
VIRUSTOTAL_API_KEY
FRONTEND_ORIGINS
```

`FRONTEND_ORIGINS`에는 Vercel 운영 주소를 입력합니다. 여러 주소는 쉼표로 구분합니다.

```text
https://scam-flow.vercel.app,https://your-custom-domain.example
```

Docker 이미지에는 공개 Scenario RAG 데이터셋을 SHA-256으로 검증한 뒤 인덱스를 미리 생성합니다. API 키와 Supabase 키는 Docker 빌드에서 참조하지 않으며 런타임 환경변수로만 사용합니다.

## Vercel

GitHub 저장소를 Vercel Project로 가져온 뒤 다음 값을 설정합니다.

- Framework Preset: Next.js
- Root Directory: `frontend`
- Production Branch: `main`
- Environment Variable: `SCAMFLOW_BACKEND_URL=https://scamflow-api.onrender.com`

`SCAMFLOW_BACKEND_URL`은 Production과 Preview에 모두 설정합니다. 브라우저는 같은 출처의 `/api/*`를 호출하고 Next.js 서버가 Render로 전달하므로 백엔드 주소나 키가 클라이언트 번들에 직접 노출되지 않습니다.

## Supabase

DB 마이그레이션은 자동 배포에서 실행하지 않습니다. 운영 데이터에 영향을 주는 변경이므로 검토 후 명시적으로 적용합니다.

```bash
cd backend
supabase link --project-ref YOUR_PROJECT_REF
supabase db push
```

프론트엔드는 Supabase에 직접 연결하지 않습니다. 따라서 서버용 `SUPABASE_SECRET_KEY`를 Vercel이나 `NEXT_PUBLIC_*` 환경변수에 넣지 않습니다.

## 배포 전 확인

```bash
cd backend
uv sync --frozen --extra dev
uv run ruff check app scripts tests
uv run pytest

cd ../frontend
npm ci
npm run lint
npm run build

cd ..
docker build --build-arg INSTALL_SCENARIO_RAG=false -t scamflow-api:ci backend
```

배포 후 다음을 확인합니다.

```bash
curl https://scamflow-api.onrender.com/api/v1/health
curl -I https://YOUR_VERCEL_DOMAIN
```
