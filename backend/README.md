# ScamFlow Backend

FastAPI, LangGraph, Rule Engine, Scenario RAG 및 Response Policy RAG로 구성된 ScamFlow API 서버입니다.

로컬 실행과 배포 방법은 저장소 루트의 `README.md`와 `DEPLOYMENT.md`를 참고합니다.

운영 서버의 준비 상태는 `GET /api/v1/health`로 확인합니다. 현재 Render 배포 주소는
`https://scamflow-api.onrender.com`이며, 응답의 `integrations` 필드에서 Solar, OCR,
Supabase, URL 평판 조회와 두 RAG 인덱스의 활성 상태를 확인할 수 있습니다.

운영 배포는 GitHub `main` 브랜치와 연결되며, Render가 `backend/` 변경을 감지해
Docker 이미지를 다시 빌드하고 헬스체크 통과 후 새 버전으로 전환합니다.
