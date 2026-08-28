"""ScamFlow FastAPI 애플리케이션 진입점."""

import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.api.routes.scamflow import router as scamflow_router
from app.core.config import settings
from app.graph.graph import get_scamflow_graph
from app.services.supabase import supabase_gateway

logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="DEBUG" if settings.debug else "INFO",
    colorize=True,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("ScamFlow Agent 서버를 시작합니다.")
    logger.info(f"Solar 보강: {settings.enable_solar and bool(settings.upstage_api_key)}")
    logger.info(f"Solar 탐지 보조: {settings.enable_solar_detection and bool(settings.upstage_api_key)}")
    logger.info(f"OCR: {settings.enable_ocr and bool(settings.upstage_api_key)}")
    logger.info(f"Supabase 영속화/RAG: {supabase_gateway.enabled}")
    logger.info(f"Scenario RAG: {settings.rag_enabled}")
    logger.info("Response Policy RAG: True")
    logger.info(f"Google Safe Browsing: {settings.enable_url_reputation and bool(settings.google_safe_browsing_api_key)}")
    logger.info(f"KISA WHOIS: {settings.enable_url_reputation and bool(settings.kisa_whois_api_key)}")
    logger.info(f"VirusTotal URL 평판: {settings.enable_url_reputation and bool(settings.virustotal_api_key)}")
    get_scamflow_graph()
    yield
    logger.info("ScamFlow Agent 서버를 종료합니다.")


app = FastAPI(
    title="ScamFlow Agent API",
    description="Rule Engine, 공식 대응정보 RAG, 선택적 Solar를 결합한 금융사기 대응 Agent",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.frontend_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scamflow_router)


@app.get("/", tags=["Root"])
async def root() -> dict:
    return {
        "service": "scamflow-agent",
        "message": "ScamFlow FastAPI backend",
        "docs": "/docs",
        "health": "/api/v1/health",
    }


@app.get("/api/v1/health", tags=["Health"])
async def health() -> dict:
    solar_enabled = bool(
        settings.upstage_api_key
        and (settings.enable_solar or settings.enable_solar_detection)
    )
    return {
        "status": "healthy",
        "service": "scamflow-agent",
        "mode": "solar-assisted" if solar_enabled else "local-rule-engine",
        "integrations": {
            "solar": solar_enabled,
            "ocr": bool(settings.enable_ocr and settings.upstage_api_key),
            "supabase": supabase_gateway.enabled,
            "virustotal": bool(
                settings.enable_url_reputation and settings.virustotal_api_key
            ),
            "google_safe_browsing": bool(settings.enable_url_reputation and settings.google_safe_browsing_api_key),
            "kisa_whois": bool(settings.enable_url_reputation and settings.kisa_whois_api_key),
            "scenario_rag": settings.rag_enabled,
            "response_policy_rag": True,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
