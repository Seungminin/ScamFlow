"""실제 외부 연동을 비밀값 노출 없이 점검하는 수동 스모크 테스트."""

import argparse
import asyncio
import base64
import json
from pathlib import Path

import httpx

from app.core.config import settings
from app.graph.graph import get_scamflow_graph
from app.graph.state import create_initial_state
from app.services.context_extractor import extract_structured_context
from app.services.ocr import OcrService
from app.services.rag import OfficialKnowledgeRepository
from app.services.reputation import UrlReputationService
from app.services.solar import SolarEnricher
from app.services.supabase import supabase_gateway


async def main(image_path: Path | None) -> int:
    checks: dict[str, dict] = {}

    solar = await SolarEnricher().analyze(
        "엄마 새 번호야. 전화는 안돼. 급하니 상품권 핀번호를 지금 보내줘.",
        "received_message",
        {
            "new_contact": True,
            "urgency": True,
            "money_request": True,
            "contact_avoidance": True,
            "relationship_mention": True,
            "family_impersonation": True,
            "urls": [],
        },
        {},
    )
    checks["solar"] = {
        "ok": bool(solar),
        "model": settings.llm_model,
        "scam_type": solar.get("scam_type") if solar else None,
    }

    normal_text = (
        "엄마가 너도 빨리 집에 오라고 했어. 학교 끝나면 픽업하고 갈 때 전화할게."
    )
    normal_solar = await SolarEnricher().analyze(
        normal_text,
        "received_message",
        extract_structured_context(normal_text),
        {},
    )
    checks["solar_negative_evidence"] = {
        "ok": bool(normal_solar.get("negative_evidence"))
        and normal_solar.get("scam_type") != "family_impersonation",
        "scam_type": normal_solar.get("scam_type"),
        "negative_count": len(normal_solar.get("negative_evidence", [])),
    }

    documents = await supabase_gateway.request(
        "GET", "scam_documents", params={"select": "id", "limit": "100"}
    )
    checks["supabase"] = {
        "ok": isinstance(documents, list) and bool(documents),
        "document_count": len(documents) if isinstance(documents, list) else 0,
    }

    rag_results = await OfficialKnowledgeRepository().search(
        "개인정보와 신분증 정보를 입력했습니다", "unknown", "entered_info", limit=3
    )
    checks["rag"] = {
        "ok": bool(rag_results)
        and all(item.get("retrieval") == "supabase-pgvector" for item in rag_results),
        "retrieval": rag_results[0].get("retrieval") if rag_results else None,
        "result_count": len(rag_results),
    }

    agent_result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("live-smoke-agent"),
            "user_input": "엄마 새 번호야. 전화는 안돼. 급하니 상품권 핀번호를 지금 보내줘.",
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )
    checks["agent_graph"] = {
        "ok": agent_result["detection"]["scam_type"] == "family_impersonation"
        and agent_result.get("model_mode") == "solar-assisted"
        and bool(agent_result.get("sources")),
        "model_mode": agent_result.get("model_mode"),
        "flow_stage": agent_result.get("flow_stage"),
        "rag_selected": agent_result.get("needs_rag"),
    }

    normal_agent = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("live-smoke-normal-agent"),
            "user_input": normal_text,
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )
    checks["normal_agent_graph"] = {
        "ok": normal_agent["detection"]["scam_type"] != "family_impersonation"
        and normal_agent["detection"]["risk_level"] == "low"
        and bool(normal_agent["detection"].get("negative_evidence")),
        "scam_type": normal_agent["detection"]["scam_type"],
        "risk_score": normal_agent["detection"]["risk_score"],
        "negative_count": len(normal_agent["detection"].get("negative_evidence", [])),
    }

    reputation = await UrlReputationService().lookup("https://www.naver.com/")
    checks["virustotal"] = {
        "ok": bool(reputation),
        "status": reputation[0].get("status") if reputation else None,
    }

    if image_path:
        encoded = base64.b64encode(image_path.read_bytes()).decode()
        try:
            text = await OcrService().extract(encoded, image_path.name)
            checks["document_parse"] = {
                "ok": bool(text.strip()),
                "characters": len(text.strip()),
            }
        except (ValueError, OSError, httpx.HTTPError) as exc:
            checks["document_parse"] = {"ok": False, "error": type(exc).__name__}

    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if all(check["ok"] for check in checks.values()) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path)
    arguments = parser.parse_args()
    raise SystemExit(asyncio.run(main(arguments.image)))
