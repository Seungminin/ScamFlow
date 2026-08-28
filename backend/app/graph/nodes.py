"""Scenario → Retrieval → Verification → Policy → Action 노드."""

import asyncio

from loguru import logger

from app.core.config import settings
from app.graph.state import ScamFlowState
from app.rag.response_policy_rag import ResponsePolicyRag
from app.rag.scenario_rag import ScenarioRag
from app.schemas.chat import SituationStage
from app.services.context_extractor import extract_structured_context
from app.services.rag import OfficialKnowledgeRepository
from app.services.rules import SafetyPolicy, ScamRuleEngine
from app.services.scenario import ScenarioUnderstandingService
from app.services.solar import SolarEnricher
from app.tools.executor import ToolExecutor

rule_engine = ScamRuleEngine()
safety_policy = SafetyPolicy()
knowledge = OfficialKnowledgeRepository()
tool_executor = ToolExecutor(knowledge)
solar = SolarEnricher()
scenario_engine = ScenarioUnderstandingService()
scenario_rag = ScenarioRag()
response_policy_rag = ResponsePolicyRag()

STAGE_LABELS = {
    "received_message": "메시지만 받음",
    "clicked_link": "링크 클릭",
    "entered_info": "정보 입력",
    "installed_app": "앱 설치",
    "transferred_money": "송금 완료",
}


async def context_node(state: ScamFlowState) -> dict:
    text = state["user_input"]
    messages = [*state.get("messages", []), {"role": "user", "content": text}][-12:]
    user_context = "\n".join(
        message["content"]
        for message in messages
        if message.get("role") == "user"
    )[-8000:]
    structured = extract_structured_context(user_context)
    if settings.environment == "development":
        logger.debug(f"[EVENT] message_purpose = {structured.get('message_purpose')}")
        for event_name, event in structured.get("validated_events", {}).items():
            logger.debug(
                f"[EVENT] {event_name} = {event.get('value')} "
                f"evidence = {event.get('evidence')!r}"
            )
        logger.debug(
            f"[EVENT] validated_events = "
            f"{[name for name, event in structured.get('validated_events', {}).items() if event.get('value')]}"
        )
    return {
        "messages": messages,
        "analysis_text": user_context,
        "structured_input": structured,
        "selected_tools": [],
        "tool_results": {},
        "tools_used": [],
        "sources": [],
        "scenario_rag_query": "",
        "scenario_rag_results": [],
        "response_policy_results": [],
        "recommended_actions": [],
        "rag_debug": {
            "enabled": settings.rag_enabled,
            "scenario_enabled": settings.rag_enabled,
            "response_policy_enabled": True,
            "scenario_results": [],
            "response_policy": [],
        },
        "needs_rag": False,
        "flow_stage": "detection",
    }


async def scenario_node(state: ScamFlowState) -> dict:
    """Entity/Event 관계에서 Tool 호출 전 사기 가설을 생성합니다."""
    structured = state.get("structured_input", {})
    local_hypothesis = scenario_engine.analyze(structured)
    llm_hypothesis = await solar.hypothesize(
        state.get("analysis_text", state["user_input"]),
        structured,
    )
    hypothesis = scenario_engine.merge_llm(local_hypothesis, llm_hypothesis)
    if settings.environment == "development":
        logger.debug(f"[AGENT] scenario_hypothesis: {hypothesis}")
    traces = [
        {
            "name": "entity_event_extraction",
            "status": "completed",
            "summary": "Entity·Event·시스템 안내 metadata 구조화",
        },
        {
            "name": "scenario_hypothesis",
            "status": "completed",
            "summary": f"{hypothesis['label']} 가설 {round(float(hypothesis['confidence']) * 100)}%",
        },
    ]
    return {
        "scenario_hypothesis": hypothesis,
        "tools_used": traces,
        "solar_used": bool(llm_hypothesis),
    }


async def orchestrator_node(state: ScamFlowState) -> dict:
    """입력 Context를 보고 필요한 Tool만 선택하는 명시적 Agent 의사결정 노드."""
    tools = tool_executor.select_tools(
        state.get("analysis_text", state["user_input"]),
        state.get("input_mode", "text"),
        state.get("structured_input", {}),
        state.get("scenario_hypothesis", {}),
    )
    decisions = [f"{tool} 선택" for tool in tools]
    if not decisions:
        decisions.append("외부 Tool 없이 규칙 기반 Context 분석 선택")
    if settings.environment == "development":
        logger.debug(f"selected_tools: {tools}")
    return {
        "selected_tools": tools,
        "agent_decisions": decisions,
        "tools_used": [*state.get("tools_used", []), {
            "name": "agent_orchestrator",
            "status": "completed",
            "summary": " · ".join(decisions),
        }],
    }


async def scenario_rag_node(state: ScamFlowState) -> dict:
    """Agent 가설을 smishing.csv 유사 사례로 보강하되 확정 판단은 하지 않습니다."""
    if not settings.rag_enabled:
        return {}
    hypothesis = state.get("scenario_hypothesis", {})
    try:
        retrieved = await asyncio.to_thread(
            scenario_rag.search,
            state.get("analysis_text", state["user_input"]),
            state.get("structured_input", {}),
            hypothesis,
        )
    except Exception as exc:  # RAG 실패는 기존 Agent+Rule 분석을 중단시키지 않습니다.
        logger.warning(f"[RAG] scenario retrieval fallback: {exc}")
        return {
            "rag_debug": {
                "enabled": True,
                "scenario_enabled": True,
                "response_policy_enabled": True,
                "scenario_query": "",
                "scenario_results": [],
                "response_policy": [],
            }
        }

    evidence = retrieved["evidence"]
    risk_axes = dict(hypothesis.get("risk_axes", {}))
    risk_axes["scenario_rag"] = {
        "score": int(evidence.get("risk_score", 0)),
        "reasons": evidence.get("reasons", []),
    }
    hypothesis = {**hypothesis, "risk_axes": risk_axes, "rag_evidence": evidence}
    if settings.environment == "development":
        logger.debug(f"[RAG] scenario_query: {retrieved['query']}")
        for item in retrieved["results"]:
            logger.debug(
                "[RAG] scenario_result: "
                f"label={item.get('label')} type={item.get('type')} "
                f"similarity={item.get('similarity')}"
            )
    return {
        "scenario_hypothesis": hypothesis,
        "scenario_rag_query": retrieved["query"],
        "scenario_rag_results": retrieved["results"],
        "rag_debug": {
            "enabled": True,
            "scenario_enabled": True,
            "response_policy_enabled": True,
            "scenario_query": retrieved["query"],
            "scenario_results": retrieved["results"],
            "response_policy": [],
        },
    }


async def tool_node(state: ScamFlowState) -> dict:
    results, traces = await tool_executor.execute_selected(
        state["selected_tools"],
        state.get("analysis_text", state["user_input"]),
        state.get("session_id"),
        state.get("structured_input", {}),
        state.get("scenario_hypothesis", {}),
        state.get("situation_stage", "received_message"),
    )
    if settings.environment == "development":
        logger.debug(f"[TOOL] selected_tools: {state['selected_tools']}")
        logger.debug(f"[TOOL] result_keys: {sorted(results)}")
        for url_result in results.get("urls", []):
            logger.debug(
                "[TOOL] url_verification: "
                f"host={url_result.get('host')} risk_score={url_result.get('risk_score')} "
                f"providers={[item.get('provider') for item in url_result.get('reputation', [])]}"
            )
    return {"tool_results": results, "tools_used": [*state.get("tools_used", []), *traces]}


async def detection_node(state: ScamFlowState) -> dict:
    stage = SituationStage(state["situation_stage"])
    analysis_text = state.get("analysis_text", state["user_input"])
    structured = state.get("structured_input", {})
    stage_confirmation = state.get("stage_confirmation", "not_required")
    detection = rule_engine.detect(
        analysis_text,
        stage,
        structured,
        stage_confirmation,
        state.get("scenario_hypothesis", {}),
    )
    verified_hypothesis = scenario_engine.apply_external_evidence(
        state.get("scenario_hypothesis", {}),
        state.get("tool_results", {}),
    )
    solar_candidate = {}
    detection = rule_engine.merge_verified_evidence(
        detection,
        stage,
        solar_candidate,
        state.get("tool_results", {}),
        structured,
        stage_confirmation,
        verified_hypothesis,
    )
    if settings.environment == "development":
        logger.debug(f"context risk: {detection.risk_breakdown['conversation_context']}")
        logger.debug(f"exposure risk: {detection.risk_breakdown['exposure_risk']}")
        logger.debug(f"final score: {detection.risk_score}")
        logger.debug(f"[AGENT] scam_likelihood: {detection.risk_score}")
        logger.debug(f"[AGENT] exposure_stage: {stage.value}")
    needs_rag = bool(
        detection.risk_score >= 45
        or stage in {SituationStage.ENTERED_INFO, SituationStage.INSTALLED_APP}
        or (stage == SituationStage.TRANSFERRED_MONEY and stage_confirmation == "confirmed")
        or detection.scam_type not in {"unknown", "safe_message"}
    )
    decisions = [*state.get("agent_decisions", [])]
    decisions.append("공식 대응정보 RAG 검색 선택" if needs_rag else "공식 대응정보 검색 생략")
    return {
        "detection": {
            "scam_type": detection.scam_type,
            "risk_level": detection.risk_level,
            "risk_score": detection.risk_score,
            "headline": detection.headline,
            "explanation": detection.explanation,
            "highlights": [item.model_dump() for item in detection.highlights],
            "negative_evidence": [
                item.model_dump() for item in detection.negative_evidence
            ],
            "risk_breakdown": detection.risk_breakdown,
            "scenario_assessment": detection.scenario_assessment,
        },
        "ai_analysis": verified_hypothesis.get("llm_candidate", {}),
        "scenario_hypothesis": verified_hypothesis,
        "solar_selected": bool(verified_hypothesis.get("llm_candidate")),
        "needs_rag": needs_rag,
        "agent_decisions": decisions,
    }


async def rag_node(state: ScamFlowState) -> dict:
    detection = state["detection"]
    sources = await knowledge.search(
        state.get("analysis_text", state["user_input"]),
        detection["scam_type"],
        state["situation_stage"],
    )
    traces = [*state.get("tools_used", []), {
        "name": "official_rag_search",
        "status": "completed",
        "summary": f"공식 대응정보 {len(sources)}건 검색",
    }]
    return {"sources": sources, "tools_used": traces, "flow_stage": "verification"}


async def response_policy_node(state: ScamFlowState) -> dict:
    """Scam Likelihood 판정 완료 후에만 피해 단계별 대응 정책을 검색합니다."""
    detection = state["detection"]
    try:
        results = await asyncio.to_thread(
            response_policy_rag.search,
            detection["scam_type"],
            state["situation_stage"],
            detection["risk_level"],
        )
        recommended = response_policy_rag.recommended_actions(results)
    except Exception as exc:  # 정책 파일 문제에도 기존 SafetyPolicy로 fallback
        logger.warning(f"[RAG] response policy fallback: {exc}")
        results, recommended = [], []
    debug = {
        **state.get("rag_debug", {"enabled": settings.rag_enabled}),
        "scenario_enabled": settings.rag_enabled,
        "response_policy_enabled": True,
        "response_policy": results,
    }
    if settings.environment == "development":
        logger.debug(f"[RAG] response_policy: {results}")
        logger.debug(f"[FINAL] recommended_actions: {recommended}")
    return {
        "response_policy_results": results,
        "recommended_actions": recommended,
        "rag_debug": debug,
    }


async def explanation_node(state: ScamFlowState) -> dict:
    detection = state["detection"]
    enriched = {}
    rag_evidence = state.get("scenario_hypothesis", {}).get("rag_evidence", {})
    scenario_examples_for_solar = (
        state.get("scenario_rag_results", [])
        if rag_evidence.get("applicable")
        else []
    )
    if not rag_evidence.get("normal_guardrail") and (
        state.get("solar_selected")
        or state.get("scenario_rag_results")
        or state.get("response_policy_results")
    ) and (
        detection["risk_score"] >= 45
        or state.get("sources")
        or state.get("scenario_rag_results")
        or state.get("response_policy_results")
    ):
        enriched = await solar.enrich(
            state.get("analysis_text", state["user_input"]),
            detection,
            state.get("sources", []),
            structured_input=state.get("structured_input", {}),
            scenario_hypothesis=state.get("scenario_hypothesis", {}),
            tool_results=state.get("tool_results", {}),
            scenario_rag_results=scenario_examples_for_solar,
            response_policy_results=state.get("response_policy_results", []),
        )
    questions = enriched.get("follow_up_questions", [])[:3]
    if not questions:
        questions = _local_follow_up_questions(state)
    explanation = safety_policy.validate_explanation(
        enriched.get("explanation", ""), detection["explanation"]
    )
    return {
        "explanation": explanation,
        "follow_up_questions": questions,
        "suggested_next_action": enriched.get("next_action_suggestion", ""),
        "model_mode": (
            "solar-rag-assisted" if enriched or state.get("solar_used")
            else "rag-assisted"
        ),
        "flow_stage": "explanation",
    }


async def policy_node(state: ScamFlowState) -> dict:
    stage = SituationStage(state["situation_stage"])
    stage_confirmation = state.get("stage_confirmation", "not_required")
    policy_scam_type = (
        "family_impersonation"
        if state.get("structured_input", {}).get("identity_grooming")
        else state["detection"]["scam_type"]
    )
    actions = safety_policy.actions_for(policy_scam_type, stage, stage_confirmation)
    rag_actions = state.get("recommended_actions", [])
    fallback_action = (
        rag_actions[0]
        if rag_actions
        else actions[0]["title"] if actions
        else "공식 기관을 통해 사실관계를 확인하세요."
    )
    if stage == SituationStage.TRANSFERRED_MONEY and stage_confirmation != "confirmed":
        next_action = "이 대화 상대의 요청으로 실제 돈이나 상품권을 보냈는지 먼저 확인하세요."
    else:
        next_action = safety_policy.validate_next_action(
            state.get("suggested_next_action", ""),
            fallback_action,
            actions[0]["id"] if actions else "",
        )
    context_summary = (
        f"피해 단계: {STAGE_LABELS[stage.value]} · 유형: {state['detection']['scam_type']} · "
        f"단계 확인: {stage_confirmation} · Scam Likelihood: {state['detection']['risk_score']}점 · "
        f"대화 {len(state.get('messages', []))}건"
    )
    return {
        "actions": actions,
        "next_action": next_action,
        "safety_notice": safety_policy.NOTICE,
        "context_summary": context_summary,
    }


async def action_node(state: ScamFlowState) -> dict:
    return {"flow_stage": "action"}


async def recovery_node(state: ScamFlowState) -> dict:
    return {"flow_stage": "recovery"}


def _local_follow_up_questions(state: ScamFlowState) -> list[str]:
    stage = state["situation_stage"]
    questions: list[str] = []
    if stage == "transferred_money" and state.get("stage_confirmation") != "confirmed":
        return ["이 대화 상대의 요청으로 실제 돈이나 상품권을 전달했나요?"]
    if state.get("structured_input", {}).get("identity_grooming"):
        return [
            "이 메시지는 평소 저장된 가족 번호에서 왔나요?",
            "평소 저장된 가족 번호로 직접 통화해 본인임을 확인했나요?",
            "상대방이 부탁의 구체적인 내용을 추가로 보냈나요?",
        ]
    if stage == "received_message":
        questions.append("링크를 누르거나 파일을 내려받았나요?")
    if stage in {"clicked_link", "entered_info"}:
        questions.append("앱 설치 또는 화면 공유를 허용했나요?")
    if stage != "transferred_money":
        questions.append("이미 돈이나 상품권 핀번호를 전달했나요?")
    if state["detection"]["scam_type"] == "family_impersonation":
        questions.append("평소 저장된 가족 번호로 직접 통화해 확인했나요?")
    return questions[:3]
