"""대화가 이어져도 피해 상황을 보존하는 Agent State."""

from typing import Any, TypedDict


class ScamFlowState(TypedDict, total=False):
    session_id: str
    user_id: str | None
    messages: list[dict[str, str]]
    user_input: str
    analysis_text: str
    input_mode: str
    situation_stage: str
    stage_confirmation: str
    trusted_contact_name: str | None
    structured_input: dict[str, Any]
    scenario_hypothesis: dict[str, Any]
    scenario_rag_query: str
    scenario_rag_results: list[dict[str, Any]]
    response_policy_results: list[dict[str, Any]]
    recommended_actions: list[str]
    rag_debug: dict[str, Any]
    selected_tools: list[str]
    agent_decisions: list[str]
    needs_rag: bool
    solar_selected: bool
    tool_results: dict[str, Any]
    tools_used: list[dict]
    detection: dict[str, Any]
    ai_analysis: dict[str, Any]
    solar_used: bool
    sources: list[dict]
    explanation: str
    follow_up_questions: list[str]
    actions: list[dict]
    pending_action: dict | None
    flow_stage: str
    next_action: str
    safety_notice: str
    model_mode: str
    context_summary: str
    suggested_next_action: str
    interactive_agent: dict[str, Any]
    updated_at: str


def create_initial_state(session_id: str, user_id: str | None = None) -> ScamFlowState:
    return {
        "session_id": session_id,
        "user_id": user_id,
        "messages": [],
        "situation_stage": "received_message",
        "stage_confirmation": "not_required",
        "selected_tools": [],
        "scenario_hypothesis": {},
        "scenario_rag_query": "",
        "scenario_rag_results": [],
        "response_policy_results": [],
        "recommended_actions": [],
        "rag_debug": {
            "enabled": False,
            "scenario_enabled": False,
            "response_policy_enabled": True,
            "scenario_results": [],
            "response_policy": [],
        },
        "agent_decisions": [],
        "needs_rag": False,
        "solar_selected": False,
        "tool_results": {},
        "tools_used": [],
        "sources": [],
        "follow_up_questions": [],
        "actions": [],
        "pending_action": None,
        "flow_stage": "detection",
        "model_mode": "local-rule-engine",
    }
