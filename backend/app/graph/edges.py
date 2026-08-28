"""피해 발생 여부에 따른 Action/Recovery 분기."""

from app.graph.state import ScamFlowState


def route_after_orchestrator(state: ScamFlowState) -> str:
    return "tools" if state.get("selected_tools") else "detection"


def route_after_detection(state: ScamFlowState) -> str:
    return "rag" if state.get("needs_rag") else "explanation"


def route_to_action_or_recovery(state: ScamFlowState) -> str:
    confirmed_transfer = (
        state["situation_stage"] == "transferred_money"
        and state.get("stage_confirmation") == "confirmed"
    )
    if state["situation_stage"] in {"entered_info", "installed_app"} or confirmed_transfer:
        return "recovery"
    return "action"
