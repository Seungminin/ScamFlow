"""ScamFlow LangGraph 컴파일."""

from functools import lru_cache

from langgraph.graph import END, START, StateGraph

from app.graph.edges import (
    route_after_detection,
    route_after_orchestrator,
    route_to_action_or_recovery,
)
from app.graph.nodes import (
    action_node,
    context_node,
    detection_node,
    explanation_node,
    orchestrator_node,
    policy_node,
    rag_node,
    recovery_node,
    response_policy_node,
    scenario_node,
    scenario_rag_node,
    tool_node,
)
from app.graph.state import ScamFlowState


@lru_cache(maxsize=1)
def get_scamflow_graph():
    graph = StateGraph(ScamFlowState)
    graph.add_node("context", context_node)
    graph.add_node("scenario", scenario_node)
    graph.add_node("scenario_rag", scenario_rag_node)
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("tools", tool_node)
    graph.add_node("detection", detection_node)
    graph.add_node("rag", rag_node)
    graph.add_node("response_policy", response_policy_node)
    graph.add_node("explanation", explanation_node)
    graph.add_node("policy", policy_node)
    graph.add_node("action", action_node)
    graph.add_node("recovery", recovery_node)
    graph.add_edge(START, "context")
    graph.add_edge("context", "scenario")
    graph.add_edge("scenario", "scenario_rag")
    graph.add_edge("scenario_rag", "orchestrator")
    graph.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        {"tools": "tools", "detection": "detection"},
    )
    graph.add_edge("tools", "detection")
    graph.add_conditional_edges(
        "detection",
        route_after_detection,
        {"rag": "rag", "explanation": "response_policy"},
    )
    graph.add_edge("rag", "response_policy")
    graph.add_edge("response_policy", "explanation")
    graph.add_edge("explanation", "policy")
    graph.add_conditional_edges(
        "policy",
        route_to_action_or_recovery,
        {"action": "action", "recovery": "recovery"},
    )
    graph.add_edge("action", END)
    graph.add_edge("recovery", END)
    return graph.compile()
