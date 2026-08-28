"""사기 판정 이후 피해 단계별 행동을 검색하는 Response Policy RAG."""

import json
from pathlib import Path

STAGE_ALIASES = {
    "received_message": "MESSAGE_RECEIVED",
    "clicked_link": "LINK_CLICKED",
    "entered_info": "INFO_ENTERED",
    "installed_app": "APP_INSTALLED",
    "transferred_money": "MONEY_SENT",
}

SCENARIO_GROUPS = {
    "institution_impersonation": {"financial_institution_impersonation", "government_impersonation", "card_payment_impersonation"},
    "smishing": {"delivery_customs_smishing", "card_payment_impersonation"},
    "remote_control_app": {"malicious_app", "malicious_app_installation"},
}


class ResponsePolicyRag:
    def __init__(self, data_path: Path | None = None) -> None:
        self.data_path = data_path or Path(__file__).parents[2] / "data" / "rag" / "response_policy" / "policies.json"
        self._policies: list[dict] | None = None

    def search(self, scenario: str, exposure_stage: str, risk_level: str, limit: int = 3) -> list[dict]:
        policies = self._load()
        normalized_stage = STAGE_ALIASES.get(exposure_stage, exposure_stage.upper())
        normalized_risk = _risk_bucket(risk_level)
        scored: list[tuple[int, dict]] = []
        for policy in policies:
            related = SCENARIO_GROUPS.get(scenario, set())
            scenario_score = (
                8 if policy["scenario"] == scenario
                else 6 if policy["scenario"] in related
                else 2 if policy["scenario"] == "*"
                else 0
            )
            stage_score = 6 if policy["exposure_stage"] == normalized_stage else 1 if policy["exposure_stage"] == "*" else 0
            compatible_high = normalized_risk == "CRITICAL" and policy["risk_level"] == "HIGH"
            risk_score = 4 if policy["risk_level"] == normalized_risk else 3 if compatible_high else 1 if policy["risk_level"] == "*" else 0
            if scenario_score and stage_score and risk_score:
                scored.append((scenario_score + stage_score + risk_score, policy))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [{**policy, "retrieval": "response-policy-local"} for _, policy in scored[:limit]]

    def recommended_actions(self, results: list[dict]) -> list[str]:
        actions: list[str] = []
        for result in results:
            for action in result.get("actions", []):
                if action not in actions:
                    actions.append(action)
        return actions[:6]

    def _load(self) -> list[dict]:
        if self._policies is None:
            self._policies = json.loads(self.data_path.read_text(encoding="utf-8"))
        return self._policies


def _risk_bucket(risk_level: str) -> str:
    return {
        "critical": "CRITICAL",
        "warning": "HIGH",
        "low": "LOW",
    }.get(risk_level.lower(), risk_level.upper())
