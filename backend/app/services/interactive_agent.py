"""탐지 결과 이후 실제 노출 상태를 확인하는 대화형 Safety Agent."""

from __future__ import annotations

import re
from typing import Any

from app.rag.response_policy_rag import ResponsePolicyRag

FACTS = (
    "message_received",
    "identity_verified",
    "institution_verified",
    "link_clicked",
    "personal_info_entered",
    "credential_entered",
    "file_downloaded",
    "app_installed",
    "phone_called",
    "credential_shared",
    "account_info_shared",
    "money_sent",
    "gift_card_purchased",
    "gift_card_code_shared",
    "remote_control_installed",
)

QUESTIONS = {
    "identity_verified": ("평소 알고 있던 번호로 가족·지인 본인 여부를 직접 확인했나요?", "사칭 여부를 가장 안전하게 가르는 확인입니다."),
    "institution_verified": ("메시지의 연락처가 아닌 공식 대표번호로 기관 안내가 맞는지 확인했나요?", "표시된 기관명만으로 발신자를 신뢰할 수 없습니다."),
    "link_clicked": ("이 메시지에 포함된 링크를 실제로 눌러 페이지를 열었나요?", "접속 여부에 따라 필요한 보호 조치가 달라집니다."),
    "personal_info_entered": ("열린 페이지에 이름·주소·주민번호 같은 개인정보를 입력했나요?", "입력한 정보의 종류에 따라 후속 보호 조치가 달라집니다."),
    "credential_entered": ("비밀번호·카드정보·인증번호 같은 인증정보를 입력했나요?", "인증정보 노출은 계정과 금융 피해로 이어질 수 있습니다."),
    "file_downloaded": ("링크에서 파일을 내려받았나요?", "다운로드된 파일이 악성앱 설치로 이어질 수 있습니다."),
    "app_installed": ("안내에 따라 앱을 설치하거나 설치 권한을 허용했나요?", "앱 설치 여부는 기기 격리가 필요한지 결정합니다."),
    "phone_called": ("메시지에 적힌 번호로 직접 전화했나요?", "통화 중 추가 정보나 앱 설치를 요구받았을 수 있습니다."),
    "credential_shared": ("통화나 답장으로 인증번호·비밀번호를 알려줬나요?", "인증정보 전달 여부를 확인해야 계정 보호 순서를 정할 수 있습니다."),
    "account_info_shared": ("계좌번호·카드번호 등 금융정보를 알려줬나요?", "금융정보 노출 여부에 따라 금융회사 연락이 필요할 수 있습니다."),
    "money_sent": ("이 메시지나 상대방의 요청과 관련해 실제로 돈을 보냈나요?", "송금이 확인되면 지급정지가 가장 먼저 필요합니다."),
    "gift_card_purchased": ("상대방 요청으로 상품권이나 기프트카드를 이미 구매했나요?", "구매 여부에 따라 결제 취소와 번호 보호 조치가 달라집니다."),
    "gift_card_code_shared": ("구매한 상품권의 핀번호나 사진을 상대방에게 보냈나요?", "번호 전달 여부가 상품권 사용 중지 조치의 긴급도를 결정합니다."),
    "remote_control_installed": ("상대방 안내로 원격제어·보안 앱을 설치했나요?", "원격제어 앱 설치 시 기기를 즉시 네트워크에서 분리해야 합니다."),
}

DOWNSTREAM = {
    "link_clicked": ("personal_info_entered", "credential_entered", "file_downloaded", "app_installed"),
    "gift_card_purchased": ("gift_card_code_shared",),
    "phone_called": ("credential_shared", "account_info_shared", "remote_control_installed"),
}


class InteractiveAgentService:
    def __init__(self, response_policy: ResponsePolicyRag | None = None) -> None:
        self.response_policy = response_policy or ResponsePolicyRag()

    def initialize(self, result: dict[str, Any], initial_hint: str) -> dict[str, Any]:
        detection = result["detection"]
        context = result.get("structured_input", {})
        scenario = self._scenario_group(detection.get("scam_type", "unknown"), context)
        state = {
            "scenario": scenario,
            "scam_likelihood": int(detection.get("risk_score", 0)),
            "status": "questioning",
            "initial_context_hint": initial_hint,
            "exposure_state": dict.fromkeys(FACTS),
            "known_facts": [],
            "unknown_facts": [],
            "questions_asked": [],
            "next_question": None,
            "next_best_action": None,
            "conversation": [],
            "confirmed_details": {},
        }
        state["exposure_state"]["message_received"] = True
        state["_context"] = self._policy_context(context, initial_hint)
        state["_risk_level"] = detection.get("risk_level", "warning")
        state["_scam_type"] = detection.get("scam_type", scenario)
        return self._advance(state)

    def respond(
        self,
        state: dict[str, Any],
        question_id: str | None,
        answer: bool | None,
        message: str | None,
    ) -> dict[str, Any]:
        current = state.get("next_question") or {}
        fact = question_id or current.get("id")
        if fact and fact not in FACTS:
            fact = current.get("id")
        updates = self._extract_fact_updates(message or "")
        amount = self._extract_sent_amount(message or "")
        if amount is not None:
            updates["money_sent"] = True
            state.setdefault("confirmed_details", {})["money_sent_amount"] = amount
        if fact and answer is not None:
            updates[fact] = answer
        elif fact and fact not in updates:
            generic = self._parse_boolean(message or "")
            if generic is not None:
                updates[fact] = generic
        if not updates:
            raise ValueError("답변에서 확인 가능한 행동 여부를 찾지 못했습니다. 예/아니요로 답해주세요.")

        exposure = state["exposure_state"]
        for key, value in updates.items():
            if key in exposure:
                exposure[key] = value
                if value is False:
                    for downstream in DOWNSTREAM.get(key, ()):
                        exposure[downstream] = False
        if fact and fact not in state["questions_asked"]:
            state["questions_asked"].append(fact)
        state["conversation"].append({"role": "user", "content": message or ("네" if answer else "아니요"), "facts": updates})
        return self._advance(state)

    def _advance(self, state: dict[str, Any]) -> dict[str, Any]:
        exposure = state["exposure_state"]
        next_fact = self._next_fact(state)
        state["known_facts"] = [key for key, value in exposure.items() if value is not None]
        state["unknown_facts"] = [key for key, value in exposure.items() if value is None]
        if next_fact:
            text, reason = QUESTIONS[next_fact]
            state["status"] = "questioning"
            state["next_question"] = {"id": next_fact, "text": text, "reason": reason, "answer_type": "boolean"}
            state["next_best_action"] = None
            if next_fact not in state["questions_asked"]:
                state["questions_asked"].append(next_fact)
                state["conversation"].append({"role": "assistant", "content": text, "question_id": next_fact})
            return state

        state["status"] = "action_ready"
        state["next_question"] = None
        state["next_best_action"] = self._next_best_action(state)
        action_title = state["next_best_action"]["title"]
        if not state["conversation"] or state["conversation"][-1].get("content") != action_title:
            state["conversation"].append({"role": "assistant", "content": action_title, "type": "next_best_action"})
        return state

    def _next_fact(self, state: dict[str, Any]) -> str | None:
        scenario = state["scenario"]
        facts = state["exposure_state"]
        context = state.get("_context", {})
        hint = state.get("initial_context_hint", "received_message")

        # 즉시 보호가 필요한 노출은 추가 문답보다 우선 행동을 먼저 제시한다.
        if any(
            facts[key] is True
            for key in ("money_sent", "gift_card_code_shared", "app_installed", "remote_control_installed")
        ):
            return None

        hint_fact = {
            "clicked_link": "link_clicked",
            "entered_info": "personal_info_entered",
            "installed_app": "app_installed",
            "transferred_money": "money_sent",
        }.get(hint)
        if hint_fact and facts[hint_fact] is None:
            return hint_fact

        if scenario == "family_impersonation":
            if context["gift_card"]:
                if facts["gift_card_purchased"] is None:
                    return "gift_card_purchased"
                if facts["gift_card_purchased"] is True and facts["gift_card_code_shared"] is None:
                    return "gift_card_code_shared"
                if facts["gift_card_purchased"] is False or facts["gift_card_code_shared"] is False:
                    return None
            if context["money"] and facts["money_sent"] is None:
                return "money_sent"
            if context["credential"] and facts["credential_shared"] is None:
                return "credential_shared"
            if facts["identity_verified"] is None:
                return "identity_verified"
            return None

        if scenario == "smishing":
            if facts["link_clicked"] is None:
                return "link_clicked"
            if facts["link_clicked"] is False:
                return None
            if context["personal_info"] and facts["personal_info_entered"] is None:
                return "personal_info_entered"
            if context["credential"] and facts["credential_entered"] is None:
                return "credential_entered"
            if context["app"] and facts["file_downloaded"] is None:
                return "file_downloaded"
            if context["app"] and facts["app_installed"] is None:
                return "app_installed"
            return None

        if scenario == "institution_impersonation":
            if context["callback"] and facts["phone_called"] is None:
                return "phone_called"
            if (facts["phone_called"] is True or context["credential"]) and facts["credential_shared"] is None:
                return "credential_shared"
            if facts["phone_called"] is True and facts["account_info_shared"] is None:
                return "account_info_shared"
            if context["money"] and facts["money_sent"] is None:
                return "money_sent"
            if context["app"] and facts["remote_control_installed"] is None:
                return "remote_control_installed"
            if facts["institution_verified"] is None:
                return "institution_verified"
            return None

        # 정상으로 보이는 메시지도 사용자가 선택한 피해 힌트는 위에서 반드시 재확인한다.
        return None

    def _next_best_action(self, state: dict[str, Any]) -> dict[str, Any]:
        facts = state["exposure_state"]
        stage = self._response_stage(facts)
        results = self.response_policy.search(
            state["scenario"],
            stage,
            state.get("_risk_level", "warning"),
            limit=3,
        )
        actions = self.response_policy.recommended_actions(results)
        if not actions:
            actions = ["상대방이 알려준 경로가 아닌 기존 연락처나 공식 대표번호로 사실관계를 확인하세요."]
        first = actions[0]
        description = actions[1] if len(actions) > 1 else "확인이 끝날 때까지 추가 행동을 중단하세요."
        return {
            "title": first,
            "description": description,
            "priority": "critical" if stage in {"MONEY_SENT", "APP_INSTALLED", "REMOTE_CONTROL_INSTALLED"} else "high",
            "policy_id": results[0]["id"] if results else None,
            "follow_up_actions": actions[1:],
        }

    @staticmethod
    def _response_stage(facts: dict[str, bool | None]) -> str:
        if facts["money_sent"]:
            return "MONEY_SENT"
        if facts["gift_card_code_shared"]:
            return "GIFT_CARD_CODE_SHARED"
        if facts["gift_card_purchased"]:
            return "GIFT_CARD_PURCHASED"
        if facts["remote_control_installed"]:
            return "REMOTE_CONTROL_INSTALLED"
        if facts["app_installed"]:
            return "APP_INSTALLED"
        if facts["credential_shared"] or facts["account_info_shared"] or facts["credential_entered"] or facts["personal_info_entered"]:
            return "INFO_ENTERED"
        if facts["phone_called"]:
            return "PHONE_CALLED"
        if facts["link_clicked"]:
            return "LINK_CLICKED"
        return "MESSAGE_RECEIVED"

    @staticmethod
    def _scenario_group(scam_type: str, context: dict[str, Any]) -> str:
        if scam_type in {"family_impersonation", "gift_card_request"} or context.get("family_impersonation"):
            return "family_impersonation"
        if scam_type in {"delivery_customs_smishing", "smishing", "malicious_app"} or (context.get("urls") and not context.get("institution_impersonation")):
            return "smishing"
        if scam_type in {"institution_impersonation", "financial_institution_impersonation", "government_impersonation", "card_payment_impersonation", "credential_theft", "loan_fraud", "remote_control_app"} or context.get("institution_impersonation"):
            return "institution_impersonation"
        return "normal"

    @staticmethod
    def _policy_context(context: dict[str, Any], hint: str) -> dict[str, bool]:
        return {
            "gift_card": bool(context.get("gift_card_request")),
            "money": bool(context.get("money_request") or context.get("financial_request") or hint == "transferred_money"),
            "credential": bool(context.get("authentication_request") or context.get("credential_request")),
            "personal_info": bool(context.get("personal_info_request") or hint == "entered_info"),
            "app": bool(context.get("app_install_request") or hint == "installed_app"),
            "callback": bool(context.get("callback_request") or context.get("phone_numbers")),
        }

    @staticmethod
    def _parse_boolean(text: str) -> bool | None:
        normalized = re.sub(r"\s+", "", text.lower())
        if re.search(r"안했|않았|아니|없어|없습니다|아직안|안보냈|안샀|안눌", normalized):
            return False
        if re.search(r"^(네|예|응|맞아|맞습니다|했어|했습니다|눌렀|보냈|샀|설치)", normalized):
            return True
        return None

    @staticmethod
    def _extract_fact_updates(text: str) -> dict[str, bool]:
        compact = re.sub(r"\s+", "", text.lower())
        updates: dict[str, bool] = {}
        patterns = {
            "gift_card_purchased": (r"(상품권|기프트카드).{0,12}(샀|구매했)", r"(상품권|기프트카드).{0,12}(안샀|구매안|구매하지않)"),
            "gift_card_code_shared": (r"(핀번호|번호|코드|사진).{0,12}(보냈|알려줬|전달했)", r"(핀번호|번호|코드|사진).{0,12}(안보냈|아직안|전달하지않)"),
            "money_sent": (r"(돈|금액|송금|이체).{0,10}(보냈|했어|했습니다|완료)", r"(돈|송금|이체).{0,10}(안보냈|안했|하지않)"),
            "link_clicked": (r"(링크|주소|url).{0,10}(눌렀|열었|들어갔|접속했)", r"(링크|주소|url).{0,10}(안눌|안열|접속안|들어가지않)"),
            "personal_info_entered": (r"(이름|주소|주민번호|개인정보).{0,12}(입력했|적었|썼)", r"(개인정보|주소|주민번호).{0,12}(안입력|입력하지않)"),
            "credential_entered": (r"(비밀번호|인증번호|카드번호).{0,12}(입력했|적었)", r"(비밀번호|인증번호|카드번호).{0,12}(안입력|입력하지않)"),
            "app_installed": (r"(앱|어플).{0,12}(설치했|깔았)", r"(앱|어플).{0,12}(안설치|안깔|설치하지않)"),
            "phone_called": (r"(전화|통화).{0,10}(했|걸었)", r"(전화|통화).{0,10}(안했|안걸|하지않)"),
            "credential_shared": (r"(인증번호|비밀번호).{0,12}(줬|알려줬|보냈|전달했)", r"(인증번호|비밀번호).{0,12}(안줬|안보냈|전달하지않)"),
            "account_info_shared": (r"(계좌|카드번호|금융정보).{0,12}(줬|알려줬|보냈)", r"(계좌|카드번호|금융정보).{0,12}(안줬|안보냈|알려주지않)"),
            "remote_control_installed": (r"(원격|보안앱).{0,12}(설치했|깔았)", r"(원격|보안앱).{0,12}(안설치|안깔|설치하지않)"),
        }
        for fact, (positive, negative) in patterns.items():
            if re.search(negative, compact):
                updates[fact] = False
            elif re.search(positive, compact):
                updates[fact] = True
        return updates

    @staticmethod
    def _extract_sent_amount(text: str) -> int | None:
        if not re.search(r"보냈|송금|이체", text):
            return None
        match = re.search(r"([\d,]+)\s*(만\s*원|원)", text)
        if not match:
            return None
        value = int(match.group(1).replace(",", ""))
        return value * 10000 if "만" in match.group(2) else value


interactive_agent_service = InteractiveAgentService()
