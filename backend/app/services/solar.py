"""규칙 결과를 변경하지 않고 설명만 보강하는 Solar 클라이언트."""

import json

import httpx
from loguru import logger

from app.core.config import settings
from app.services.scenario import SCENARIO_LABELS


class SolarEnricher:
    ALLOWED_TYPES = {
        "family_impersonation",
        "institution_impersonation",
        "loan_fraud",
        "smishing",
        "investment_fraud",
        "remote_control_app",
        "unknown",
        "safe_message",
    }

    async def phrase_agent_question(self, scenario: str, question: str, reason: str) -> str:
        """Policy가 고른 질문의 의미를 바꾸지 않고 자연스러운 한국어로만 다듬습니다."""
        if not settings.enable_solar or not settings.upstage_api_key:
            return question
        parsed = await self._complete(
            {
                "task": "Safety Agent의 확정된 질문을 쉽고 짧은 존댓말 한 문장으로 표현",
                "scenario": scenario,
                "fixed_meaning": question,
                "why_needed": reason,
                "output": {"question": "예/아니요로 답할 수 있는 한국어 질문"},
                "constraints": [
                    "JSON만 출력",
                    "질문의 대상 행동과 의미를 추가하거나 바꾸지 말 것",
                    "위험도나 다음 질문을 결정하지 말 것",
                    "한 문장, 100자 이내",
                ],
            },
            max_tokens=100,
        )
        phrased = parsed.get("question")
        if not isinstance(phrased, str) or not phrased.strip() or len(phrased) > 100:
            return question
        return phrased.strip()

    async def hypothesize(self, text: str, structured_input: dict) -> dict:
        """Tool 호출 전에 전체 대화 관계를 읽고 사기 가설만 생성합니다."""
        if not settings.enable_solar_detection or not settings.upstage_api_key:
            return {}
        prompt = {
            "task": "전체 대화의 Entity와 Event 관계를 분석해 사기 시나리오 가설 생성",
            "allowed_scenario_types": sorted(SCENARIO_LABELS),
            "message_content": structured_input.get("message_content") or text[:4000],
            "system_notices": structured_input.get("system_notices", []),
            "entities_and_events": structured_input,
            "output": {
                "primary_type": "allowed_scenario_types 중 하나",
                "confidence": "0~1 숫자",
                "evidence": ["실제 Entity/Event 근거"],
                "reasoning": ["A → B → C 형태의 관계 추론"],
            },
            "constraints": [
                "JSON만 출력",
                "피해 단계는 사기 가능성 판단에 사용하지 말 것",
                "각 문장을 따로 평가하지 말고 전체 대화의 사건 순서와 관계를 평가할 것",
                "시스템 안내 문구는 공격자가 작성한 메시지로 취급하지 말고 metadata로만 사용할 것",
                "가족 주장, 휴대전화 고장, 대리 행동, 상품권 요구가 이어지면 하나의 가족사칭 흐름으로 평가할 것",
                "기관명, 표시 전화번호, 인증정보 요구가 함께 있으면 외부 검증이 필요한 가설로 평가할 것",
                "validated_events의 value와 evidence만 Event 근거로 사용할 것",
                "금융기관명·계좌번호·수수료·카드·투자 단어만으로 금전 요구나 기관 사칭으로 판단하지 말 것",
                "phone_number_present와 contact_request, url_present와 url_click_request를 각각 구분할 것",
                "fee_change_notice이고 실제 행동 요구가 없으면 benign_signals을 반영해 safe_message 또는 unknown을 우선할 것",
                "supporting_evidence와 contradicting_evidence를 모두 비교할 것",
                "근거가 부족하면 unknown을 선택할 것",
            ],
        }
        parsed = await self._complete(prompt, max_tokens=450)
        if parsed.get("primary_type") not in SCENARIO_LABELS:
            return {}
        try:
            confidence = float(parsed.get("confidence", 0))
        except (TypeError, ValueError):
            return {}
        if not 0 <= confidence <= 1:
            return {}
        parsed["confidence"] = confidence
        parsed["evidence"] = [str(item)[:160] for item in parsed.get("evidence", []) if str(item).strip()][:6]
        parsed["reasoning"] = [str(item)[:200] for item in parsed.get("reasoning", []) if str(item).strip()][:6]
        return parsed

    async def analyze(
        self, text: str, stage: str, structured_input: dict, tool_results: dict
    ) -> dict:
        """유형·표현 후보를 만들지만 Safety Engine의 최종 판단을 대신하지 않습니다."""
        if not settings.enable_solar_detection or not settings.upstage_api_key:
            return {}
        prompt = {
            "task": "한국어 금융사기 메시지에서 위험 근거와 정상·완화 근거를 균형 있게 추출",
            "allowed_scam_types": sorted(self.ALLOWED_TYPES),
            "situation_stage": stage,
            "message": text[:4000],
            "structured_input": structured_input,
            "tool_results": tool_results,
            "output": {
                "scam_type": "allowed_scam_types 중 하나",
                "confidence": "0~1 숫자",
                "risk_score": "0~100 정수 후보값",
                "positive_evidence": [
                    {
                        "phrase": "원문에 실제 존재하는 표현",
                        "reason": "위험을 높이는 이유",
                        "category": "risk_signal",
                        "strength": "1~3 정수",
                    }
                ],
                "negative_evidence": [
                    {
                        "phrase": "원문에 실제 존재하는 표현",
                        "reason": "정상 대화 또는 위험을 낮추는 이유",
                        "category": "normal_context",
                        "strength": "1~3 정수",
                    }
                ],
                "scenario_stage": "normal_context | identity_grooming | exploitation_request | unclear",
            },
            "constraints": [
                "JSON만 출력",
                "메시지에 없는 표현을 근거로 만들지 말 것",
                "엄마, 아빠, 아들, 딸 같은 관계어만으로 가족사칭으로 분류하지 말 것",
                "가족사칭은 신규 연락처, 기존 연락 회피, 긴급성, 금전 또는 개인정보 요구를 함께 확인할 것",
                "금전 요구 전이라도 가족 관계 주장, 휴대전화 고장 명분, 문자 답장 유도, 모호한 부탁이 결합되면 identity_grooming 후보로 표시할 것",
                "identity_grooming은 가족사칭 확정이 아니라 기존 연락처 확인이 필요한 중간 상태임을 유지할 것",
                "일상 약속, 직접 통화 의사, 금전·개인정보 요구 부재는 negative_evidence로 평가할 것",
                "API 미탐지를 안전 판정으로 해석하지 말 것",
            ],
        }
        parsed = await self._complete(prompt, max_tokens=500)
        if not parsed:
            logger.warning("Solar Evidence 응답이 비어 있어 로컬 Evidence를 사용합니다.")
            return {}
        if parsed.get("scam_type") not in self.ALLOWED_TYPES:
            logger.warning(
                f"Solar scam_type 계약 불일치: {parsed.get('scam_type')!r}; unknown으로 제한합니다."
            )
            parsed["scam_type"] = "unknown"
        try:
            confidence = float(parsed.get("confidence", 0))
            risk_score = int(parsed.get("risk_score", 0))
        except (TypeError, ValueError):
            logger.warning("Solar confidence/risk_score 형식이 올바르지 않습니다.")
            return {}
        if not 0 <= confidence <= 1 or not 0 <= risk_score <= 100:
            logger.warning("Solar confidence/risk_score 범위를 벗어났습니다.")
            return {}
        positive = parsed.get("positive_evidence", parsed.get("highlights", []))
        negative = parsed.get("negative_evidence", [])
        parsed["highlights"] = self._validated_evidence(positive, text, "risk_signal")
        parsed["positive_evidence"] = parsed["highlights"]
        parsed["negative_evidence"] = self._validated_evidence(
            negative, text, "normal_context"
        )
        if not parsed["negative_evidence"]:
            parsed["negative_evidence"] = self._fallback_negative_evidence(
                text, structured_input
            )
        risky_context = any(
            structured_input.get(key)
            for key in (
                "money_request",
                "personal_info_request",
                "app_install_request",
                "family_impersonation",
                "institution_impersonation",
            )
        )
        if (
            parsed["scam_type"] == "unknown"
            and not parsed["highlights"]
            and parsed["negative_evidence"]
            and not risky_context
        ):
            parsed["scam_type"] = "safe_message"
        return parsed

    @staticmethod
    def _validated_evidence(items: object, text: str, default_category: str) -> list[dict]:
        if not isinstance(items, list):
            return []
        validated: list[dict] = []
        for item in items[:5]:
            if not isinstance(item, dict):
                continue
            phrase = item.get("phrase")
            reason = item.get("reason")
            try:
                strength = int(item.get("strength", 1))
            except (TypeError, ValueError):
                continue
            if (
                not isinstance(phrase, str)
                or not phrase.strip()
                or phrase not in text
                or not isinstance(reason, str)
                or not reason.strip()
                or not 1 <= strength <= 3
            ):
                continue
            validated.append(
                {
                    "phrase": phrase,
                    "reason": reason,
                    "category": str(item.get("category") or default_category)[:40],
                    "strength": strength,
                }
            )
        return validated

    @staticmethod
    def _fallback_negative_evidence(text: str, structured_input: dict) -> list[dict]:
        """모델이 필드를 누락해도 검증된 정상 신호를 구조화 계약에 보충합니다."""
        evidence: list[dict] = []
        if structured_input.get("direct_contact_willingness"):
            phrase = next(
                (
                    item
                    for item in ("전화할게", "전화 할게", "전화해", "통화하자")
                    if item in text
                ),
                None,
            )
            if phrase:
                evidence.append(
                    {
                        "phrase": phrase,
                        "reason": "직접 통화를 피하지 않고 후속 연락 의사를 표현합니다.",
                        "category": "direct_contact",
                        "strength": 3,
                    }
                )
        if structured_input.get("everyday_conversation"):
            phrase = next(
                (item for item in ("학교", "픽업", "집에", "갈 때", "갈때") if item in text),
                None,
            )
            if phrase:
                evidence.append(
                    {
                        "phrase": phrase,
                        "reason": "일상적인 약속·이동에 관한 대화 흐름입니다.",
                        "category": "normal_context",
                        "strength": 2,
                    }
                )
        return evidence[:5]

    async def enrich(
        self,
        text: str,
        detection: dict,
        sources: list[dict],
        *,
        structured_input: dict | None = None,
        scenario_hypothesis: dict | None = None,
        tool_results: dict | None = None,
        scenario_rag_results: list[dict] | None = None,
        response_policy_results: list[dict] | None = None,
    ) -> dict:
        if not settings.enable_solar or not settings.upstage_api_key:
            return {}

        prompt = {
            "task": "금융사기 분석 결과의 설명과 필요한 추가 질문만 한국어로 보강",
            "constraints": [
                "risk_score, scam_type, actions를 변경하지 말 것",
                "송금이 안전하다고 보증하지 말 것",
                "제공된 공식 검색 결과 밖의 신고 절차를 만들지 말 것",
                "JSON만 출력: explanation 문자열, follow_up_questions 문자열 배열, next_action_suggestion 문자열",
                "next_action_suggestion은 제공된 공식 검색 결과와 현재 피해 단계 안에서 한 문장으로 작성",
                "Scenario RAG 유사 사례는 참고 근거이며 해당 메시지의 확정 판정으로 표현하지 말 것",
                "원문에 금전·상품권·인증정보·개인정보·링크·앱 설치 요구가 없으면 유사 스미싱 사례의 일반적인 패턴을 현재 대화의 위험 근거로 인용하지 말 것",
                "직접 통화 의사와 학교·픽업·날씨·귀가 등 일상 흐름은 정상·완화 근거로 명시할 것",
                "입력 원문에 없는 문구나 잘못 인식된 OCR 표현을 새로 만들어 근거로 사용하지 말 것",
                "Response Policy RAG에 없는 대응 절차를 새로 만들지 말 것",
            ],
            "message": text[:4000],
            "structured_input": structured_input or {},
            "scenario_hypothesis": scenario_hypothesis or {},
            "tool_results": tool_results or {},
            "rule_result": detection,
            "scenario_rag_evidence": (scenario_rag_results or [])[:5],
            "response_policy": (response_policy_results or [])[:3],
            "official_sources": sources,
            "output": {
                "explanation": "사용자가 이해하기 쉬운 설명",
                "follow_up_questions": ["추가 확인 질문"],
                "next_action_suggestion": "지금 해야 할 안전한 행동 한 문장",
            },
        }
        parsed = await self._complete(prompt, max_tokens=settings.solar_max_tokens)
        if not isinstance(parsed.get("follow_up_questions", []), list):
            return {}
        return parsed

    async def _complete(self, prompt: dict, max_tokens: int) -> dict:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.post(
                    "https://api.upstage.ai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.upstage_api_key}"},
                    json={
                        "model": settings.llm_model,
                        "messages": [
                            {"role": "system", "content": "당신은 금융사기 분석 보조자입니다. Safety Rule Engine의 결정을 대신하지 않습니다."},
                            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
                        ],
                        "temperature": 0.1,
                        "max_tokens": max_tokens,
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                content = content.strip().removeprefix("```json").removesuffix("```").strip()
                parsed = json.loads(content)
                return parsed if isinstance(parsed, dict) else {}
        except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"Solar 요청 실패, 로컬 결과 사용: {exc}")
            return {}
