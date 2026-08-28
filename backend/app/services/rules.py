"""금융사기 핵심 판단을 LLM과 분리한 결정론적 Rule Engine."""

from dataclasses import dataclass, field
from typing import Any

from app.schemas.chat import HighlightItem, SituationStage
from app.services.context_extractor import extract_structured_context
from app.tools.scam_tools import inspect_url


@dataclass(slots=True)
class DetectionResult:
    scam_type: str
    risk_level: str
    risk_score: int
    headline: str
    explanation: str
    highlights: list[HighlightItem] = field(default_factory=list)
    negative_evidence: list[HighlightItem] = field(default_factory=list)
    risk_breakdown: dict[str, Any] = field(default_factory=dict)
    scenario_assessment: dict = field(default_factory=dict)


PATTERNS: dict[str, list[tuple[str, str, int]]] = {
    "institution_impersonation": [
        ("검찰", "수사기관을 사칭해 공포와 복종을 유도할 수 있습니다.", 2),
        ("경찰", "기관 명칭을 신뢰 근거로 제시합니다.", 1),
        ("금감원", "금융기관 명칭을 신뢰 근거로 제시합니다.", 1),
        ("안전계좌", "공공기관이 자금 검증용 안전계좌 송금을 요구하지 않습니다.", 3),
        ("대포통장", "범죄 연루 공포를 조성하는 전형적인 표현입니다.", 3),
        ("구속", "즉시 행동하지 않으면 처벌받는다는 압박입니다.", 2),
        ("보안 유지", "주변의 도움과 사실 확인을 차단하려는 요구입니다.", 2),
    ],
    "loan_fraud": [
        ("저금리", "과도하게 유리한 조건으로 접근하는 대출 미끼입니다.", 1),
        ("대환", "대환대출을 빙자한 접근일 수 있습니다.", 1),
        ("선입금", "정상 대출 전에 비용을 먼저 보내라는 요구는 고위험 신호입니다.", 3),
        ("보증료", "대출 실행 전 별도 송금을 요구하는 패턴입니다.", 3),
        ("예치금", "대출 승인을 빌미로 자금을 요구합니다.", 3),
        ("가상계좌", "특정 계좌 송금을 재촉하는 정황입니다.", 2),
    ],
    "smishing": [
        ("택배", "배송을 언급하지만 링크·요구와 함께 검토해야 합니다.", 1),
        ("배송", "배송 조회를 가장한 접근일 수 있습니다.", 1),
        ("청첩장", "지인의 행사 안내를 사칭할 수 있습니다.", 1),
        ("부고", "감정적 반응을 이용할 수 있습니다.", 1),
        ("과태료", "행정기관을 사칭해 조회를 유도할 수 있습니다.", 2),
        ("범칙금", "벌금 확인을 빌미로 개인정보 입력을 유도할 수 있습니다.", 2),
        (".apk", "안드로이드 설치 파일 직접 배포는 매우 위험합니다.", 3),
        ("bit.ly", "최종 목적지를 숨기는 단축 URL입니다.", 2),
    ],
    "investment_fraud": [
        ("수익 보장", "투자 수익을 확정적으로 보장하는 표현은 위험합니다.", 3),
        ("원금 보장", "검증되지 않은 투자에서 원금 보장을 약속합니다.", 3),
        ("리딩방", "단체방에서 특정 종목·코인 매수를 유도합니다.", 2),
        ("상장 예정", "확인하기 어려운 내부정보를 미끼로 사용합니다.", 2),
        ("고수익", "비정상적으로 높은 수익률을 강조합니다.", 2),
        ("출금 수수료", "출금을 빌미로 추가 입금을 요구합니다.", 3),
    ],
    "remote_control_app": [
        ("teamviewer", "원격제어 앱은 화면과 금융정보 탈취에 악용될 수 있습니다.", 3),
        ("anydesk", "원격제어 권한을 넘기도록 유도합니다.", 3),
        ("애니데스크", "원격제어 권한을 넘기도록 유도합니다.", 3),
        ("원격지원", "상대방이 기기를 직접 조작할 위험이 있습니다.", 2),
        ("보안앱 설치", "공식 스토어 밖의 앱 설치를 유도하는 고위험 신호입니다.", 3),
    ],
}

TYPE_LABELS = {
    "family_impersonation": "가족·지인 사칭",
    "institution_impersonation": "기관 사칭",
    "loan_fraud": "대출 사기",
    "smishing": "택배·스미싱",
    "investment_fraud": "투자 사기",
    "remote_control_app": "원격제어 악성앱",
    "unknown": "추가 확인 필요",
    "safe_message": "뚜렷한 사기 패턴 없음",
    "financial_institution_impersonation": "금융기관 사칭",
    "government_impersonation": "정부·수사기관 사칭",
    "delivery_customs_smishing": "택배·통관 스미싱",
    "card_payment_impersonation": "카드·결제 사칭",
    "gift_card_request": "상품권 구매 요구",
    "credential_theft": "개인정보·인증번호 탈취",
    "malicious_app": "악성 앱 설치 유도",
}


# 이 유형들은 시나리오명 자체가 위험 근거가 아니다. 기관명·배송 문제를 언급하는
# 정상 안내도 존재하므로 실제 행동 요구와 발신·외부 검증 신호로 점수를 계산한다.
EVIDENCE_GATED_SCENARIOS = {
    "government_impersonation",
    "financial_institution_impersonation",
    "card_payment_impersonation",
    "delivery_customs_smishing",
    "credential_theft",
    "malicious_app",
}

STAGE_LABELS = {
    SituationStage.RECEIVED_MESSAGE: "메시지만 받음",
    SituationStage.CLICKED_LINK: "링크 클릭",
    SituationStage.ENTERED_INFO: "정보 입력",
    SituationStage.INSTALLED_APP: "앱 설치",
    SituationStage.TRANSFERRED_MONEY: "송금 완료",
}


class ScamRuleEngine:
    """URL·피해 단계·사기 정황을 분리한 뒤 결정론적으로 융합합니다."""

    SITUATION_RISK = {
        SituationStage.RECEIVED_MESSAGE: 0,
        SituationStage.CLICKED_LINK: 15,
        SituationStage.ENTERED_INFO: 55,
        SituationStage.INSTALLED_APP: 85,
        SituationStage.TRANSFERRED_MONEY: 100,
    }

    def detect(
        self,
        text: str,
        stage: SituationStage,
        structured_input: dict | None = None,
        stage_confirmation: str = "not_required",
        scenario_hypothesis: dict | None = None,
    ) -> DetectionResult:
        normalized = text.strip().lower()
        structured = structured_input or extract_structured_context(text)
        hypothesis = scenario_hypothesis or {}
        matches: dict[str, list[HighlightItem]] = {}
        for scam_type, patterns in PATTERNS.items():
            found = [
                HighlightItem(
                    phrase=keyword,
                    reason=reason,
                    category=scam_type,
                    strength=strength,
                )
                for keyword, reason, strength in patterns
                if keyword in normalized
            ]
            if found:
                matches[scam_type] = found

        family_evidence = self._family_evidence(normalized, structured)
        if structured.get("family_impersonation"):
            matches["family_impersonation"] = family_evidence

        negative_evidence = self._negative_evidence(normalized, structured)
        hypothesis_type = hypothesis.get("primary_type")
        hypothesis_confidence = float(hypothesis.get("confidence", 0))
        if (
            hypothesis_type not in {None, "unknown", "safe_message"}
            and hypothesis_confidence >= 0.55
        ):
            scam_type = hypothesis_type
            highlights = (
                []
                if hypothesis_type in EVIDENCE_GATED_SCENARIOS
                else [
                    HighlightItem(
                        phrase=reason,
                        reason="대화 전체 Event 관계가 하나의 사기 시나리오로 이어집니다.",
                        category="scenario_relationship",
                        strength=3 if hypothesis_confidence >= 0.8 else 2,
                    )
                    for reason in (hypothesis.get("relationships") or hypothesis.get("evidence", []))[:5]
                ]
            )
            positive_strength = sum(item.strength for item in highlights)
        elif matches:
            scam_type = max(
                matches,
                key=lambda key: (sum(item.strength for item in matches[key]), len(matches[key])),
            )
            highlights = matches[scam_type][:5]
            positive_strength = sum(item.strength for item in highlights)
        elif structured.get("identity_grooming"):
            scam_type = "unknown"
            highlights = self._identity_grooming_evidence(normalized, structured)
            positive_strength = sum(item.strength for item in highlights)
        elif self._looks_like_safe_transaction_notice(normalized):
            scam_type = "safe_message"
            highlights = []
            positive_strength = 0
        else:
            scam_type = "unknown"
            highlights = []
            positive_strength = 0

        negative_evidence = self._relevant_negative_evidence(
            negative_evidence, scam_type
        )
        negative_strength = sum(item.strength for item in negative_evidence)
        positive_score = min(100, positive_strength * 12)
        negative_score = min(100, negative_strength * 10)
        context_score = max(
            5,
            min(96, 8 + positive_strength * 10 - negative_strength * 7),
        )
        scenario_axis = hypothesis.get("risk_axes", {}).get("scenario_pattern", {})
        if (
            hypothesis_type not in {None, "unknown", "safe_message"}
            and hypothesis_type not in EVIDENCE_GATED_SCENARIOS
        ):
            context_score = max(context_score, int(scenario_axis.get("score", 0)))
        if scam_type == "safe_message":
            context_score = min(context_score, 8)
        if context_score < 35 and scam_type not in {"safe_message", "unknown"}:
            scam_type = "unknown"
            highlights = []
            positive_strength = 0
            positive_score = 0

        situation_score = self.SITUATION_RISK[stage]
        score = self._fuse_risk(
            context_score,
            situation_score,
            0,
            positive_strength,
            negative_strength,
        )
        level = self._risk_level(score)
        scenario_assessment = self._scenario_assessment(
            structured, scam_type, score, stage, stage_confirmation
        )

        label = TYPE_LABELS[scam_type]
        headline = self._headline(label, score, stage, stage_confirmation)
        if scenario_assessment["status"] == "verification_required" and stage != SituationStage.TRANSFERRED_MONEY:
            headline = scenario_assessment["title"]
        breakdown = {
            "url_risk": 0,
            "situation_risk": situation_score,
            "scam_context_risk": context_score,
            "positive_evidence_score": positive_score,
            "negative_evidence_score": negative_score,
            **self._stage_assessment(stage, stage_confirmation),
            "fusion_reason": "사기 가능성은 대화 근거와 URL 검증으로 계산하고, 사용자가 선택한 피해 단계와 대응 긴급도는 별도로 평가했습니다.",
            "threat_intelligence": {"score": 0, "reasons": ["외부 URL 위협정보 조회 전입니다."]},
            "domain_reputation": {"score": 0, "reasons": ["도메인 등록정보 조회 전입니다."]},
            "url_structure": {"score": 0, "reasons": ["분석할 URL이 없거나 URL Tool 실행 전입니다."]},
            "conversation_context": {"score": context_score, "reasons": self._context_reasons(highlights, negative_evidence)},
            "exposure_risk": {"score": situation_score, "reasons": [self._stage_assessment(stage, stage_confirmation)["situation_summary"]]},
            "scenario_pattern": hypothesis.get("risk_axes", {}).get("scenario_pattern", {"score": context_score, "reasons": []}),
            "scenario_rag": hypothesis.get("risk_axes", {}).get("scenario_rag", {"score": 0, "reasons": ["Scenario RAG가 비활성화되었거나 유사 사례가 없습니다."]}),
            "identity_risk": hypothesis.get("risk_axes", {}).get("identity_risk", {"score": 0, "reasons": []}),
            "financial_credential_request": hypothesis.get("risk_axes", {}).get("financial_credential_request", {"score": 0, "reasons": []}),
            "external_verification": hypothesis.get("risk_axes", {}).get("external_verification", {"score": 0, "reasons": ["외부 검증 전입니다."]}),
        }
        explanation = self._explanation(
            label, stage, highlights, negative_evidence, breakdown
        )
        return DetectionResult(
            scam_type=scam_type,
            risk_level=level,
            risk_score=score,
            headline=headline,
            explanation=explanation,
            highlights=highlights,
            negative_evidence=negative_evidence,
            risk_breakdown=breakdown,
            scenario_assessment=scenario_assessment,
        )

    def merge_verified_evidence(
        self,
        result: DetectionResult,
        stage: SituationStage,
        solar_candidate: dict,
        tool_results: dict,
        structured_input: dict | None = None,
        stage_confirmation: str = "not_required",
        scenario_hypothesis: dict | None = None,
    ) -> DetectionResult:
        """긍정·부정 Evidence와 외부 검증을 Safety Rule에서 다시 융합합니다."""
        structured = structured_input or {}
        hypothesis = scenario_hypothesis or {}
        scam_type = result.scam_type
        highlights = list(result.highlights)
        negative_evidence = list(result.negative_evidence)

        url_scores = [self._verified_url_score(item) for item in tool_results.get("urls", [])]
        url_score = max(url_scores, default=0)
        threat_axis = self._aggregate_url_axis(tool_results, "threat_intelligence")
        domain_axis = self._aggregate_url_axis(tool_results, "domain_reputation")
        structure_axis = self._aggregate_url_axis(tool_results, "url_structure")
        malicious_urls = [
            item
            for item in tool_results.get("urls", [])
            if any(
                reputation.get("status") == "malicious"
                for reputation in item.get("reputation", [])
            )
        ]
        if malicious_urls:
            if scam_type in {"unknown", "safe_message"}:
                scam_type = "smishing"
            url_score = max(url_score, 92)
            highlights.append(
                HighlightItem(
                    phrase=malicious_urls[0].get("host") or "URL",
                    reason="외부 평판 서비스에서 악성 URL 탐지 이력이 확인됐습니다.",
                )
            )

        situation_score = self.SITUATION_RISK[stage]
        if solar_candidate and float(solar_candidate.get("confidence", 0)) >= 0.65:
            candidate_type = solar_candidate.get("scam_type", "unknown")
            family_allowed = candidate_type != "family_impersonation" or bool(
                structured.get("family_impersonation")
            )
            if family_allowed:
                for item in solar_candidate.get("highlights", []):
                    if len(highlights) >= 5:
                        break
                    if all(existing.phrase != item["phrase"] for existing in highlights):
                        highlights.append(HighlightItem(**item))
            for item in solar_candidate.get("negative_evidence", []):
                if len(negative_evidence) >= 5:
                    break
                if all(existing.phrase != item["phrase"] for existing in negative_evidence):
                    negative_evidence.append(HighlightItem(**item))

            solar_positive_strength = sum(
                int(item.get("strength", 1))
                for item in solar_candidate.get("highlights", [])
            )
            if (
                scam_type == "unknown"
                and candidate_type not in {"unknown", "safe_message"}
                and family_allowed
                and solar_positive_strength >= 4
            ):
                scam_type = candidate_type

        negative_evidence = self._relevant_negative_evidence(
            negative_evidence, scam_type
        )
        positive_strength = sum(item.strength for item in highlights)
        negative_strength = sum(item.strength for item in negative_evidence)
        positive_score = min(100, positive_strength * 12)
        negative_score = min(100, negative_strength * 10)
        context_score = max(
            5,
            min(96, 8 + positive_strength * 10 - negative_strength * 7),
        )
        scenario_axis = hypothesis.get("risk_axes", {}).get("scenario_pattern", {"score": 0, "reasons": []})
        scenario_rag_axis = hypothesis.get("risk_axes", {}).get("scenario_rag", {"score": 0, "reasons": []})
        identity_axis = hypothesis.get("risk_axes", {}).get("identity_risk", {"score": 0, "reasons": []})
        request_axis = hypothesis.get("risk_axes", {}).get("financial_credential_request", {"score": 0, "reasons": []})
        external_axis = hypothesis.get("risk_axes", {}).get("external_verification", {"score": 0, "reasons": []})
        hypothesis_type = hypothesis.get("primary_type")
        evidence_gated = hypothesis_type in EVIDENCE_GATED_SCENARIOS
        if hypothesis_type not in {None, "unknown", "safe_message"}:
            scam_type = hypothesis_type
            if not evidence_gated:
                context_score = max(context_score, int(scenario_axis.get("score", 0)))
        if (
            context_score < 35
            and not malicious_urls
            and not structured.get("identity_grooming")
            and hypothesis_type in {None, "unknown", "safe_message"}
        ):
            scam_type = "safe_message" if negative_strength >= 4 else "unknown"
            highlights = []
            positive_strength = 0
            positive_score = 0
            context_score = max(5, min(context_score, 12))

        score = self._fuse_scam_likelihood(
            scenario_score=int(scenario_axis.get("score", context_score)),
            scenario_rag_score=int(scenario_rag_axis.get("score", 0)),
            identity_score=int(identity_axis.get("score", 0)),
            request_score=int(request_axis.get("score", 0)),
            external_score=int(external_axis.get("score", 0)),
            threat_score=int(threat_axis.get("score", 0)),
            url_score=url_score,
            fallback_context_score=context_score,
            verified_malicious=bool(malicious_urls),
            evidence_gated=evidence_gated,
            unverified_external_url=bool(tool_results.get("urls"))
            and any(
                not item.get("is_allowlisted", False)
                for item in tool_results.get("urls", [])
            ),
        )
        verified_official_contact = (
            tool_results.get("institution_verification", {}).get("status") == "match"
        )
        sensitive_action_present = any(
            structured.get(key)
            for key in (
                "financial_request",
                "authentication_request",
                "personal_info_request",
                "app_install_request",
                "link_access_request",
                "unauthorized_claim",
                "international_sender",
            )
        )
        if (
            evidence_gated
            and score < 45
            and verified_official_contact
            and not sensitive_action_present
        ):
            scam_type = "safe_message"
        level = self._risk_level(score)
        scenario_assessment = self._scenario_assessment(
            structured, scam_type, score, stage, stage_confirmation
        )
        label = TYPE_LABELS.get(scam_type, TYPE_LABELS["unknown"])
        breakdown = {
            "url_risk": url_score,
            "situation_risk": situation_score,
            "scam_context_risk": context_score,
            "positive_evidence_score": positive_score,
            "negative_evidence_score": negative_score,
            **self._stage_assessment(stage, stage_confirmation),
            "fusion_reason": "사기 가능성은 위험·완화 근거와 URL 검증으로 계산했습니다. 피해 단계는 이 점수에 섞지 않고 별도의 대응 긴급도로 표시합니다.",
            "threat_intelligence": threat_axis,
            "domain_reputation": domain_axis,
            "url_structure": structure_axis,
            "conversation_context": {"score": context_score, "reasons": self._context_reasons(highlights, negative_evidence)},
            "exposure_risk": {"score": situation_score, "reasons": [self._stage_assessment(stage, stage_confirmation)["situation_summary"]]},
            "scenario_pattern": scenario_axis,
            "scenario_rag": scenario_rag_axis,
            "identity_risk": identity_axis,
            "financial_credential_request": request_axis,
            "external_verification": external_axis,
        }
        headline = self._headline(label, score, stage, stage_confirmation)
        if score < 20 and url_score <= 10 and context_score <= 12:
            headline = "현재 확인된 위험 신호가 없습니다."
        if scenario_assessment["status"] == "verification_required" and stage != SituationStage.TRANSFERRED_MONEY:
            headline = scenario_assessment["title"]
        return DetectionResult(
            scam_type=scam_type,
            risk_level=level,
            risk_score=score,
            headline=headline,
            explanation=self._explanation(
                label, stage, highlights, negative_evidence, breakdown
            ),
            highlights=highlights,
            negative_evidence=negative_evidence,
            risk_breakdown=breakdown,
            scenario_assessment=scenario_assessment,
        )

    @staticmethod
    def _family_evidence(text: str, structured: dict) -> list[HighlightItem]:
        definitions = [
            ("relationship_mention", ("엄마", "아빠", "어머니", "아버지", "딸", "아들", "가족", "지인"), "가족 관계를 주장합니다.", "relationship", 1),
            ("new_contact", ("새 번호", "번호 바뀌", "임시폰", "액정 깨", "폰 고장", "폰고장", "수리 맡", "as맡"), "새 연락처 또는 휴대전화 고장을 주장합니다.", "new_contact", 2),
            ("contact_avoidance", ("전화 안돼", "전화는 안돼", "통화 안돼", "통화 못해", "전화하지 마"), "기존 음성 연락과 신원 확인을 피합니다.", "contact_avoidance", 2),
            ("money_request", ("상품권", "핀번호", "송금", "이체", "입금", "돈 보내"), "금전 또는 현금성 수단을 요구합니다.", "money_request", 3),
            ("personal_info_request", ("주민번호", "비밀번호", "인증번호", "신분증", "개인정보"), "개인정보 또는 인증정보를 요구합니다.", "personal_info_request", 3),
            ("urgency", ("급해", "급하", "긴급", "즉시", "지금", "바로", "빨리"), "사용자의 확인 시간을 줄이도록 재촉합니다.", "urgency", 1),
        ]
        evidence: list[HighlightItem] = []
        for key, keywords, reason, category, strength in definitions:
            if not structured.get(key):
                continue
            phrase = next((keyword for keyword in keywords if keyword in text), category)
            evidence.append(
                HighlightItem(
                    phrase=phrase,
                    reason=reason,
                    category=category,
                    strength=strength,
                )
            )
        return evidence[:5]

    @staticmethod
    def _identity_grooming_evidence(text: str, structured: dict) -> list[HighlightItem]:
        definitions = [
            ("relationship_mention", ("엄마", "아빠", "어머니", "아버지", "딸", "아들"), "새 연락수단에서 가족 관계를 먼저 주장합니다.", "identity_claim", 1),
            ("device_failure_pretext", ("폰고장", "폰 고장", "휴대폰 고장", "수리 맡", "as맡"), "휴대전화 고장을 연락수단 변경의 이유로 제시합니다.", "device_pretext", 2),
            ("channel_restriction", ("문자로만", "문자 확인하는대로", "문자 확인하는 대로", "문자확인하는대로", "문자확인하는 대로", "문자로 답", "카톡으로만"), "음성 확인보다 문자 답장을 유도합니다.", "channel_restriction", 1),
            ("vague_favor_request", ("부탁할거", "부탁할 게", "부탁할게", "부탁이 있어", "부탁 좀"), "구체적인 내용을 밝히기 전에 반응을 유도하는 모호한 부탁입니다.", "vague_request", 1),
        ]
        evidence: list[HighlightItem] = []
        for key, keywords, reason, category, strength in definitions:
            if not structured.get(key):
                continue
            phrase = next((keyword for keyword in keywords if keyword in text), category)
            evidence.append(HighlightItem(phrase=phrase, reason=reason, category=category, strength=strength))
        return evidence[:5]

    @staticmethod
    def _negative_evidence(text: str, structured: dict) -> list[HighlightItem]:
        evidence: list[HighlightItem] = []
        if not any(
            structured.get(key)
            for key in ("money_request", "personal_info_request", "app_install_request")
        ):
            evidence.append(
                HighlightItem(
                    phrase="금전·개인정보·앱 설치 요구 없음",
                    reason="사기에서 흔한 직접적인 이득 요구가 확인되지 않았습니다.",
                    category="absence",
                    strength=2,
                )
            )
        if structured.get("direct_contact_willingness"):
            phrase = next(
                (item for item in ("전화할게", "전화 할게", "전화해", "통화하자") if item in text),
                "직접 통화 의사",
            )
            evidence.append(
                HighlightItem(
                    phrase=phrase,
                    reason="직접 통화를 피하지 않고 후속 연락 의사를 표현합니다.",
                    category="direct_contact",
                    strength=3,
                )
            )
        if structured.get("everyday_conversation"):
            evidence.append(
                HighlightItem(
                    phrase="일상적인 약속·이동 대화",
                    reason="학교, 귀가, 픽업 등 일상적인 대화 흐름이 확인됩니다.",
                    category="normal_context",
                    strength=2,
                )
            )
        if not structured.get("new_contact") and not structured.get("contact_avoidance"):
            evidence.append(
                HighlightItem(
                    phrase="새 연락처·통화 회피 정황 없음",
                    reason="가족사칭의 핵심인 연락처 변경과 기존 연락 회피가 확인되지 않았습니다.",
                    category="family_absence",
                    strength=2,
                )
            )
        return evidence[:5]

    @staticmethod
    def _relevant_negative_evidence(
        evidence: list[HighlightItem], scam_type: str
    ) -> list[HighlightItem]:
        if scam_type in {"family_impersonation", "unknown", "safe_message"}:
            return evidence
        family_only = {"family_absence", "direct_contact", "normal_context"}
        return [item for item in evidence if item.category not in family_only]

    @staticmethod
    def _fuse_risk(
        context_score: int,
        situation_score: int,
        url_score: int,
        positive_strength: int,
        negative_strength: int,
        *,
        verified_malicious: bool = False,
    ) -> int:
        """사기 가능성은 피해 단계와 분리해 Evidence와 URL만으로 계산합니다."""
        score = round(context_score * 0.72 + url_score * 0.28)
        score += min(12, max(0, positive_strength - negative_strength) * 2)
        if url_score >= 45 and context_score >= 45:
            score += 10
        score = min(score, 100)

        if verified_malicious or url_score >= 92:
            score = max(score, 92)
        elif url_score >= 65 and context_score >= 45:
            score = max(score, 75)
        if context_score >= 80 and positive_strength >= 6:
            score = max(score, 85)
        elif context_score >= 50 and positive_strength >= 4:
            score = max(score, 55)
        return min(score, 100)

    @staticmethod
    def _fuse_scam_likelihood(
        *,
        scenario_score: int,
        scenario_rag_score: int,
        identity_score: int,
        request_score: int,
        external_score: int,
        threat_score: int,
        url_score: int,
        fallback_context_score: int,
        verified_malicious: bool = False,
        evidence_gated: bool = False,
        unverified_external_url: bool = False,
    ) -> int:
        """Scam Likelihood만 계산하며 Exposure Stage는 입력으로 받지 않습니다."""
        if evidence_gated:
            score = round(
                identity_score * 0.20
                + request_score * 0.30
                + external_score * 0.25
                + max(threat_score, url_score) * 0.25
            )
            if unverified_external_url and request_score >= 80:
                score = max(score, 85)
            elif request_score >= 95 and max(threat_score, url_score) >= 65:
                score = max(score, 90)
            elif external_score >= 85 and request_score >= 55:
                score = max(score, 88)
            elif request_score >= 80 and (identity_score >= 40 or external_score >= 65):
                score = max(score, 85)
            elif request_score >= 70 and max(threat_score, url_score) >= 45:
                score = max(score, 82)
            elif request_score >= 85 and max(threat_score, url_score) >= 20:
                score = max(score, 82)
            elif identity_score >= 80 and request_score >= 55:
                score = max(score, 75)
            if verified_malicious or threat_score >= 92 or url_score >= 92:
                score = max(score, 92)
            return min(score, 100)
        if max(scenario_score, scenario_rag_score, identity_score, request_score, external_score, threat_score, url_score) == 0:
            return min(fallback_context_score, 100)
        scenario_score = scenario_score or fallback_context_score
        score = round(
            scenario_score * 0.42
            + identity_score * 0.16
            + request_score * 0.22
            + external_score * 0.12
            + max(threat_score, url_score) * 0.08
        )
        # 유사 사례는 독립적인 확정 판단이 아니라 기존 시나리오 가설을 보강하는 근거로만 반영합니다.
        if scenario_rag_score:
            score = round(score * 0.85 + scenario_rag_score * 0.15)
        if scenario_score >= 85 and request_score >= 80:
            score = max(score, 88)
        elif scenario_score >= 85 and identity_score >= 80 and request_score >= 55:
            score = max(score, 88)
        elif scenario_score >= 88 and request_score >= 60:
            score = max(score, 85)
        elif scenario_score >= 65 and url_score >= 65:
            score = max(score, 85)
        elif scenario_score >= 80 and (identity_score >= 70 or external_score >= 65):
            score = max(score, 82)
        if external_score >= 85 and request_score >= 80:
            score = max(score, 90)
        if verified_malicious or threat_score >= 92 or url_score >= 92:
            score = max(score, 92)
        return min(score, 100)

    @staticmethod
    def _risk_level(score: int) -> str:
        return "critical" if score >= 85 else "warning" if score >= 45 else "low"

    @staticmethod
    def _looks_like_safe_transaction_notice(text: str) -> bool:
        safe = any(word in text for word in ("잔액", "승인금액", "체크카드", "출금"))
        dangerous = any(word in text for word in ("링크", "입력", "송금", "비밀번호", "인증번호"))
        return safe and not dangerous

    @staticmethod
    def _verified_url_score(item: dict) -> int:
        """URL 구조 점수에 평판·redirect 정보를 더하되 피해 단계는 섞지 않습니다."""
        score = int(item.get("risk_score", 0))
        for reputation in item.get("reputation", []):
            status = reputation.get("status")
            if status == "malicious":
                score = max(score, 92)
            elif status == "suspicious":
                score = max(score, 65)
            if int(reputation.get("community_reputation") or 0) < 0:
                score = max(score, 45)
            redirect_target = reputation.get("redirect_target")
            if redirect_target and redirect_target != item.get("url"):
                score = max(score, int(inspect_url(redirect_target).get("risk_score", 0)))
        return min(score, 100)

    @staticmethod
    def _aggregate_url_axis(tool_results: dict, axis: str) -> dict:
        components = [
            item.get("risk_components", {}).get(axis, {})
            for item in tool_results.get("urls", [])
        ]
        score = max((int(component.get("score", 0)) for component in components), default=0)
        reasons = [
            reason
            for component in components
            for reason in component.get("reasons", [])
        ]
        return {"score": score, "reasons": list(dict.fromkeys(reasons))[:6] or ["해당 축의 위험 신호가 없습니다."]}

    @staticmethod
    def _context_reasons(
        highlights: list[HighlightItem], negative_evidence: list[HighlightItem]
    ) -> list[str]:
        reasons = [f"위험: {item.reason}" for item in highlights]
        reasons.extend(f"완화: {item.reason}" for item in negative_evidence)
        return reasons[:6] or ["대화에서 구체적인 사기 요구가 확인되지 않았습니다."]

    @staticmethod
    def _headline(
        label: str, score: int, stage: SituationStage, stage_confirmation: str = "not_required"
    ) -> str:
        if stage == SituationStage.TRANSFERRED_MONEY and stage_confirmation == "confirmed":
            return "송금 피해 단계입니다. 지금은 분석보다 지급정지가 먼저입니다."
        if stage == SituationStage.TRANSFERRED_MONEY:
            return "대화 분석과 별개로, 실제 송금 여부를 먼저 확인해야 합니다."
        if score >= 85 and stage == SituationStage.RECEIVED_MESSAGE:
            return "사기 가능성이 높은 연락이지만 아직 피해 전 단계입니다."
        if score >= 85:
            return f"{label} 가능성이 매우 높습니다. 즉시 추가 행동을 멈추세요."
        if score >= 45:
            return f"{label} 징후가 있습니다. 공식 경로로 확인이 필요합니다."
        if stage == SituationStage.CLICKED_LINK:
            return "URL 자체의 뚜렷한 위험 신호는 없지만, 클릭한 상태이므로 추가 확인이 필요합니다."
        return "현재 입력에서 뚜렷한 사기 패턴은 확인되지 않았습니다."

    @staticmethod
    def _stage_assessment(stage: SituationStage, confirmation: str) -> dict[str, str]:
        if stage == SituationStage.TRANSFERRED_MONEY:
            if confirmation == "confirmed":
                return {
                    "stage_confirmation": "confirmed",
                    "response_urgency": "critical",
                    "situation_summary": "이 입력과 관련된 송금 피해가 확인됨",
                }
            return {
                "stage_confirmation": "needs_confirmation",
                "response_urgency": "caution",
                "situation_summary": "송금 완료 선택됨 · 실제 관련성 확인 필요",
            }
        if stage == SituationStage.INSTALLED_APP:
            return {"stage_confirmation": "not_required", "response_urgency": "critical", "situation_summary": "앱 설치 단계"}
        if stage == SituationStage.ENTERED_INFO:
            return {"stage_confirmation": "not_required", "response_urgency": "urgent", "situation_summary": "개인·금융정보 입력 단계"}
        if stage == SituationStage.CLICKED_LINK:
            return {"stage_confirmation": "not_required", "response_urgency": "caution", "situation_summary": "링크 클릭 · 추가 행동 여부 확인 필요"}
        return {"stage_confirmation": "not_required", "response_urgency": "routine", "situation_summary": "메시지만 수신"}

    @staticmethod
    def _scenario_assessment(
        structured: dict,
        scam_type: str,
        score: int,
        stage: SituationStage,
        stage_confirmation: str,
    ) -> dict:
        if stage == SituationStage.TRANSFERRED_MONEY and stage_confirmation == "confirmed":
            return {
                "status": "harm_confirmed",
                "stage": "harm_occurred",
                "title": "피해 발생이 확인된 상황입니다.",
                "summary": "사기 가능성 점수와 별개로 확인된 송금 피해에 우선 대응합니다.",
                "confidence": "confirmed",
                "confirmed_signals": ["사용자가 이 대화와 관련된 송금을 확인함"],
                "absent_signals": [],
            }
        if structured.get("identity_grooming"):
            signals: list[str] = []
            if structured.get("relationship_mention"):
                signals.append("새 연락수단에서 가족 관계 주장")
            if structured.get("device_failure_pretext"):
                signals.append("휴대전화 고장을 연락처 변경 이유로 제시")
            if structured.get("channel_restriction"):
                signals.append("문자 중심의 답장 유도")
            if structured.get("vague_favor_request"):
                signals.append("내용을 밝히지 않은 모호한 부탁")
            absent: list[str] = []
            if not structured.get("money_request"):
                absent.append("송금·상품권 요구는 아직 없음")
            if not structured.get("personal_info_request"):
                absent.append("개인정보 요구는 아직 없음")
            if not structured.get("urgency"):
                absent.append("강한 긴급성 표현은 확인되지 않음")
            return {
                "status": "verification_required",
                "stage": "identity_grooming",
                "title": "가족사칭 초기 접근과 유사해 신원 확인이 필요합니다.",
                "summary": "아직 금전 요구는 없지만, 가족 관계 주장과 연락수단 변경 명분이 결합되어 있습니다.",
                "confidence": "medium",
                "confirmed_signals": signals,
                "absent_signals": absent,
            }
        if stage in {SituationStage.ENTERED_INFO, SituationStage.INSTALLED_APP}:
            return {
                "status": "harm_exposure",
                "stage": "exposure_occurred",
                "title": "추가 피해를 막기 위한 빠른 대응이 필요합니다.",
                "summary": "입력 내용의 사기 가능성과 별개로 개인정보 또는 기기 노출 단계입니다.",
                "confidence": "confirmed",
                "confirmed_signals": ["사용자가 피해 노출 단계를 선택함"],
                "absent_signals": [],
            }
        if score >= 85:
            status, scenario_stage, title = "high_risk", "exploitation_request", "구체적인 사기 요구가 확인된 고위험 상황입니다."
        elif score >= 45 or scam_type not in {"unknown", "safe_message"}:
            status, scenario_stage, title = "suspicious", "suspicious_request", "복합적인 사기 의심 정황이 확인됩니다."
        elif scam_type == "safe_message":
            status, scenario_stage, title = "normal_likely", "normal_context", "현재는 정상 정황이 우세합니다."
        else:
            status, scenario_stage, title = "unclear", "insufficient_context", "판단에 필요한 문맥이 충분하지 않습니다."
        return {
            "status": status,
            "stage": scenario_stage,
            "title": title,
            "summary": "위험·정상 근거와 외부 확인 결과를 함께 반영한 판단입니다.",
            "confidence": "high" if score >= 85 else "medium" if score >= 45 else "low",
            "confirmed_signals": [],
            "absent_signals": [],
        }

    @staticmethod
    def _explanation(
        label: str,
        stage: SituationStage,
        highlights: list[HighlightItem],
        negative_evidence: list[HighlightItem],
        breakdown: dict[str, int | str],
    ) -> str:
        evidence = ", ".join(item.phrase for item in highlights) or "명확한 위험 표현 부족"
        mitigating = (
            ", ".join(item.phrase for item in negative_evidence)
            or "별도의 완화 근거 없음"
        )
        return (
            f"규칙 기반 분석에서 '{label}' 유형을 우선 검토했습니다. "
            f"위험 근거는 {evidence}, 정상·완화 근거는 {mitigating}이며 현재 피해 단계는 '{STAGE_LABELS[stage]}'입니다. "
            f"URL {breakdown['url_risk']}점, 상황 {breakdown['situation_risk']}점, 사기 정황 {breakdown['scam_context_risk']}점으로 각각 평가했습니다. "
            "이 결과는 송금의 안전이나 상대방의 신원을 보증하지 않습니다."
        )


class SafetyPolicy:
    """LLM이 변경할 수 없는 긴급 대응·행동 승인 규칙."""

    NOTICE = "ScamFlow는 송금 또는 거래의 안전을 보증하지 않습니다. 공식 번호와 기존 신뢰 연락처로 직접 확인하세요."

    def validate_explanation(self, explanation: str, fallback: str) -> str:
        """사용자 설명에서도 거래 안전 보증 표현을 차단합니다."""
        cleaned = " ".join(explanation.split()).strip()
        forbidden = (
            "안전한 거래",
            "안전합니다",
            "송금해도 됩니다",
            "이체해도 됩니다",
            "사기가 아닙니다",
            "신원이 확인되었습니다",
        )
        if not cleaned or len(cleaned) > 2000 or any(item in cleaned for item in forbidden):
            return fallback
        return cleaned

    def validate_next_action(
        self, suggestion: str, fallback: str, required_action_id: str
    ) -> str:
        """Solar 제안을 실행 가능한 안전 안내로 제한합니다."""
        cleaned = " ".join(suggestion.split()).strip()
        forbidden = (
            "안전한 거래",
            "안전합니다",
            "송금해도",
            "이체해도",
            "거래를 진행",
            "보증합니다",
        )
        safe_verbs = ("중단", "확인", "연락", "신고", "차단", "요청", "보관", "변경")
        required_signals = {
            "trusted-family-contact": ("가족", "기존", "평소", "확인"),
            "stop-contact": ("연락 중단", "통화 중단", "메시지 중단", "끊"),
            "do-not-interact": ("중단", "누르지", "입력하지", "보내지"),
            "close-page": ("페이지를 닫", "창을 닫", "추가 입력 중단"),
            "disconnect-network": ("네트워크", "비행기 모드", "와이파이", "데이터를 끄"),
            "call-112": ("112", "지급정지", "신고"),
        }
        required = required_signals.get(required_action_id, ())
        if (
            not cleaned
            or len(cleaned) > 140
            or any(phrase in cleaned for phrase in forbidden)
            or not any(verb in cleaned for verb in safe_verbs)
            or "http://" in cleaned
            or "https://" in cleaned
            or (required and not any(signal in cleaned for signal in required))
        ):
            return fallback
        return cleaned

    def actions_for(
        self, scam_type: str, stage: SituationStage, stage_confirmation: str = "not_required"
    ) -> list[dict]:
        if stage == SituationStage.TRANSFERRED_MONEY and stage_confirmation != "confirmed":
            return [
                self._guide(
                    "confirm-transfer",
                    "이 대화와 관련된 송금인지 확인",
                    "실제 송금·상품권 전달이 이 대화 상대의 요청 때문인지 답해주세요.",
                    1,
                )
            ]
        if stage == SituationStage.TRANSFERRED_MONEY:
            return [
                self._call("call-112", "112에 신고·지급정지 요청", "송금은행과 사기 이용 계좌의 긴급 지급정지를 요청하세요.", "112", 1),
                self._call("call-bank", "거래은행 공식 대표번호로 연락", "카드·은행 앱 또는 공식 홈페이지에서 대표번호를 직접 확인하세요.", "1332", 2),
                self._call("call-1332", "금융감독원 피해상담", "추가 계좌 보호와 개인정보 노출 대응을 상담하세요.", "1332", 3),
            ]
        if stage == SituationStage.INSTALLED_APP:
            return [
                self._guide("disconnect-network", "기기 네트워크 즉시 차단", "비행기 모드를 켜고 Wi-Fi와 모바일 데이터를 끄세요.", 1),
                self._call("call-112", "다른 안전한 전화로 112 상담", "감염 의심 휴대전화가 아닌 다른 기기를 사용하세요.", "112", 2),
                self._call("call-118", "KISA 118 악성앱 상담", "앱 삭제·초기화 전 증거 보존과 조치 순서를 확인하세요.", "118", 3),
            ]
        if stage == SituationStage.ENTERED_INFO:
            return [
                self._guide("stop-contact", "추가 입력과 인증 즉시 중단", "인증번호·비밀번호·신분증을 더 전달하지 마세요.", 1),
                self._call("call-1332", "금융감독원 1332 상담", "개인정보 노출 등록과 계좌 보호 절차를 확인하세요.", "1332", 2),
                self._call("call-118", "KISA 118 상담", "피싱사이트와 개인정보 노출 대응을 상담하세요.", "118", 3),
            ]
        if stage == SituationStage.CLICKED_LINK:
            return [
                self._guide("close-page", "페이지를 닫고 추가 입력 중단", "파일 다운로드·앱 설치·알림 허용을 하지 마세요.", 1),
                self._call("call-118", "KISA 118에 URL 확인 요청", "의심 링크와 설치 여부를 상담하세요.", "118", 2),
            ]
        if scam_type in {"family_impersonation", "gift_card_request"}:
            return [
                self._guide("trusted-family-contact", "기존에 저장된 가족 번호로 확인", "메시지에 적힌 새 번호가 아니라 평소 연락처로 직접 통화하세요.", 1),
                self._guide("no-transfer", "송금·상품권 전송 중단", "핀번호와 신분증 사진을 보내지 마세요.", 2),
            ]
        if scam_type in {"institution_impersonation", "government_impersonation"}:
            return [
                self._guide("stop-contact", "통화와 메시지 중단", "상대가 알려준 번호로 다시 연락하지 마세요.", 1),
                self._call("call-112", "112로 기관 사칭 여부 확인", "직접 112에 전화해 사건과 요구의 진위를 확인하세요.", "112", 2),
            ]
        if scam_type in {
            "financial_institution_impersonation",
            "card_payment_impersonation",
            "credential_theft",
        }:
            return [
                self._guide("stop-contact", "인증번호·개인정보 전달 중단", "문자나 통화 상대에게 인증번호·비밀번호·카드정보를 제공하지 마세요.", 1),
                self._guide("official-bank-contact", "공식 앱·카드 뒷면 번호로 직접 확인", "상대가 알려준 번호가 아니라 공식 앱이나 카드 뒷면의 번호로 연락하세요.", 2),
                self._call("call-1332", "금융감독원 1332 상담", "기관 사칭과 인증정보 요구 여부를 상담하세요.", "1332", 3),
            ]
        if scam_type == "delivery_customs_smishing":
            return [
                self._guide("do-not-interact", "링크 접속·통관비 결제 중단", "문자 링크가 아닌 관세청·배송사 공식 경로에서 직접 조회하세요.", 1),
                self._call("call-customs", "관세청 125로 통관 사실 확인", "문자에 적힌 번호가 아니라 125로 직접 문의하세요.", "125", 2),
                self._call("call-118", "KISA 118 스미싱 상담", "의심 링크와 문자 내용을 상담하세요.", "118", 3),
            ]
        if scam_type == "malicious_app":
            return [
                self._guide("do-not-interact", "앱 설치·권한 허용 중단", "공식 앱스토어 밖의 파일이나 원격지원 앱을 설치하지 마세요.", 1),
                self._call("call-118", "KISA 118 악성앱 상담", "설치 전이라면 링크와 파일 정보를 확인받으세요.", "118", 2),
            ]
        if scam_type == "safe_message":
            return [
                self._guide(
                    "monitor-context",
                    "현재 대화의 추가 요구만 확인",
                    "현재 뚜렷한 사기 정황은 없지만 이후 금전·개인정보·앱 설치 요구가 생기는지 확인하세요.",
                    1,
                )
            ]
        return [
            self._guide("do-not-interact", "링크·송금·개인정보 입력 중단", "발신자와 기관을 공식 경로로 먼저 확인하세요.", 1),
            self._call("call-118", "118에서 의심 메시지 상담", "URL 또는 스미싱 여부를 확인하세요.", "118", 2),
        ]

    @staticmethod
    def _guide(action_id: str, title: str, description: str, priority: int) -> dict:
        return {"id": action_id, "title": title, "description": description, "priority": priority, "action_type": "guide", "target": None, "requires_approval": False}

    @staticmethod
    def _call(action_id: str, title: str, description: str, phone: str, priority: int) -> dict:
        return {"id": action_id, "title": title, "description": description, "priority": priority, "action_type": "call", "target": phone, "requires_approval": True}
